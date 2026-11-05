package parity.adminconsole.identity;

import java.io.IOException;
import java.io.InputStream;
import java.io.UncheckedIOException;
import java.time.Clock;
import java.time.Duration;
import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.ThreadLocalRandom;
import java.util.concurrent.atomic.AtomicInteger;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.core.annotation.Order;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;
import parity.adminconsole.config.AdminConsoleProperties;
import parity.adminconsole.db.Rls;
import parity.adminconsole.lifecycle.Drainable;
import parity.adminconsole.obs.ConsoleMetrics;
import parity.adminconsole.security.ReservedTenantIds;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.json.JsonMapper;
import tools.jackson.databind.node.ArrayNode;
import tools.jackson.databind.node.ObjectNode;

/**
 * Tenants → Keycloak organizations (SAML-PLAN step 4, "How a change reaches Keycloak"). Postgres holds
 * the desired state ({@link TenantIdentities}); this brings Keycloak to it, one tenant at a time under
 * its row lock ({@code FOR NO KEY UPDATE SKIP LOCKED}, so instances share the work and never apply one tenant
 * twice at once). Every call is idempotent: an apply that dies halfway is simply run again.
 * <ul>
 *   <li><b>active</b>: the organization (alias = tenant id, no domains) enabled; the desktop client
 *       {@code desktop-<tenant_id>} from the template, its redirect URIs on the tenant's hostname in
 *       every region; accounts a suspension disabled are enabled again, if they are still the tenant's
 *       ({@link #belongs}) and no admin disabled them meanwhile (that clears their record, review MF-2);</li>
 *   <li><b>suspended</b>: the organization disabled, and every enabled account of the tenant disabled
 *       and signed out. The spike showed a disabled organization still lets its local password members
 *       in (SAML-PLAN step 1, check 7), so the accounts are disabled too; each is recorded before it is
 *       disabled, so lifting the suspension enables those and no others;</li>
 *   <li><b>deleted</b>: the tenant's accounts (its {@code tenant_id}, in its organization or in none),
 *       the desktop client and the organization are deleted.</li>
 * </ul>
 * A failure records its code and is retried with backoff (full jitter, {@code backoff-min} to
 * {@code backoff-max}) by {@link #runDue}; never forever silently: {@code admin_identity_apply_total}.
 */
@Component
@Order(2)
public class IdentityApplier implements Drainable {

    private static final Logger log = LoggerFactory.getLogger(IdentityApplier.class);
    private static final JsonMapper JSON = JsonMapper.builder().build();
    private static final int PAGE = 100;

    /** How one apply ended. */
    public enum Result { APPLIED, UP_TO_DATE, BUSY, FAILED, DISABLED }

    private final ObjectProvider<KeycloakAdmin> keycloakProvider;
    private final TenantIdentities identities;
    private final Rls rls;
    private final Clock clock;
    private final ConsoleMetrics metrics;
    private final AdminConsoleProperties.Identity config;
    private final ReservedTenantIds reserved;
    private final JsonNode template;
    private final AtomicInteger running = new AtomicInteger();
    private volatile boolean stopping;

    public IdentityApplier(ObjectProvider<KeycloakAdmin> keycloak, TenantIdentities identities, Rls rls, Clock clock,
            ConsoleMetrics metrics, AdminConsoleProperties properties, ReservedTenantIds reserved) {
        this.keycloakProvider = keycloak;
        this.identities = identities;
        this.rls = rls;
        this.clock = clock;
        this.metrics = metrics;
        this.config = properties.identity();
        this.reserved = reserved;
        try (InputStream in = IdentityApplier.class.getClassLoader().getResourceAsStream("keycloak/desktop-client.json")) {
            if (in == null) {
                throw new IllegalStateException("keycloak/desktop-client.json is missing from the jar");
            }
            this.template = JSON.readTree(in);
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }

    private KeycloakAdmin keycloak() {
        return keycloakProvider.getIfAvailable();
    }

    /** Applies the tenant's desired state now, if no other instance is applying it. */
    public Result apply(String tenantId) {
        KeycloakAdmin kc = keycloak();
        if (kc == null) {
            return Result.DISABLED;
        }
        if (stopping) {
            return Result.BUSY;
        }
        if (reserved.contains(tenantId)) {
            throw new IllegalArgumentException("a reserved id (the staff organization among them) is never a tenant's");
        }
        running.incrementAndGet();
        try {
            Result r = rls.platform(db -> {
                Optional<TenantIdentities.Row> locked = TenantIdentities.lock(db, tenantId);
                if (locked.isEmpty()) {
                    return Result.BUSY;
                }
                TenantIdentities.Row row = locked.get();
                if (row.applied()) {
                    return Result.UP_TO_DATE;
                }
                try {
                    Applied a = switch (row.state()) {
                        case ACTIVE -> active(kc, row);
                        case SUSPENDED -> suspended(kc, row);
                        case DELETED -> deleted(kc, row);
                    };
                    TenantIdentities.applied(db, row, a.organizationId(), a.desktopClientId(), now());
                    log.atInfo().addKeyValue("tenant_id", tenantId).addKeyValue("state", row.state())
                            .addKeyValue("version", row.version()).addKeyValue("event", "identity.applied").log("identity applied");
                    return Result.APPLIED;
                } catch (KeycloakException e) {
                    Duration backoff = backoff(row.attempts());
                    TenantIdentities.failed(db, row, e.kind().code(), backoff, now());
                    log.atWarn().addKeyValue("tenant_id", tenantId).addKeyValue("state", row.state())
                            .addKeyValue("code", e.kind().code()).addKeyValue("status", e.status())
                            .addKeyValue("call", String.valueOf(e.call()))
                            .addKeyValue("retry_ms", backoff.toMillis()).addKeyValue("event", "identity.apply_failed").log("identity apply failed; will retry");
                    return Result.FAILED;
                }
            });
            metrics.identityApply(r.name().toLowerCase(java.util.Locale.ROOT));
            return r;
        } finally {
            running.decrementAndGet();
        }
    }

    /** The job: every tenant whose state isn't applied and whose next attempt is due. */
    @Scheduled(fixedDelayString = "${parity-admin-console.identity.apply-interval}",
            initialDelayString = "${parity-admin-console.identity.apply-interval}")
    public void runDue() {
        if (keycloak() == null || stopping) {
            return;
        }
        try {
            for (String tenant : identities.due(config.applyBatch())) {
                if (stopping) {
                    return;
                }
                apply(tenant);
            }
        } catch (RuntimeException e) {
            log.atWarn().addKeyValue("cause", e.getClass().getSimpleName()).addKeyValue("event", "identity.apply_failed").log("the identity apply job failed; next round");
        }
    }

    private record Applied(String organizationId, String desktopClientId) {}

    private Applied active(KeycloakAdmin kc, TenantIdentities.Row row) {
        String t = row.tenantId();
        JsonNode org = ensureOrganization(kc, t, row.name(), true);
        String orgId = org.path("id").asString();
        if (!org.path("enabled").asBoolean(true)) {
            ((ObjectNode) org).put("enabled", true);
            kc.updateOrganization(orgId, org);
        }
        for (String userId : identities.suspendedUsers(t)) {
            Optional<JsonNode> u = kc.user(userId);
            if (u.isPresent() && belongs(kc, t, u.get())) {
                ObjectNode rep = (ObjectNode) u.get();
                rep.put("enabled", true);
                kc.updateUser(userId, rep);
            }
            identities.unsuspended(t, userId);
        }
        String clientId = ensureDesktopClient(kc, t);
        return new Applied(orgId, clientId);
    }

    private Applied suspended(KeycloakAdmin kc, TenantIdentities.Row row) {
        String t = row.tenantId();
        JsonNode org = ensureOrganization(kc, t, row.name(), false);
        String orgId = org.path("id").asString();
        if (org.path("enabled").asBoolean(true)) {
            ((ObjectNode) org).put("enabled", false);
            kc.updateOrganization(orgId, org);
        }
        for (JsonNode u : accounts(kc, t, orgId)) {
            if (u.path("enabled").asBoolean(false)) {
                String id = u.path("id").asString();
                identities.suspended(t, id);
                ObjectNode rep = (ObjectNode) kc.user(id).orElse(u);
                rep.put("enabled", false);
                kc.updateUser(id, rep);
                kc.logout(id);
            }
        }
        String clientId = kc.clientByClientId(desktopClientId(t)).map(c -> c.path("id").asString()).orElse(null);
        return new Applied(orgId, clientId);
    }

    private Applied deleted(KeycloakAdmin kc, TenantIdentities.Row row) {
        String t = row.tenantId();
        Optional<JsonNode> org = kc.organizationByAlias(t);
        String orgId = org.map(o -> o.path("id").asString()).orElse(null);
        for (JsonNode u : accounts(kc, t, orgId)) {
            try {
                kc.deleteUser(u.path("id").asString());
            } catch (KeycloakException e) {
                if (e.kind() != KeycloakException.Kind.NOT_FOUND) {
                    throw e;
                }
            }
        }
        Optional<JsonNode> client = kc.clientByClientId(desktopClientId(t));
        if (client.isPresent()) {
            kc.deleteClient(client.get().path("id").asString());
        }
        if (orgId != null) {
            kc.deleteOrganization(orgId);
        }
        return new Applied(null, null);
    }

    /**
     * The tenant's accounts: its organization's members, and the users whose {@code tenant_id} is the
     * tenant and that belong to that organization or to none. A user with this {@code tenant_id} in another
     * organization is a mismatch: left to the nightly check (disabled there), never touched here.
     */
    List<JsonNode> accounts(KeycloakAdmin kc, String tenant, String orgId) {
        Set<String> seen = new LinkedHashSet<>();
        List<JsonNode> out = new ArrayList<>();
        if (orgId != null) {
            for (int first = 0; ; first += PAGE) {
                List<JsonNode> page = kc.members(orgId, first, PAGE);
                for (JsonNode m : page) {
                    if (seen.add(m.path("id").asString())) {
                        out.add(m);
                    }
                }
                if (page.size() < PAGE) {
                    break;
                }
            }
        }
        for (int first = 0; ; first += PAGE) {
            List<JsonNode> page = kc.usersByTenant(tenant, first, PAGE);
            for (JsonNode u : page) {
                String id = u.path("id").asString();
                if (seen.contains(id) || !tenant.equals(attribute(u, "tenant_id"))) {
                    continue;
                }
                List<JsonNode> orgs = kc.userOrganizations(id);
                boolean ours = orgs.isEmpty() || (orgs.size() == 1 && tenant.equals(orgs.get(0).path("alias").asString("")));
                if (ours && seen.add(id)) {
                    out.add(u);
                }
            }
            if (page.size() < PAGE) {
                break;
            }
        }
        return out;
    }

    private JsonNode ensureOrganization(KeycloakAdmin kc, String tenant, String name, boolean enabled) {
        Optional<JsonNode> org = kc.organizationByAlias(tenant);
        if (org.isPresent()) {
            return org.get();
        }
        try {
            kc.createOrganization(tenant, name, enabled);
        } catch (KeycloakException e) {
            if (e.kind() != KeycloakException.Kind.CONFLICT) {
                throw e;
            }
        }
        return kc.organizationByAlias(tenant).orElseThrow(() -> new KeycloakException(KeycloakException.Kind.UNAVAILABLE, 0));
    }

    private String ensureDesktopClient(KeycloakAdmin kc, String tenant) {
        Optional<JsonNode> existing = kc.clientByClientId(desktopClientId(tenant));
        if (existing.isPresent()) {
            return existing.get().path("id").asString();
        }
        String id;
        try {
            id = kc.createClient(desktopClient(tenant));
        } catch (KeycloakException e) {
            if (e.kind() != KeycloakException.Kind.CONFLICT) {
                throw e;
            }
            return kc.clientByClientId(desktopClientId(tenant)).map(c -> c.path("id").asString())
                    .orElseThrow(() -> new KeycloakException(KeycloakException.Kind.UNAVAILABLE, 0));
        }
        // fullScopeAllowed is off: the tokens carry the roles the realm's `desktop` client scope maps (the
        // tenant roles), set as code in the realm, never granted at run time.
        return id;
    }

    /** The desktop client of {@code tenant}, from the template: redirect URIs on its hostname in every region. */
    ObjectNode desktopClient(String tenant) {
        ObjectNode c = (ObjectNode) JSON.readTree(template.toString().replace("{tenant}", tenant));
        ArrayNode redirects = c.putArray("redirectUris");
        ArrayNode origins = c.putArray("webOrigins");
        List<String> logout = new ArrayList<>();
        for (String region : config.regions()) {
            String origin = config.tenantUrlTemplate().replace("{tenant}", tenant).replace("{region}", region);
            redirects.add(origin + "/*");
            origins.add(origin);
            logout.add(origin + "/*");
        }
        ((ObjectNode) c.path("attributes")).put("post.logout.redirect.uris", String.join("##", logout));
        return c;
    }

    static String desktopClientId(String tenant) {
        return "desktop-" + tenant;
    }

    /**
     * The account is the tenant's: its {@code tenant_id} is the tenant and the tenant's organization is
     * its one organization (rule 2). Listing, changing and re-enabling an account all ask this.
     */
    static boolean belongs(KeycloakAdmin kc, String tenant, JsonNode user) {
        if (!tenant.equals(attribute(user, "tenant_id"))) {
            return false;
        }
        List<JsonNode> orgs = kc.userOrganizations(user.path("id").asString());
        return orgs.size() == 1 && tenant.equals(orgs.get(0).path("alias").asString(""));
    }

    /** A single-valued user attribute, or null. */
    static String attribute(JsonNode user, String name) {
        JsonNode v = user.path("attributes").path(name);
        return v.isArray() && v.size() == 1 ? v.get(0).asString() : null;
    }

    private Duration backoff(int attempts) {
        long min = config.backoffMin().toMillis();
        long max = config.backoffMax().toMillis();
        long cap = Math.min(max, min << Math.min(attempts, 20));
        return Duration.ofMillis(min + ThreadLocalRandom.current().nextLong(Math.max(1, cap - min + 1)));
    }

    private OffsetDateTime now() {
        return OffsetDateTime.now(clock).withOffsetSameInstant(ZoneOffset.UTC);
    }

    /** The jobs stop taking tenants; an apply in progress finishes. */
    @Override
    public boolean drain(Duration timeout) throws InterruptedException {
        stopping = true;
        long deadline = System.nanoTime() + timeout.toNanos();
        while (running.get() > 0) {
            if (System.nanoTime() > deadline) {
                return false;
            }
            Thread.sleep(20);
        }
        return true;
    }
}
