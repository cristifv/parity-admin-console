package parity.adminconsole.identity;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.locks.ReentrantLock;
import java.util.regex.Pattern;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;
import parity.adminconsole.audit.AuditLog;
import parity.adminconsole.config.AdminConsoleProperties;
import parity.adminconsole.obs.ConsoleMetrics;
import parity.adminconsole.security.ReservedTenantIds;
import parity.adminconsole.store.StoreClient;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.json.JsonMapper;
import tools.jackson.databind.node.ObjectNode;

/**
 * The nightly check (SAML-PLAN step 4, multi-tenant rules 2 and 5), tenant by tenant so one failure
 * never stops the run (finding 18):
 * <ol>
 *   <li>every parity-store tenant has an identity row (a create that died between parity-store and
 *       Postgres is finished here);</li>
 *   <li>each tenant's organization and desktop client exist and the organization's enabled flag matches
 *       the state; a difference is applied again (a repair, counted: it alerts);</li>
 *   <li><b>each account belongs to exactly one organization, whose alias is its {@code tenant_id}</b>,
 *       that is a tenant's: a reserved id (the realm's staff organization {@code platform} among them)
 *       is nobody's, and no account holds {@code platform-admin} (user decision D2, 2026-11-03: the
 *       tenant realm has no staff; staff sign in to parity-cc-tools' own realm). An enabled account that
 *       breaks any of these is disabled and signed out, with two audit rows (the actor is
 *       {@code system:identity-check}).</li>
 * </ol>
 * It never deletes anything: an identity whose parity-store tenant is missing is only counted.
 */
@Component
public class IdentityCheck {

    private static final Logger log = LoggerFactory.getLogger(IdentityCheck.class);
    private static final JsonMapper JSON = JsonMapper.builder().build();
    private static final Pattern TENANT = Pattern.compile("^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$");
    private static final int PAGE = 100;

    /** What a run found and did. */
    public record Summary(int tenants, int identitiesCreated, int repaired, int accountsChecked, int accountsDisabled,
            int failures) {}

    private final ObjectProvider<KeycloakAdmin> keycloakProvider;
    private final TenantIdentities identities;
    private final IdentityApplier applier;
    private final StoreClient store;
    private final AuditLog audit;
    private final ConsoleMetrics metrics;
    private final AdminConsoleProperties properties;
    private final ReservedTenantIds reserved;
    private final ReentrantLock oneAtATime = new ReentrantLock();

    public IdentityCheck(ObjectProvider<KeycloakAdmin> keycloak, TenantIdentities identities, IdentityApplier applier,
            StoreClient store, AuditLog audit, ConsoleMetrics metrics, AdminConsoleProperties properties,
            ReservedTenantIds reserved) {
        this.keycloakProvider = keycloak;
        this.identities = identities;
        this.applier = applier;
        this.store = store;
        this.audit = audit;
        this.metrics = metrics;
        this.properties = properties;
        this.reserved = reserved;
    }

    @Scheduled(cron = "${parity-admin-console.identity.check-cron}", zone = "UTC")
    public void nightly() {
        if (properties.identity().checkEnabled()) {
            run();
        }
    }

    /** One run (the nightly job; no HTTP route). Concurrent runs on one instance wait. */
    public Summary run() {
        KeycloakAdmin kc = keycloakProvider.getIfAvailable();
        if (kc == null) {
            return new Summary(0, 0, 0, 0, 0, 0);
        }
        oneAtATime.lock();
        try {
            int[] c = new int[6];
            storeTenants(c);
            tenants(kc, c);
            accounts(kc, c);
            Summary s = new Summary(c[0], c[1], c[2], c[3], c[4], c[5]);
            log.atInfo().addKeyValue("tenants", s.tenants()).addKeyValue("identities_created", s.identitiesCreated())
                    .addKeyValue("repaired", s.repaired()).addKeyValue("accounts", s.accountsChecked())
                    .addKeyValue("accounts_disabled", s.accountsDisabled()).addKeyValue("failures", s.failures())
                    .addKeyValue("event", "identity.check_done").log("identity check done");
            return s;
        } finally {
            oneAtATime.unlock();
        }
    }

    private void storeTenants(int[] c) {
        String after = null;
        try {
            do {
                JsonNode page = store.listTenants(after, 500, null);
                for (JsonNode t : page.path("tenants")) {
                    String id = t.path("tenant_id").asString();
                    c[0]++;
                    if (!identities.exists(id)) {
                        identities.create(id, t.path("name").asString(id));
                        applier.apply(id);
                        c[1]++;
                        metrics.identityRepair("missing_identity");
                    }
                }
                after = StoreClient.text(page, "next_after");
            } while (after != null);
        } catch (RuntimeException e) {
            c[5]++;
            log.atWarn().addKeyValue("cause", e.getClass().getSimpleName()).addKeyValue("event", "identity.check_failed").log("identity check: can't list parity-store's tenants");
        }
    }

    private void tenants(KeycloakAdmin kc, int[] c) {
        for (TenantIdentities.Row row : identities.live()) {
            try {
                Optional<JsonNode> org = kc.organizationByAlias(row.tenantId());
                boolean wantEnabled = row.state() == TenantIdentities.State.ACTIVE;
                boolean drift = org.isEmpty() || org.get().path("enabled").asBoolean(true) != wantEnabled
                        || kc.clientByClientId(IdentityApplier.desktopClientId(row.tenantId())).isEmpty();
                if (drift) {
                    identities.reapply(row.tenantId());
                    applier.apply(row.tenantId());
                    c[2]++;
                    metrics.identityRepair("tenant_drift");
                    log.atWarn().addKeyValue("tenant_id", row.tenantId()).addKeyValue("event", "identity.repaired").log("identity check: repaired a tenant's organization or client");
                }
            } catch (RuntimeException e) {
                c[5]++;
                log.atWarn().addKeyValue("tenant_id", row.tenantId()).addKeyValue("cause", e.getClass().getSimpleName())
                        .addKeyValue("event", "identity.check_failed").log("identity check: a tenant failed; next one");
            }
        }
    }

    private void accounts(KeycloakAdmin kc, int[] c) {
        Map<String, Set<String>> orgsOf = new HashMap<>();
        Set<String> platformAdmins = new HashSet<>();
        try {
            for (int first = 0; ; first += PAGE) {
                List<JsonNode> orgs = kc.organizations(first, PAGE);
                for (JsonNode o : orgs) {
                    String alias = o.path("alias").asString();
                    for (int m = 0; ; m += PAGE) {
                        List<JsonNode> members = kc.members(o.path("id").asString(), m, PAGE);
                        for (JsonNode u : members) {
                            orgsOf.computeIfAbsent(u.path("id").asString(), k -> new HashSet<>()).add(alias);
                        }
                        if (members.size() < PAGE) {
                            break;
                        }
                    }
                }
                if (orgs.size() < PAGE) {
                    break;
                }
            }
            staffRole(kc, platformAdmins);
        } catch (RuntimeException e) {
            c[5]++;
            log.atWarn().addKeyValue("cause", e.getClass().getSimpleName()).addKeyValue("event", "identity.check_failed").log("identity check: can't read the organizations; accounts not checked");
            return;
        }
        for (int first = 0; ; first += PAGE) {
            List<JsonNode> page;
            try {
                page = kc.users(first, PAGE);
            } catch (RuntimeException e) {
                c[5]++;
                log.atWarn().addKeyValue("cause", e.getClass().getSimpleName()).addKeyValue("event", "identity.check_failed").log("identity check: can't list accounts; stopped");
                return;
            }
            for (JsonNode u : page) {
                if (u.hasNonNull("serviceAccountClientId") || u.path("username").asString("").startsWith("service-account-")) {
                    continue;
                }
                c[3]++;
                String id = u.path("id").asString();
                String tenant = IdentityApplier.attribute(u, "tenant_id");
                Set<String> orgs = orgsOf.getOrDefault(id, Set.of());
                String reason = null;
                if (tenant == null || !TENANT.matcher(tenant).matches()) {
                    reason = "no_tenant_id";
                } else if (reserved.contains(tenant)) {
                    reason = "reserved_tenant_id";
                } else if (!orgs.equals(Set.of(tenant))) {
                    reason = "tenant_id_mismatch";
                } else if (platformAdmins.contains(id)) {
                    reason = "platform_admin_role";
                }
                if (reason != null && u.path("enabled").asBoolean(false)) {
                    try {
                        disable(kc, u, tenant, orgs, reason);
                        c[4]++;
                    } catch (RuntimeException e) {
                        c[5]++;
                        log.atWarn().addKeyValue("user_id", id).addKeyValue("cause", e.getClass().getSimpleName())
                                .addKeyValue("event", "identity.check_failed").log("identity check: can't disable a mismatched account; next one");
                    }
                }
            }
            if (page.size() < PAGE) {
                return;
            }
        }
    }

    /** The holders of {@code platform-admin}, if the realm still has the role (a realm without it has none). */
    private static void staffRole(KeycloakAdmin kc, Set<String> into) {
        for (int first = 0; ; first += PAGE) {
            List<JsonNode> page;
            try {
                page = kc.roleUsers("platform-admin", first, PAGE);
            } catch (KeycloakException e) {
                if (e.kind() == KeycloakException.Kind.NOT_FOUND) {
                    return;
                }
                throw e;
            }
            page.forEach(u -> into.add(u.path("id").asString()));
            if (page.size() < PAGE) {
                return;
            }
        }
    }

    private void disable(KeycloakAdmin kc, JsonNode user, String tenant, Set<String> orgs, String reason) {
        String id = user.path("id").asString();
        // The row goes to a tenant's audit view only when the account is wholly that tenant's: its one
        // organization is its tenant_id (and not a reserved id). A mismatch's row has no tenant, so no
        // tenant sees it: the attribute may be planted, and the row names the account's organizations,
        // so either side would learn of the other tenant.
        String auditTenant = tenant != null && TENANT.matcher(tenant).matches() && !reserved.contains(tenant)
                && orgs.equals(Set.of(tenant)) ? tenant : null;
        Map<String, Object> request = new LinkedHashMap<>();
        request.put("user_id", id);
        request.put("tenant_id", tenant);
        request.put("organizations", new ArrayList<>(orgs));
        AuditLog.Ticket t = audit.requested(AuditLog.Actor.system("identity-check"), auditTenant, "identity.account_disabled",
                id, reason, JSON.valueToTree(request), "identity-check:" + java.util.UUID.randomUUID());
        try {
            ObjectNode rep = (ObjectNode) kc.user(id).orElse(user);
            rep.put("enabled", false);
            kc.updateUser(id, rep);
            kc.logout(id);
        } catch (KeycloakException e) {
            audit.answered(t, AuditLog.Outcome.ERROR, e.kind().code());
            throw e;
        } catch (RuntimeException e) {
            audit.answered(t, AuditLog.Outcome.ERROR, "internal");
            throw e;
        }
        audit.answered(t, AuditLog.Outcome.OK, null);
        metrics.identityRepair("account_disabled");
        log.atWarn().addKeyValue("user_id", id).addKeyValue("tenant_id", tenant).addKeyValue("reason", reason)
                .addKeyValue("event", "identity.account_disabled").log("identity check: disabled an account that breaks the tenant rules (the reason says which)");
    }
}
