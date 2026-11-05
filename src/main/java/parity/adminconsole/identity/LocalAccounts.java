package parity.adminconsole.identity;

import java.util.ArrayList;
import java.util.EnumSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.regex.Pattern;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.stereotype.Component;
import parity.adminconsole.audit.AuditLog;
import parity.adminconsole.security.Caller;
import parity.adminconsole.security.Role;
import parity.adminconsole.security.TenantNotFoundException;
import parity.adminconsole.web.ApiException;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.json.JsonMapper;
import tools.jackson.databind.node.ObjectNode;

/**
 * A tenant's local accounts (SAML-PLAN step 4): created by admin-api only, in the tenant's organization,
 * with {@code tenant_id} set by admin-api and a username {@code <tenant_id>.<name>} (login with email is
 * off: finding 5). Roles are {@code tenant-admin}, {@code supervisor} and {@code agent} only: any
 * other, {@code platform-admin} among them, is refused (rule 5; D2: no staff role here). The password and MFA are the person's own, set at their
 * first login (required actions); the console never sees one. Every change has two audit rows.
 * An account is found, listed and changed only within its tenant: its {@code tenant_id} is the tenant
 * and the tenant's organization is its one organization ({@link IdentityApplier#belongs}); any other
 * is 404 (rule 6) and never listed (review F9).
 */
@Component
public class LocalAccounts {

    private static final JsonMapper JSON = JsonMapper.builder().build();
    private static final Pattern NAME = Pattern.compile("^[a-z0-9](?:[a-z0-9._-]{0,60}[a-z0-9])?$");
    private static final Pattern USER_ID = Pattern.compile("^[A-Za-z0-9-]{1,64}$");
    private static final Pattern PERSON = Pattern.compile("^[^\\u0000-\\u001f\\u007f<>]{1,100}$");
    private static final Pattern EMAIL = Pattern.compile("^[^@\\s]{1,64}@[A-Za-z0-9.-]{1,190}$");
    private static final Set<Role> ALLOWED = EnumSet.of(Role.TENANT_ADMIN, Role.SUPERVISOR, Role.AGENT);

    /** A new account's details (from the request body; the tenant comes from the path, checked). */
    public record NewAccount(String name, String firstName, String lastName, String email, List<String> roles) {}

    private final ObjectProvider<KeycloakAdmin> keycloakProvider;
    private final TenantIdentities identities;
    private final AuditLog audit;

    public LocalAccounts(ObjectProvider<KeycloakAdmin> keycloak, TenantIdentities identities, AuditLog audit) {
        this.keycloakProvider = keycloak;
        this.identities = identities;
        this.audit = audit;
    }

    private KeycloakAdmin kc() {
        KeycloakAdmin kc = keycloakProvider.getIfAvailable();
        if (kc == null) {
            throw ApiException.of(ApiException.Code.IDENTITY_UNAVAILABLE);
        }
        return kc;
    }

    public List<Map<String, Object>> list(String tenant, int first, int max) {
        KeycloakAdmin kc = kc();
        List<Map<String, Object>> out = new ArrayList<>();
        for (JsonNode u : kc.usersByTenant(tenant, first, max)) {
            if (IdentityApplier.belongs(kc, tenant, u)) {
                out.add(view(u, roles(kc, u.path("id").asString())));
            }
        }
        return out;
    }

    /**
     * A new account of the tenant: by its tenant admin ({@link AuditLog.Actor#of}), or its first admin by
     * billing's provisioning (a service actor; that consumer is the next slice).
     */
    public Map<String, Object> create(AuditLog.Actor actor, String tenant, NewAccount a) {
        if (a.name() == null || !NAME.matcher(a.name()).matches()) {
            throw ApiException.badRequest("name");
        }
        if (a.firstName() != null && !PERSON.matcher(a.firstName()).matches()) {
            throw ApiException.badRequest("first_name");
        }
        if (a.lastName() != null && !PERSON.matcher(a.lastName()).matches()) {
            throw ApiException.badRequest("last_name");
        }
        if (a.email() != null && !EMAIL.matcher(a.email()).matches()) {
            throw ApiException.badRequest("email");
        }
        List<Role> roles = new ArrayList<>();
        if (a.roles() == null || a.roles().isEmpty()) {
            throw ApiException.of(ApiException.Code.ROLE_NOT_ALLOWED);
        }
        for (String r : a.roles()) {
            Optional<Role> role = Role.fromClaim(r);
            if (role.isEmpty() || !ALLOWED.contains(role.get())) {
                throw ApiException.of(ApiException.Code.ROLE_NOT_ALLOWED);
            }
            roles.add(role.get());
        }
        TenantIdentities.Row row = activeIdentity(tenant);
        KeycloakAdmin kc = kc();
        String username = tenant + "." + a.name();
        Map<String, Object> asked = new LinkedHashMap<>();
        asked.put("username", username);
        asked.put("roles", roles.stream().map(Role::claim).sorted().toList());
        AuditLog.Ticket t = audit.requested(actor, tenant, "user.create", username, null,
                JSON.valueToTree(asked), "console:" + java.util.UUID.randomUUID());
        String id = null;
        try {
            ObjectNode rep = JSON.createObjectNode().put("username", username).put("enabled", true).put("emailVerified", false);
            if (a.firstName() != null) {
                rep.put("firstName", a.firstName());
            }
            if (a.lastName() != null) {
                rep.put("lastName", a.lastName());
            }
            if (a.email() != null) {
                rep.put("email", a.email());
            }
            rep.putObject("attributes").putArray("tenant_id").add(tenant);
            rep.putArray("requiredActions").add("UPDATE_PASSWORD");
            id = kc.createUser(rep);
            kc.addRealmRoles(id, kc.realmRoles(roles.stream().map(Role::claim).toList()));
            String orgId = row.organizationId() != null ? row.organizationId()
                    : kc.organizationByAlias(tenant).map(o -> o.path("id").asString())
                            .orElseThrow(() -> new KeycloakException(KeycloakException.Kind.UNAVAILABLE, 0));
            kc.addMember(orgId, id);
        } catch (KeycloakException e) {
            if (id != null) {
                // Never leave an account outside its organization, or without its roles.
                try {
                    kc.deleteUser(id);
                } catch (KeycloakException ignored) {
                    // The nightly check disables an account left without an organization.
                }
            }
            audit.answered(t, AuditLog.Outcome.ERROR, e.kind().code());
            if (e.kind() == KeycloakException.Kind.CONFLICT) {
                throw ApiException.of(ApiException.Code.CONFLICT);
            }
            throw ApiException.of(ApiException.Code.IDENTITY_UNAVAILABLE);
        } catch (RuntimeException e) {
            if (id != null) {
                try {
                    kc.deleteUser(id);
                } catch (RuntimeException ignored) {
                    // The nightly check disables an account left without an organization.
                }
            }
            audit.answered(t, AuditLog.Outcome.ERROR, "internal");
            throw e;
        }
        audit.answered(t, AuditLog.Outcome.OK, null);
        return view(kc.user(id).orElseThrow(), roles.stream().map(Role::claim).sorted().toList());
    }

    /**
     * Enables or disables an account of the tenant; disabling also ends its sessions, and clears the
     * account's suspension record first, so lifting a suspension never enables an account an admin
     * disabled during it (review MF-2).
     */
    public Map<String, Object> setEnabled(Caller caller, String tenant, String userId, boolean enabled) {
        if (userId == null || !USER_ID.matcher(userId).matches()) {
            throw new TenantNotFoundException();
        }
        if (enabled) {
            activeIdentity(tenant);
        }
        KeycloakAdmin kc = kc();
        JsonNode user = ours(kc, tenant, userId);
        AuditLog.Ticket t = audit.requested(AuditLog.Actor.of(caller), tenant, enabled ? "user.enable" : "user.disable",
                user.path("username").asString(), null, JSON.createObjectNode().put("user_id", userId),
                "console:" + java.util.UUID.randomUUID());
        try {
            if (!enabled) {
                identities.unsuspended(tenant, userId);
            }
            ObjectNode rep = (ObjectNode) user;
            rep.put("enabled", enabled);
            kc.updateUser(userId, rep);
            if (!enabled) {
                kc.logout(userId);
            }
        } catch (KeycloakException e) {
            audit.answered(t, AuditLog.Outcome.ERROR, e.kind().code());
            throw ApiException.of(ApiException.Code.IDENTITY_UNAVAILABLE);
        } catch (RuntimeException e) {
            audit.answered(t, AuditLog.Outcome.ERROR, "internal");
            throw e;
        }
        audit.answered(t, AuditLog.Outcome.OK, null);
        return view(kc.user(userId).orElseThrow(), roles(kc, userId));
    }

    /** The account, if its tenant_id is the tenant and it belongs to the tenant's organization only; else 404. */
    private JsonNode ours(KeycloakAdmin kc, String tenant, String userId) {
        JsonNode u = kc.user(userId).orElseThrow(TenantNotFoundException::new);
        if (!IdentityApplier.belongs(kc, tenant, u)) {
            throw new TenantNotFoundException();
        }
        return u;
    }

    private TenantIdentities.Row activeIdentity(String tenant) {
        TenantIdentities.Row row = identities.get(tenant).orElseThrow(TenantNotFoundException::new);
        return switch (row.state()) {
            case ACTIVE -> row;
            case SUSPENDED -> throw ApiException.of(ApiException.Code.TENANT_SUSPENDED);
            case DELETED -> throw new TenantNotFoundException();
        };
    }

    private static List<String> roles(KeycloakAdmin kc, String userId) {
        List<String> out = new ArrayList<>();
        for (JsonNode r : kc.realmRoleMappings(userId)) {
            String name = r.path("name").asString("");
            if (Role.fromClaim(name).isPresent()) {
                out.add(name);
            }
        }
        out.sort(null);
        return out;
    }

    private static Map<String, Object> view(JsonNode u, List<String> roles) {
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("id", u.path("id").asString());
        m.put("username", u.path("username").asString());
        m.put("enabled", u.path("enabled").asBoolean(false));
        m.put("first_name", u.hasNonNull("firstName") ? u.get("firstName").asString() : null);
        m.put("last_name", u.hasNonNull("lastName") ? u.get("lastName").asString() : null);
        m.put("email", u.hasNonNull("email") ? u.get("email").asString() : null);
        m.put("sso_managed", "true".equals(IdentityApplier.attribute(u, "sso_managed")));
        m.put("roles", roles);
        return m;
    }
}
