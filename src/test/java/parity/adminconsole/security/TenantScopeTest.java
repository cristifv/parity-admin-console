package parity.adminconsole.security;

import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import org.junit.jupiter.api.Test;

/**
 * The tenant scope (rules 2 and 6): own tenant, a parent's sub-tenants, everyone else's is 404. There is
 * no every-tenant scope (user decision D2, 2026-11-03).
 */
class TenantScopeTest {

    private static final Map<String, String> PARENTS = Map.of("initech-de", "initech", "initech-uk", "initech",
            "globex-at", "globex");
    private final TenantScope scope = new TenantScope(t -> Optional.ofNullable(PARENTS.get(t)));

    private static Caller caller(String tenant, Role... roles) {
        return new Caller("sub", "user", Set.of(roles), tenant);
    }

    /** No caller crosses to an unrelated tenant, whatever its roles: the scope is the token's own tenant. */
    @Test
    void noRoleReachesAnUnrelatedTenantOrItsSubTenants() {
        for (Caller c : List.of(caller("acme", Role.TENANT_ADMIN), caller("acme", Role.SUPERVISOR),
                caller("acme", Role.TENANT_ADMIN, Role.SUPERVISOR, Role.AGENT), caller("acme"))) {
            for (String other : List.of("globex", "globex-at", "initech", "initech-de")) {
                assertThatThrownBy(() -> scope.requireVisible(c, other)).as(c + " " + other).isInstanceOf(TenantNotFoundException.class);
                assertThatThrownBy(() -> scope.requireAdmin(c, other)).as(c + " " + other).isInstanceOf(TenantNotFoundException.class);
            }
        }
        // Another parent's sub-tenant is out of scope for a parent's admin too.
        assertThatThrownBy(() -> scope.requireAdmin(caller("initech", Role.TENANT_ADMIN), "globex-at"))
                .isInstanceOf(TenantNotFoundException.class);
        // A caller without a tenant (never past TokenChecks) sees nothing.
        assertThatThrownBy(() -> scope.requireVisible(caller(null, Role.TENANT_ADMIN), "acme")).isInstanceOf(TenantNotFoundException.class);
    }

    @Test
    void aParentsAdminReachesItsSubTenantsAndNoOneElses() {
        Caller parent = caller("initech", Role.TENANT_ADMIN);
        assertThatCode(() -> scope.requireAdmin(parent, "initech")).doesNotThrowAnyException();
        assertThatCode(() -> scope.requireAdmin(parent, "initech-de")).doesNotThrowAnyException();
        assertThatThrownBy(() -> scope.requireVisible(parent, "acme")).isInstanceOf(TenantNotFoundException.class);
    }

    @Test
    void aSubTenantsAdminSeesNeitherItsParentNorItsSiblings() {
        Caller child = caller("initech-de", Role.TENANT_ADMIN);
        assertThatThrownBy(() -> scope.requireVisible(child, "initech")).isInstanceOf(TenantNotFoundException.class);
        assertThatThrownBy(() -> scope.requireVisible(child, "initech-uk")).isInstanceOf(TenantNotFoundException.class);
    }

    @Test
    void aSupervisorSeesTheirOwnTenantOnlyAndAdministersNothing() {
        Caller sup = caller("initech", Role.SUPERVISOR);
        assertThatCode(() -> scope.requireVisible(sup, "initech")).doesNotThrowAnyException();
        assertThatThrownBy(() -> scope.requireVisible(sup, "initech-de")).isInstanceOf(TenantNotFoundException.class);
        assertThatThrownBy(() -> scope.requireAdmin(sup, "initech")).isInstanceOf(ForbiddenException.class);
    }

    @Test
    void aSuspendedSubTenantIsRefusedToItsParentAndADeletedOneIsGone() {
        Map<String, parity.adminconsole.identity.TenantIdentities.State> states = Map.of(
                "initech-de", parity.adminconsole.identity.TenantIdentities.State.SUSPENDED,
                "initech-uk", parity.adminconsole.identity.TenantIdentities.State.DELETED);
        TenantScope gated = new TenantScope(t -> Optional.ofNullable(PARENTS.get(t)), t -> Optional.ofNullable(states.get(t)));
        Caller parent = caller("initech", Role.TENANT_ADMIN);
        assertThatThrownBy(() -> gated.requireVisible(parent, "initech-de")).isInstanceOf(parity.adminconsole.web.ApiException.class)
                .extracting(e -> ((parity.adminconsole.web.ApiException) e).code().code()).isEqualTo("tenant_suspended");
        assertThatThrownBy(() -> gated.requireVisible(parent, "initech-uk")).isInstanceOf(TenantNotFoundException.class);
        // Out of scope stays a plain 404, whatever its state: the state of another's tenant never shows.
        assertThatThrownBy(() -> gated.requireVisible(caller("acme", Role.TENANT_ADMIN), "initech-de"))
                .isInstanceOf(TenantNotFoundException.class);
    }

    @Test
    void outOfScopeAndMalformedAreTheSame404() {
        Caller acme = caller("acme", Role.TENANT_ADMIN);
        assertThatThrownBy(() -> scope.requireVisible(acme, "globex")).isInstanceOf(TenantNotFoundException.class);
        assertThatThrownBy(() -> scope.requireVisible(acme, "../etc")).isInstanceOf(TenantNotFoundException.class);
        assertThatThrownBy(() -> scope.requireVisible(acme, null)).isInstanceOf(TenantNotFoundException.class);
    }
}
