package parity.adminconsole.security;

import java.util.List;
import java.util.Set;

/**
 * Who is calling, from the token only (PLAN.md "Identity never comes from a form"): the subject, the
 * username, the tenant roles, and the tenant ({@code tenant_id}, checked equal to the caller's one
 * organization by {@link TokenChecks}). Every caller is a tenant's person: there is no staff caller and
 * no every-tenant scope here (user decision D2, 2026-11-03).
 */
public record Caller(String subject, String username, Set<Role> roles, String tenantId) {

    public Caller {
        roles = Set.copyOf(roles);
    }

    public boolean has(Role role) {
        return roles.contains(role);
    }

    /** The roles as the audit log stores them, sorted. */
    public List<String> roleNames() {
        return roles.stream().map(Role::claim).sorted().toList();
    }
}
