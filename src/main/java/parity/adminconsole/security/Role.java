package parity.adminconsole.security;

import java.util.Optional;

/**
 * The tenant roles (ARCH §3.9) this console knows: it is the public, tenant-only tool (user decisions
 * D1-D2, 2026-11-03), so there is no staff role here. {@code platform-admin} is not one: a token that
 * carries it is refused ({@link TokenChecks}), and staff work in parity-cc-tools' own realm.
 * {@code parity-user} is a composite marker, not a role here.
 */
public enum Role {
    TENANT_ADMIN("tenant-admin"),
    SUPERVISOR("supervisor"),
    AGENT("agent");

    private final String claim;

    Role(String claim) {
        this.claim = claim;
    }

    /** The name in the token's {@code realm_access.roles}. */
    public String claim() {
        return claim;
    }

    public static Optional<Role> fromClaim(String name) {
        for (Role r : values()) {
            if (r.claim.equals(name)) {
                return Optional.of(r);
            }
        }
        return Optional.empty();
    }
}
