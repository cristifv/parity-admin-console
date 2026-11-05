package parity.adminconsole.security;

/**
 * A tenant the caller may not see, answered exactly like one that doesn't exist (404 {@code not_found}),
 * so the answer never confirms that another tenant exists (multi-tenant rule 2).
 */
public class TenantNotFoundException extends RuntimeException {

    private static final long serialVersionUID = 1L;

    public TenantNotFoundException() {
        super("not_found");
    }
}
