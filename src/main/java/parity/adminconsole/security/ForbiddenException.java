package parity.adminconsole.security;

/** The caller sees the tenant but its role doesn't allow the action: 403. */
public class ForbiddenException extends RuntimeException {

    private static final long serialVersionUID = 1L;

    public ForbiddenException() {
        super("forbidden");
    }
}
