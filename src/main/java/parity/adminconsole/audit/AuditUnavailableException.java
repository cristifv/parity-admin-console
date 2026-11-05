package parity.adminconsole.audit;

/**
 * The {@code requested} row couldn't be written, so the command isn't sent (PLAN.md finding 7, the
 * safe default until postponed question 4 decides otherwise): 503 {@code audit_unavailable}.
 */
public class AuditUnavailableException extends RuntimeException {

    private static final long serialVersionUID = 1L;

    public AuditUnavailableException(Throwable cause) {
        super("audit_unavailable", cause);
    }
}
