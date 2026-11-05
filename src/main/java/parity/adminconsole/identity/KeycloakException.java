package parity.adminconsole.identity;

/**
 * A Keycloak Admin REST API call that failed. The message is the kind's code: never a response body
 * (it may hold names or emails).
 */
public class KeycloakException extends RuntimeException {

    private static final long serialVersionUID = 1L;

    /** Retryable ({@link #UNAVAILABLE}) or not. */
    public enum Kind {
        UNAVAILABLE("keycloak_unavailable"), NOT_FOUND("keycloak_not_found"), CONFLICT("keycloak_conflict"),
        REFUSED("keycloak_refused");

        private final String code;

        Kind(String code) {
            this.code = code;
        }

        public String code() {
            return code;
        }
    }

    /** Which call failed: the method and the resource kind (no id, no query). */
    public record Call(String method, String resource) {
        @Override
        public String toString() {
            return method + " " + resource;
        }
    }

    private final Kind kind;
    private final int status;
    private final transient Call call;

    public KeycloakException(Kind kind, int status) {
        this(kind, status, null);
    }

    public KeycloakException(Kind kind, int status, Call call) {
        super(kind.code());
        this.kind = kind;
        this.status = status;
        this.call = call;
    }

    public KeycloakException(Kind kind, Throwable cause) {
        super(kind.code(), cause);
        this.kind = kind;
        this.status = 0;
        this.call = null;
    }

    /** The failed call, or null (a token or connection failure). */
    public Call call() {
        return call;
    }

    public Kind kind() {
        return kind;
    }

    public int status() {
        return status;
    }
}
