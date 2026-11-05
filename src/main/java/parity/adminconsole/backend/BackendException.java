package parity.adminconsole.backend;

/**
 * A request that didn't succeed: the backend's error answer, no answer in time ({@link Kind#NOT_CONFIRMED}:
 * the change may still land), or the request couldn't be sent. The exception message is the kind's
 * constant; the backend's own words are in {@link #error()}.
 */
public class BackendException extends RuntimeException {

    private static final long serialVersionUID = 1L;

    /** How the console answers each (PLAN.md "Kafka request/reply"). */
    public enum Kind {
        BAD_REQUEST(400, "bad_request"),
        FORBIDDEN(502, "forbidden"),
        NOT_FOUND(404, "not_found"),
        CONFLICT(409, "conflict"),
        UNAVAILABLE(503, "unavailable"),
        INTERNAL(502, "internal"),
        NOT_CONFIRMED(504, "not_confirmed"),
        NOT_SENT(503, "not_sent");

        private final int status;
        private final String code;

        Kind(int status, String code) {
            this.status = status;
            this.code = code;
        }

        public int status() {
            return status;
        }

        public String code() {
            return code;
        }

        static Kind of(String code) {
            for (Kind k : values()) {
                if (k.code.equals(code)) {
                    return k;
                }
            }
            return INTERNAL;
        }
    }

    private final Kind kind;
    private final transient BackendError error;

    public BackendException(Kind kind, BackendError error) {
        super(kind.code());
        this.kind = kind;
        this.error = error;
    }

    public BackendException(Kind kind, Throwable cause) {
        super(kind.code(), cause);
        this.kind = kind;
        this.error = null;
    }

    public Kind kind() {
        return kind;
    }

    /** The backend's answer, or null when there was none. */
    public BackendError error() {
        return error;
    }

    /** The rule a {@code conflict} or {@code bad_request} names, or null. */
    public String rule() {
        return error == null ? null : error.rule();
    }
}
