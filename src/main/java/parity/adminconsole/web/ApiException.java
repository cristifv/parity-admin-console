package parity.adminconsole.web;

/**
 * A request the API refuses with a status and a fixed code ({@code bad_request} names the field, a code
 * from a closed vocabulary, never the value).
 */
public class ApiException extends RuntimeException {

    private static final long serialVersionUID = 1L;

    /** The codes the API answers with besides the backends' own. */
    public enum Code {
        BAD_REQUEST(400), CONFIRMATION_REQUIRED(400), REASON_REQUIRED(400), RESERVED_TENANT_ID(400),
        ROLE_NOT_ALLOWED(400), CONFLICT(409), TENANT_SUSPENDED(409), TENANT_DELETED(409),
        /** A deleted tenant's id: retired for good, never created again (decision 2026-10-31, review MF-3). */
        TENANT_ID_RETIRED(409),
        /** A tenant role's request while its tenant (or the sub-tenant it acts on) is suspended: refused at once (decision 2026-10-31). */
        SUSPENDED_TENANT_ACCESS(403, "tenant_suspended"),
        /** A tenant role's request while its own tenant is deleted (its token outlives the accounts by up to 5 minutes). */
        DELETED_TENANT_ACCESS(403, "tenant_deleted"),
        IDENTITY_UNAVAILABLE(503);

        private final int status;
        private final String wire;

        Code(int status) {
            this(status, null);
        }

        Code(int status, String wire) {
            this.status = status;
            this.wire = wire;
        }

        public int status() {
            return status;
        }

        public String code() {
            return wire != null ? wire : name().toLowerCase(java.util.Locale.ROOT);
        }
    }

    private final Code code;
    private final Field field;

    /** The field a {@code bad_request} names. */
    public record Field(String name) {}

    public ApiException(Code code, Field field) {
        super(code.name());
        this.code = code;
        this.field = field;
    }

    public static ApiException badRequest(@com.google.errorprone.annotations.CompileTimeConstant String field) {
        return new ApiException(Code.BAD_REQUEST, new Field(field));
    }

    public static ApiException of(Code code) {
        return new ApiException(code, null);
    }

    public Code code() {
        return code;
    }

    /** The field, or null. */
    public String field() {
        return field == null ? null : field.name();
    }
}
