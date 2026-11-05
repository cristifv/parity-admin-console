package parity.adminconsole.tenants;

import java.util.List;
import java.util.regex.Pattern;
import parity.adminconsole.audit.AuditLog;

/**
 * Who asks for a staff operation on a tenant (suspend, lift a suspension), never a tenant-realm token
 * (user decisions D2-D3, 2026-11-03; coordinator ruling 2): the ops identity parity-cc-tools vouches for
 * (its {@code ops} realm's subject and username) and the operation's {@code op_id}, which links this
 * console's audit rows to parity-cc-tools' own. The consumer of {@code admin.ops.requests} (Kafka ACL:
 * parity-cc-tools the only writer; the next slice) builds one from each command; nothing else does.
 * The audit actor is {@code ops:<subject>} with the role {@code ops}, and the request id
 * {@code ops:<op_id>}.
 */
public record OpsActor(String subject, String username, String opId) {

    private static final Pattern SUBJECT = Pattern.compile("^[A-Za-z0-9-]{1,128}$");
    private static final Pattern USERNAME = Pattern.compile("^[A-Za-z0-9._@-]{1,64}$");
    private static final Pattern UUID7 = Pattern.compile("^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$");

    public OpsActor {
        if (subject == null || !SUBJECT.matcher(subject).matches()) {
            throw new IllegalArgumentException("an ops actor needs its subject");
        }
        if (username == null || !USERNAME.matcher(username).matches()) {
            throw new IllegalArgumentException("an ops actor needs its username");
        }
        if (opId == null || !UUID7.matcher(opId).matches()) {
            throw new IllegalArgumentException("an ops operation needs its op_id (a UUIDv7)");
        }
    }

    /** The audit log's actor: {@code ops:<subject>}, role {@code ops}. */
    public AuditLog.Actor actor() {
        return new AuditLog.Actor("ops:" + subject, List.of("ops"));
    }

    /** The audit rows' request id: the same for both rows, and for a retry of the same operation. */
    public String requestId() {
        return "ops:" + opId;
    }
}
