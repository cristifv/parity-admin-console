package parity.adminconsole.audit;

import java.time.Clock;
import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import java.util.List;
import java.util.UUID;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.dao.DataAccessException;
import org.springframework.stereotype.Component;
import parity.adminconsole.db.Rls;
import parity.adminconsole.obs.ConsoleMetrics;
import parity.adminconsole.security.Caller;
import tools.jackson.databind.JsonNode;

/**
 * The audit log's writes (PLAN.md "Audit log", finding 7): two rows per command.
 * <ul>
 *   <li>{@link #requested} before the command is sent, in its own committed transaction. If it can't
 *       be written, {@link AuditUnavailableException}: the caller must not send the command;</li>
 *   <li>{@link #answered} after: {@code ok}, {@code error} with the code, or {@code not_confirmed}. A
 *       failure here is counted and logged (it alerts), never thrown: the command already ran.</li>
 * </ul>
 * Rows are only inserted (the app role can't update or delete them). The actor and roles always come
 * from the token ({@link Caller}) or name a system job.
 */
@Component
public class AuditLog {

    private static final Logger log = LoggerFactory.getLogger(AuditLog.class);

    /** Who acted: a person from the token, or a job ({@code system:<name>}). */
    public record Actor(String subject, List<String> roles) {
        public static Actor of(Caller caller) {
            return new Actor(caller.subject(), caller.roleNames());
        }

        public static Actor system(String job) {
            return new Actor("system:" + job, List.of());
        }
    }

    /** A command's first row, to answer with {@link #answered}. */
    public record Ticket(String requestId, Actor actor, String tenantId, String action, String target) {}

    /** How a command ended. */
    public enum Outcome { OK, ERROR, NOT_CONFIRMED }

    private final Rls rls;
    private final Clock clock;
    private final ConsoleMetrics metrics;

    public AuditLog(Rls rls, Clock clock, ConsoleMetrics metrics) {
        this.rls = rls;
        this.clock = clock;
        this.metrics = metrics;
    }

    /**
     * Writes the first row (phase "requested"). A null tenant: a job's row no tenant sees (the
     * identity check's mismatch). The request: what was asked, without secrets.
     */
    public Ticket requested(Actor actor, String tenantId, String action, String target, String reason, JsonNode request,
            String requestId) {
        Ticket t = new Ticket(requestId, actor, tenantId, action, target);
        try {
            insert(t, "requested", reason, request, null, null);
            metrics.auditRow("console", "requested", true);
            return t;
        } catch (DataAccessException | IllegalArgumentException e) {
            metrics.auditRow("console", "requested", false);
            log.atError().addKeyValue("action", action).addKeyValue("request_id", requestId)
                    .addKeyValue("cause", e.getClass().getSimpleName())
                    .addKeyValue("event", "audit.write_failed").log("can't write the requested audit row; the command is not sent");
            throw new AuditUnavailableException(e);
        }
    }

    /** Writes the {@code answered} row; never throws. */
    public void answered(Ticket t, Outcome outcome, String errorCode) {
        try {
            insert(t, "answered", null, null, outcome.name().toLowerCase(java.util.Locale.ROOT), errorCode);
            metrics.auditRow("console", "answered", true);
        } catch (RuntimeException e) {
            metrics.auditRow("console", "answered", false);
            log.atError().addKeyValue("action", t.action()).addKeyValue("request_id", t.requestId())
                    .addKeyValue("cause", e.getClass().getSimpleName())
                    .addKeyValue("event", "audit.write_failed").log("can't write the answered audit row; the requested row stays (shown as not confirmed)");
        }
    }

    private void insert(Ticket t, String phase, String reason, JsonNode request, String outcome, String errorCode) {
        OffsetDateTime at = OffsetDateTime.now(clock).withOffsetSameInstant(ZoneOffset.UTC);
        rls.scoped(t.tenantId(), db -> db.sql("""
                INSERT INTO audit_log (id, at, source, phase, request_id, actor, actor_roles, tenant_id, action, target,
                                       reason, request, outcome, error_code)
                VALUES (?, ?, 'console', ?, ?, ?, ?, ?, ?, ?, ?, CAST(? AS jsonb), ?, ?)""")
                .params(Uuid7.next(clock), at, phase, t.requestId(), t.actor().subject(),
                        t.actor().roles().toArray(new String[0]), t.tenantId(), t.action(), t.target(), reason,
                        request == null ? null : request.toString(), outcome, errorCode)
                .update());
    }

    /** UUIDv7 (RFC 9562): 48 bits of Unix milliseconds, then random bits. */
    static final class Uuid7 {
        private static final java.security.SecureRandom RANDOM = new java.security.SecureRandom();

        private Uuid7() {}

        static UUID next(Clock clock) {
            long ms = clock.millis();
            long hi = (ms << 16) | 0x7000L | (RANDOM.nextInt() & 0x0FFFL);
            long lo = (RANDOM.nextLong() & 0x3FFFFFFFFFFFFFFFL) | 0x8000000000000000L;
            return new UUID(hi, lo);
        }
    }
}
