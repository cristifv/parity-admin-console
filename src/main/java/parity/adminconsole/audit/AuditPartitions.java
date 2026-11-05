package parity.adminconsole.audit;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.context.event.ApplicationReadyEvent;
import org.springframework.context.event.EventListener;
import org.springframework.jdbc.core.simple.JdbcClient;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;
import parity.adminconsole.config.AdminConsoleProperties;

/**
 * Keeps the audit log's monthly partitions created ahead (PLAN.md: "monthly partitions, created ahead
 * by a job"), at start and then every {@code audit.partition-interval}, through the owner's
 * {@code audit_log_ensure_partitions} function (the app role can't create tables). A month without a
 * partition would make every command's {@code requested} row fail, so commands stop rather than run
 * unaudited; a failure here alerts first (readiness, the log).
 */
@Component
public class AuditPartitions {

    private static final Logger log = LoggerFactory.getLogger(AuditPartitions.class);

    private final JdbcClient db;
    private final int ahead;
    private volatile String failure = "partitions not checked yet";

    public AuditPartitions(JdbcClient db, AdminConsoleProperties properties) {
        this.db = db;
        this.ahead = properties.audit().partitionsAhead();
    }

    @EventListener(ApplicationReadyEvent.class)
    public void atStart() {
        ensure();
    }

    @Scheduled(fixedDelayString = "${parity-admin-console.audit.partition-interval}",
            initialDelayString = "${parity-admin-console.audit.partition-interval}")
    public void ensure() {
        try {
            Integer created = db.sql("SELECT audit_log_ensure_partitions(?)").param(ahead).query(Integer.class).single();
            if (created != null && created > 0) {
                log.atInfo().addKeyValue("created", created).addKeyValue("event", "audit.partitions_created").log("created audit log partitions");
            }
            failure = null;
        } catch (RuntimeException e) {
            failure = "audit partitions can't be checked (" + e.getClass().getSimpleName() + ")";
            log.atError().addKeyValue("cause", e.getClass().getSimpleName()).addKeyValue("event", "audit.partitions_failed").log("can't create the audit log's partitions ahead");
        }
    }

    /** Null when the partitions are in place. */
    public String failure() {
        return failure;
    }
}
