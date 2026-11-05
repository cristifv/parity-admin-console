package parity.adminconsole.lifecycle;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.jdbc.core.simple.JdbcClient;
import parity.adminconsole.audit.AuditPartitions;
import parity.adminconsole.backend.BackendClient;

/**
 * The readiness checks (PLAN.md "Startup and graceful shutdown"): Postgres answers (Flyway ran before
 * the context started), the replies partitions are assigned, the audit log's partitions exist. Keycloak
 * isn't one: its keys are fetched on the first request, so the console starts while it's down.
 */
@Configuration
public class ConsoleReadiness {

    @Bean
    @Order(1)
    ReadinessChecks.Check postgresCheck(JdbcClient db) {
        return new ReadinessChecks.Check("postgres", () -> {
            try {
                db.sql("SELECT 1").query(Integer.class).single();
                return null;
            } catch (RuntimeException e) {
                return "Postgres doesn't answer (" + e.getClass().getSimpleName() + ")";
            }
        });
    }

    @Bean
    @Order(2)
    ReadinessChecks.Check repliesCheck(BackendClient backend) {
        return new ReadinessChecks.Check("replies", backend::failure);
    }

    @Bean
    @Order(3)
    ReadinessChecks.Check auditPartitionsCheck(AuditPartitions partitions) {
        return new ReadinessChecks.Check("audit_partitions", partitions::failure);
    }
}
