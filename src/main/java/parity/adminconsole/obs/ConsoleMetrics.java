package parity.adminconsole.obs;

import io.micrometer.core.instrument.Counter;
import io.micrometer.core.instrument.Gauge;
import io.micrometer.core.instrument.MeterRegistry;
import io.micrometer.core.instrument.Timer;
import java.time.Duration;
import org.springframework.stereotype.Component;

/**
 * The console's metrics (PLAN.md "Observability"). No label carries a tenant: tenants are many and
 * unbounded (ARCH §7.5); the audit log answers per-tenant questions.
 */
@Component
public class ConsoleMetrics {

    private final MeterRegistry registry;

    public ConsoleMetrics(MeterRegistry registry) {
        this.registry = registry;
        Gauge.builder("admin_log_lines_dropped", CountingAsyncAppender::dropped).register(registry);
    }

    /** {@code admin_backend_requests_total} and {@code admin_backend_latency_seconds}. */
    public void backend(String backend, String cmd, String outcome, long startedNanos) {
        Counter.builder("admin_backend_requests_total").tag("backend", backend).tag("cmd", cmd).tag("outcome", outcome)
                .register(registry).increment();
        Timer.builder("admin_backend_latency_seconds").tag("backend", backend).tag("cmd", cmd).tag("outcome", outcome)
                .register(registry).record(Duration.ofNanos(System.nanoTime() - startedNanos));
    }

    /** {@code admin_audit_rows_total} and {@code admin_audit_write_failures_total} (any failure alerts). */
    public void auditRow(String source, String phase, boolean ok) {
        Counter.builder(ok ? "admin_audit_rows_total" : "admin_audit_write_failures_total")
                .tag("source", source).tag("phase", phase).register(registry).increment();
    }

    /** {@code admin_identity_apply_total{result}} (SAML-PLAN "Observability": admin_sso_apply_total). */
    public void identityApply(String result) {
        Counter.builder("admin_identity_apply_total").tag("result", result).register(registry).increment();
    }

    /** {@code admin_identity_repairs_total{what}}: the nightly check's repairs (each one alerts). */
    public void identityRepair(String what) {
        Counter.builder("admin_identity_repairs_total").tag("what", what).register(registry).increment();
    }

    /** {@code admin_token_refusals_total{reason}}: tokens refused by the checks beyond signature and expiry. */
    public void tokenRefused(String reason) {
        Counter.builder("admin_token_refusals_total").tag("reason", reason).register(registry).increment();
    }
}
