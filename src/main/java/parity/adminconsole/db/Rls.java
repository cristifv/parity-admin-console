package parity.adminconsole.db;

import java.util.function.Function;
import java.util.regex.Pattern;
import org.springframework.jdbc.core.simple.JdbcClient;
import org.springframework.stereotype.Component;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.TransactionDefinition;
import org.springframework.transaction.support.TransactionTemplate;

/**
 * Row-level security per transaction (PLAN.md "Security and tenancy", multi-tenant rules 4 and 10):
 * every transaction sets {@code app.tenant_id} ({@code SET LOCAL}) for one tenant, or {@code app.platform}
 * for a platform-wide query of the console's own jobs (identity apply and check, never a request's
 * caller: user decision D2, 2026-11-03); a query with neither sees and writes no row. Only this class
 * sets them.
 */
@Component
public class Rls {

    private static final Pattern TENANT = Pattern.compile("^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$");

    private final JdbcClient db;
    private final TransactionTemplate tx;
    private final TransactionTemplate newTx;

    public Rls(JdbcClient db, PlatformTransactionManager transactions) {
        this.db = db;
        this.tx = new TransactionTemplate(transactions);
        this.newTx = new TransactionTemplate(transactions);
        this.newTx.setPropagationBehavior(TransactionDefinition.PROPAGATION_REQUIRES_NEW);
    }

    /** {@code work} in one transaction that sees {@code tenantId}'s rows only. */
    public <T> T tenant(String tenantId, Function<JdbcClient, T> work) {
        if (tenantId == null || !TENANT.matcher(tenantId).matches()) {
            throw new IllegalArgumentException("not a tenant id");
        }
        return tx.execute(status -> {
            db.sql("SELECT set_config('app.tenant_id', ?, true)").param(tenantId).query(String.class).single();
            return work.apply(db);
        });
    }

    /**
     * {@link #tenant}, always in a transaction of its own, committed when this returns, even inside another
     * one: a write-ahead record (the accounts a suspension disables) must survive the caller's rollback.
     */
    public <T> T tenantCommitted(String tenantId, Function<JdbcClient, T> work) {
        if (tenantId == null || !TENANT.matcher(tenantId).matches()) {
            throw new IllegalArgumentException("not a tenant id");
        }
        return newTx.execute(status -> {
            db.sql("SELECT set_config('app.tenant_id', ?, true)").param(tenantId).query(String.class).single();
            return work.apply(db);
        });
    }

    /** {@code work} in one platform-wide transaction: the jobs only, never for a request's caller. */
    public <T> T platform(Function<JdbcClient, T> work) {
        return tx.execute(status -> {
            db.sql("SELECT set_config('app.platform', 'on', true)").query(String.class).single();
            return work.apply(db);
        });
    }

    /** {@link #tenant} for a tenant, {@link #platform} for null. */
    public <T> T scoped(String tenantIdOrNull, Function<JdbcClient, T> work) {
        return tenantIdOrNull == null ? platform(work) : tenant(tenantIdOrNull, work);
    }
}
