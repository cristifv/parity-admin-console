package parity.adminconsole.identity;

import java.sql.ResultSet;
import java.sql.SQLException;
import java.time.Clock;
import java.time.Duration;
import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import java.util.List;
import java.util.Optional;
import org.springframework.jdbc.core.simple.JdbcClient;
import org.springframework.stereotype.Component;
import parity.adminconsole.db.Rls;

/**
 * {@code tenant_identity} and {@code identity_suspension} (V2): the desired identity state of each
 * tenant, what was applied to Keycloak, and the accounts a suspension disabled. A change bumps
 * {@code version}; the apply job brings {@code applied_version} up to it.
 */
@Component
public class TenantIdentities {

    /** A tenant's identity state. */
    public enum State { ACTIVE, SUSPENDED, DELETED }

    /** One row. */
    public record Row(String tenantId, State state, String name, long version, long appliedVersion,
            String organizationId, String desktopClientId, String lastApplyError, int attempts) {

        public boolean applied() {
            return appliedVersion >= version;
        }
    }

    private final Rls rls;
    private final Clock clock;

    public TenantIdentities(Rls rls, Clock clock) {
        this.rls = rls;
        this.clock = clock;
    }

    private OffsetDateTime now() {
        return OffsetDateTime.now(clock).withOffsetSameInstant(ZoneOffset.UTC);
    }

    /** The row, read in the tenant's own scope. */
    public Optional<Row> get(String tenantId) {
        return rls.tenant(tenantId, db -> db.sql("SELECT * FROM tenant_identity WHERE tenant_id = ?")
                .param(tenantId).query(TenantIdentities::row).optional());
    }

    /**
     * A new tenant's identity: active, version 1. A row that exists already is left as it is: a retry
     * finds it active, and a deleted tenant's id is retired for good, never brought back (decision
     * 2026-10-31, review MF-3: the audit log and the accounts key on the id).
     */
    public void create(String tenantId, String name) {
        OffsetDateTime now = now();
        rls.tenant(tenantId, db -> db.sql("""
                INSERT INTO tenant_identity (tenant_id, state, name, version, created_at, updated_at)
                VALUES (?, 'active', ?, 1, ?, ?)
                ON CONFLICT (tenant_id) DO NOTHING""")
                .params(tenantId, name, now, now).update());
    }

    /** The id belonged to a tenant that was deleted: retired, never to be created again. */
    public boolean retired(String tenantId) {
        return rls.platform(db -> db.sql("SELECT count(*) FROM tenant_identity WHERE tenant_id = ? AND state = 'deleted'")
                .param(tenantId).query(Long.class).single()) > 0;
    }

    /** A new desired state: version + 1, to be applied at once. False when there's no row. */
    public boolean desire(String tenantId, State state) {
        int n = rls.tenant(tenantId, db -> db.sql("""
                UPDATE tenant_identity SET state = ?, version = version + 1, next_attempt_at = now(), attempts = 0,
                    updated_at = ? WHERE tenant_id = ?""")
                .params(state.name().toLowerCase(java.util.Locale.ROOT), now(), tenantId).update());
        return n == 1;
    }

    /** Asks for the current state to be applied again (a drift repair): version + 1, same state. */
    public void reapply(String tenantId) {
        rls.platform(db -> db.sql("""
                UPDATE tenant_identity SET version = version + 1, next_attempt_at = now(), attempts = 0, updated_at = ?
                WHERE tenant_id = ?""").params(now(), tenantId).update());
    }

    /** Tenants whose state isn't applied yet and whose next attempt is due. */
    public List<String> due(int limit) {
        return rls.platform(db -> db.sql("""
                SELECT tenant_id FROM tenant_identity WHERE applied_version < version AND next_attempt_at <= now()
                ORDER BY next_attempt_at LIMIT ?""").param(limit).query(String.class).list());
    }

    /** Every tenant that isn't deleted (the nightly check). */
    public List<Row> live() {
        return rls.platform(db -> db.sql("SELECT * FROM tenant_identity WHERE state <> 'deleted' ORDER BY tenant_id")
                .query(TenantIdentities::row).list());
    }

    public boolean exists(String tenantId) {
        return rls.platform(db -> db.sql("SELECT count(*) FROM tenant_identity WHERE tenant_id = ?")
                .param(tenantId).query(Long.class).single()) > 0;
    }

    /** The row locked for one apply, in the caller's platform transaction; empty if another instance holds it. */
    static Optional<Row> lock(JdbcClient db, String tenantId) {
        // NO KEY UPDATE: excludes another apply, but not the suspension rows' foreign-key checks (their own
        // committed transactions, written while this lock is held).
        return db.sql("SELECT * FROM tenant_identity WHERE tenant_id = ? FOR NO KEY UPDATE SKIP LOCKED")
                .param(tenantId).query(TenantIdentities::row).optional();
    }

    static void applied(JdbcClient db, Row r, String organizationId, String desktopClientId, OffsetDateTime now) {
        db.sql("""
                UPDATE tenant_identity SET applied_version = ?, organization_id = ?, desktop_client_id = ?,
                    last_apply_error = NULL, attempts = 0, updated_at = ? WHERE tenant_id = ?""")
                .params(r.version(), organizationId, desktopClientId, now, r.tenantId()).update();
    }

    static void failed(JdbcClient db, Row r, String code, Duration backoff, OffsetDateTime now) {
        db.sql("""
                UPDATE tenant_identity SET last_apply_error = ?, attempts = attempts + 1, next_attempt_at = ?, updated_at = ?
                WHERE tenant_id = ?""").params(code, now.plus(backoff), now, r.tenantId()).update();
    }

    /** Records, in its own committed transaction, that a suspension disables this account (before it does). */
    public void suspended(String tenantId, String userId) {
        rls.tenantCommitted(tenantId, db -> db.sql("""
                INSERT INTO identity_suspension (tenant_id, user_id, disabled_at) VALUES (?, ?, ?)
                ON CONFLICT DO NOTHING""").params(tenantId, userId, now()).update());
    }

    public List<String> suspendedUsers(String tenantId) {
        return rls.tenant(tenantId, db -> db.sql("SELECT user_id FROM identity_suspension WHERE tenant_id = ? ORDER BY user_id")
                .param(tenantId).query(String.class).list());
    }

    public void unsuspended(String tenantId, String userId) {
        rls.tenantCommitted(tenantId, db -> db.sql("DELETE FROM identity_suspension WHERE tenant_id = ? AND user_id = ?")
                .params(tenantId, userId).update());
    }

    private static Row row(ResultSet rs, int n) throws SQLException {
        return new Row(rs.getString("tenant_id"), State.valueOf(rs.getString("state").toUpperCase(java.util.Locale.ROOT)),
                rs.getString("name"), rs.getLong("version"), rs.getLong("applied_version"), rs.getString("organization_id"),
                rs.getString("desktop_client_id"), rs.getString("last_apply_error"), rs.getInt("attempts"));
    }
}
