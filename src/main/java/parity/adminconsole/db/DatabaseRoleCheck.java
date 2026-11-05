package parity.adminconsole.db;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.boot.flyway.autoconfigure.FlywayMigrationInitializer;
import org.springframework.jdbc.core.simple.JdbcClient;
import org.springframework.stereotype.Component;
import parity.adminconsole.lifecycle.ConfigurationRefusedException;

/**
 * Row-level security holds only for a role it applies to (review F7): at start, after the migrations
 * when they run in the app, the console refuses (exit 2) an app database role that is a superuser,
 * has {@code BYPASSRLS}, or owns the console's tables (or belongs to their owner): each of those reads
 * and writes every tenant's rows whatever {@code app.tenant_id} says. The app role is
 * {@code parity_admin_console_app}; the owner runs the migrations only.
 */
@Component
public class DatabaseRoleCheck {

    private static final Logger log = LoggerFactory.getLogger(DatabaseRoleCheck.class);

    /** What the check reads about the role the pool connects as. */
    record Role(boolean superuser, boolean bypassRls, boolean ownsTables) {}

    public DatabaseRoleCheck(JdbcClient db, ObjectProvider<FlywayMigrationInitializer> migrations) {
        // The migrations first, when they run in the app (the tables' owner is then known).
        migrations.ifAvailable(m -> { });
        Role role = db.sql("""
                SELECT r.rolsuper, r.rolbypassrls,
                       EXISTS (SELECT 1 FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
                               WHERE n.nspname = current_schema()
                                 AND c.relname IN ('audit_log', 'tenant_identity', 'identity_suspension', 'number_destination')
                                 AND pg_has_role(current_user, c.relowner, 'USAGE')) AS owns
                FROM pg_roles r WHERE r.rolname = current_user""")
                .query((rs, n) -> new Role(rs.getBoolean(1), rs.getBoolean(2), rs.getBoolean(3))).single();
        refuse(role);
        log.atInfo().addKeyValue("event", "db.rls_detected").log("the app database role is subject to row-level security");
    }

    static void refuse(Role role) {
        if (role.superuser()) {
            throw new ConfigurationRefusedException("the app database role is a superuser: row-level security doesn't apply to it");
        }
        if (role.bypassRls()) {
            throw new ConfigurationRefusedException("the app database role has BYPASSRLS: row-level security doesn't apply to it");
        }
        if (role.ownsTables()) {
            throw new ConfigurationRefusedException("the app database role owns the console's tables (or belongs to their owner): use the app role");
        }
    }
}
