package parity.adminconsole.it;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.Properties;
import org.apache.kafka.clients.consumer.KafkaConsumer;
import org.apache.kafka.common.TopicPartition;
import org.apache.kafka.common.serialization.StringDeserializer;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import parity.adminconsole.ParityAdminConsoleApplication;
import parity.adminconsole.audit.AuditUnavailableException;
import parity.adminconsole.backend.BackendException;
import parity.adminconsole.tenants.ServiceIdentity;
import parity.adminconsole.tenants.TenantService;

/**
 * Console step 2: the audit log's partitions, row-level security (multi-tenant rules 4 and 10) for the
 * insert-and-read app role (the {@code app.platform} setting is the console's jobs' only, never a
 * request's caller), and "a command whose requested row fails isn't sent".
 */
@SpringBootTest(classes = ParityAdminConsoleApplication.class, webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
class AuditIT {

    @DynamicPropertySource
    static void properties(DynamicPropertyRegistry r) {
        Stack.properties(r);
    }

    @Autowired
    TenantService tenants;

    @Test
    void partitionsAreMonthlyAndCreatedAhead() throws SQLException {
        try (Connection c = Stack.connect(true); Statement s = c.createStatement();
                ResultSet rs = s.executeQuery("SELECT count(*) FROM pg_inherits WHERE inhparent = 'audit_log'::regclass")) {
            rs.next();
            assertThat(rs.getInt(1)).isGreaterThanOrEqualTo(4);
        }
    }

    @Test
    void rule4_withoutATenantOrPlatformSettingTheAppRoleSeesAndWritesNothing() throws SQLException {
        try (Connection c = Stack.connect(false)) {
            c.setAutoCommit(false);
            try (Statement s = c.createStatement()) {
                s.execute("SELECT set_config('app.platform', 'on', true)");
                for (String tenant : List.of("rls-a", "rls-b")) {
                    s.execute("INSERT INTO audit_log (id, at, source, phase, request_id, actor, actor_roles, tenant_id, action) "
                            + "VALUES (gen_random_uuid(), now(), 'console', 'requested', 'rls:" + tenant + "', 'test', '{}', '" + tenant + "', 'test.row')");
                }
            }
            c.commit();
            assertThat(count(c, null)).as("no setting: no rows").isZero();
            assertThat(count(c, "rls-a")).isEqualTo(1);
            assertThat(count(c, "rls-b")).isEqualTo(1);
            // Writing without a setting, or for another tenant than the one set, is refused by the policy.
            try (Statement s = c.createStatement()) {
                assertThatThrownBy(() -> s.execute("INSERT INTO audit_log (id, at, source, phase, request_id, actor, actor_roles, tenant_id, action) "
                        + "VALUES (gen_random_uuid(), now(), 'console', 'requested', 'rls:x', 'test', '{}', 'rls-a', 'test.row')"))
                        .isInstanceOf(SQLException.class);
            }
            c.rollback();
            try (Statement s = c.createStatement()) {
                s.execute("SELECT set_config('app.tenant_id', 'rls-a', true)");
                assertThatThrownBy(() -> s.execute("INSERT INTO audit_log (id, at, source, phase, request_id, actor, actor_roles, tenant_id, action) "
                        + "VALUES (gen_random_uuid(), now(), 'console', 'requested', 'rls:y', 'test', '{}', 'rls-b', 'test.row')"))
                        .isInstanceOf(SQLException.class);
            }
            c.rollback();
            // Insert and read only: no row is ever changed or removed.
            try (Statement s = c.createStatement()) {
                s.execute("SELECT set_config('app.platform', 'on', true)");
                assertThatThrownBy(() -> s.execute("UPDATE audit_log SET actor = 'x'")).isInstanceOf(SQLException.class);
            }
            c.rollback();
            try (Statement s = c.createStatement()) {
                s.execute("SELECT set_config('app.platform', 'on', true)");
                assertThatThrownBy(() -> s.execute("DELETE FROM audit_log")).isInstanceOf(SQLException.class);
            }
            c.rollback();
            // A partition can't be reached around the parent's policies.
            try (Statement s = c.createStatement()) {
                assertThatThrownBy(() -> s.executeQuery("SELECT count(*) FROM audit_log_y" + java.time.YearMonth.now(java.time.ZoneOffset.UTC)
                        .toString().replace("-", "m"))).isInstanceOf(SQLException.class);
            }
            c.rollback();
        }
    }

    /**
     * SAML-PLAN rule 10 on the console's own tenant tables (V2): without a setting the app role sees no
     * row, with a tenant set it sees and changes that tenant's only. One transaction, rolled back, so the
     * identity apply job and the nightly check never see these rows.
     */
    @Test
    void rule10_theTenantTablesShowAndTakeOnlyTheTenantSet() throws SQLException {
        List<String> tables = List.of("tenant_identity", "identity_suspension", "number_destination");
        try (Connection c = Stack.connect(false)) {
            c.setAutoCommit(false);
            try (Statement s = c.createStatement()) {
                s.execute("SELECT set_config('app.platform', 'on', true)");
                for (String tenant : List.of("rls-a", "rls-b")) {
                    s.execute("INSERT INTO tenant_identity (tenant_id, state, name, version, applied_version, created_at, updated_at) "
                            + "VALUES ('" + tenant + "', 'active', 'RLS test', 1, 1, now(), now())");
                    s.execute("INSERT INTO identity_suspension (tenant_id, user_id, disabled_at) VALUES ('" + tenant + "', 'u-" + tenant + "', now())");
                    s.execute("INSERT INTO number_destination (tenant_id, number, kind, target, version, updated_by, updated_at) "
                            + "VALUES ('" + tenant + "', '+15550199001', 'queue', 'q', 1, 'test', now())");
                }
                s.execute("SELECT set_config('app.platform', '', true)");
                for (String table : tables) {
                    assertThat(rlsCount(s, table)).as(table + " with no setting").isZero();
                }
                s.execute("SELECT set_config('app.tenant_id', 'rls-a', true)");
                for (String table : tables) {
                    assertThat(rlsCount(s, table)).as(table + " for rls-a").isEqualTo(1);
                }
                assertThat(s.executeUpdate("UPDATE number_destination SET target = 'x' WHERE tenant_id = 'rls-b'"))
                        .as("another tenant's row can't be changed").isZero();
                assertThat(s.executeUpdate("UPDATE tenant_identity SET state = 'suspended' WHERE tenant_id = 'rls-b'")).isZero();
                assertThatThrownBy(() -> s.execute("INSERT INTO number_destination (tenant_id, number, kind, target, version, updated_by, updated_at) "
                        + "VALUES ('rls-b', '+15550199002', 'queue', 'q', 1, 'test', now())"))
                        .as("nor written for it").isInstanceOf(SQLException.class);
            } finally {
                c.rollback();
            }
        }
    }

    private static int rlsCount(Statement s, String table) throws SQLException {
        try (ResultSet rs = s.executeQuery("SELECT count(*) FROM " + table + " WHERE tenant_id IN ('rls-a', 'rls-b')")) {
            rs.next();
            return rs.getInt(1);
        }
    }

    /** A tenant creation (billing's provisioning, in-process: no HTTP route since D2) without its audit row isn't sent. */
    @Test
    void aCommandWhoseRequestedRowFailsIsNotSent() throws SQLException {
        long before = adminTopicRecords("unsent");
        try (Connection owner = Stack.connect(true); Statement s = owner.createStatement()) {
            s.execute("REVOKE INSERT ON audit_log FROM parity_admin_console_app");
            try {
                assertThatThrownBy(() -> tenants.create(ServiceIdentity.PROVISIONING,
                        new TenantService.CreateTenant("unsent", "Never sent", "small", null, null)))
                        .isInstanceOf(AuditUnavailableException.class);
            } finally {
                s.execute("GRANT INSERT ON audit_log TO parity_admin_console_app");
            }
        }
        assertThat(adminTopicRecords("unsent")).as("nothing reached parity-store's admin topic").isEqualTo(before);
        assertThatThrownBy(() -> tenants.get("unsent")).isInstanceOf(BackendException.class)
                .extracting(e -> ((BackendException) e).kind()).isEqualTo(BackendException.Kind.NOT_FOUND);
    }

    private static int count(Connection c, String tenant) throws SQLException {
        try (Statement s = c.createStatement()) {
            if (tenant != null) {
                try (PreparedStatement p = c.prepareStatement("SELECT set_config('app.tenant_id', ?, true)")) {
                    p.setString(1, tenant);
                    p.execute();
                }
            }
            try (ResultSet rs = s.executeQuery("SELECT count(*) FROM audit_log WHERE action = 'test.row'")) {
                rs.next();
                int n = rs.getInt(1);
                c.rollback();
                return n;
            }
        }
    }

    private static long adminTopicRecords(String tenant) {
        Properties p = new Properties();
        p.put("bootstrap.servers", Stack.kafka());
        String topic = "tenant.store.admin.requests";
        try (KafkaConsumer<String, String> c = new KafkaConsumer<>(p, new StringDeserializer(), new StringDeserializer())) {
            List<TopicPartition> parts = new ArrayList<>();
            c.partitionsFor(topic).forEach(i -> parts.add(new TopicPartition(topic, i.partition())));
            c.assign(parts);
            c.seekToBeginning(parts);
            var end = c.endOffsets(parts);
            long n = 0;
            long deadline = System.nanoTime() + Duration.ofSeconds(20).toNanos();
            while (parts.stream().anyMatch(tp -> c.position(tp) < end.get(tp)) && System.nanoTime() < deadline) {
                for (var r : c.poll(Duration.ofMillis(200))) {
                    if (tenant.equals(r.key())) {
                        n++;
                    }
                }
            }
            return n;
        }
    }
}
