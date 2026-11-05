package parity.adminconsole.it;

import static org.assertj.core.api.Assertions.assertThat;

import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermissions;
import java.security.SecureRandom;
import java.sql.Connection;
import java.sql.Statement;
import java.util.ArrayList;
import java.util.HexFormat;
import java.util.List;
import java.util.concurrent.TimeUnit;
import org.junit.jupiter.api.Test;

/**
 * Console step 0's "SIGTERM drains cleanly", on the packaged jar as a process: the healthy file once
 * Flyway ran and the replies partitions are assigned (Keycloak isn't needed to start), then on SIGTERM
 * the healthy file goes, the drained file comes, and the exit code is 0.
 */
class DrainIT {

    @Test
    void startsHealthyAndDrainsOnSigterm() throws Exception {
        Stack.start();
        String jar = System.getProperty("console.jar", "target/parity-admin-console-0.1.0.jar");
        Path dir = Stack.dir();
        Path healthy = dir.resolve("drain.healthy");
        Path drained = dir.resolve("drain.drained");
        Files.deleteIfExists(healthy);
        Files.deleteIfExists(drained);
        List<String> cmd = List.of(Path.of(System.getProperty("java.home"), "bin", "java").toString(), "-Xmx256m", "-jar",
                Path.of(jar).toAbsolutePath().toString(),
                "--spring.datasource.url=" + Stack.postgresJdbcUrl(),
                "--spring.datasource.username=parity_admin_console_app",
                "--parity-admin-console.environment=test",
                "--parity-admin-console.instance=console-drain",
                "--parity-admin-console.db.password-file=" + dir.resolve("app-password"),
                "--parity-admin-console.db.flyway-user=" + Stack.postgresOwner(),
                "--parity-admin-console.db.flyway-password-file=" + dir.resolve("owner-password"),
                "--parity-admin-console.kafka.bootstrap-servers=" + Stack.kafka(),
                "--parity-admin-console.kafka.create-topics=true",
                "--parity-admin-console.lifecycle.healthy-file=" + healthy,
                "--parity-admin-console.lifecycle.drained-file=" + drained,
                "--parity-admin-console.lifecycle.deregistration-delay=200ms",
                "--parity-admin-console.auth.issuer=http://127.0.0.1:9/realms/parity",
                "--parity-admin-console.auth.jwks-uri=http://127.0.0.1:9/realms/parity/protocol/openid-connect/certs",
                "--server.port=0", "--management.server.port=0");
        Process p = new ProcessBuilder(cmd).redirectErrorStream(true).redirectOutput(dir.resolve("drain-it.log").toFile()).start();
        try {
            long deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(60);
            while (!Files.exists(healthy) && p.isAlive() && System.nanoTime() < deadline) {
                Thread.sleep(100);
            }
            assertThat(Files.exists(healthy)).as("healthy with Keycloak unreachable (see target/it-stack/drain-it.log)").isTrue();
            p.destroy(); // SIGTERM
            assertThat(p.waitFor(45, TimeUnit.SECONDS)).isTrue();
            assertThat(p.exitValue()).isZero();
            assertThat(Files.exists(drained)).isTrue();
            assertThat(Files.exists(healthy)).isFalse();
        } finally {
            p.destroyForcibly();
        }
    }

    /**
     * Review F7: an app database role that row-level security doesn't bind is refused at start, exit 2:
     * the owner of the test database (a superuser), and a plain role with BYPASSRLS.
     */
    @Test
    void refusesAnAppRoleThatRowLevelSecurityDoesntBind() throws Exception {
        Stack.start();
        Path dir = Stack.dir();
        String pw = HexFormat.of().formatHex(new SecureRandom().generateSeed(16));
        try (Connection c = Stack.connect(true); Statement s = c.createStatement()) {
            s.execute("DROP ROLE IF EXISTS acw2_bypass");
            s.execute("CREATE ROLE acw2_bypass LOGIN BYPASSRLS PASSWORD '" + pw + "'");
        }
        Path pwFile = dir.resolve("bypass-password");
        Files.deleteIfExists(pwFile);
        Files.createFile(pwFile, PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rw-------")));
        Files.writeString(pwFile, pw);
        assertThat(startAs(Stack.postgresOwner(), dir.resolve("owner-password"), "superuser")).isEqualTo(2);
        assertThat(Files.readString(dir.resolve("role-superuser.log"))).contains("is a superuser");
        assertThat(startAs("acw2_bypass", pwFile, "bypass")).isEqualTo(2);
        assertThat(Files.readString(dir.resolve("role-bypass.log"))).contains("BYPASSRLS");
    }

    private static int startAs(String user, Path passwordFile, String name) throws Exception {
        Path dir = Stack.dir();
        String jar = System.getProperty("console.jar", "target/parity-admin-console-0.1.0.jar");
        List<String> cmd = new ArrayList<>(List.of(Path.of(System.getProperty("java.home"), "bin", "java").toString(), "-Xmx256m", "-jar",
                Path.of(jar).toAbsolutePath().toString(),
                "--spring.datasource.url=" + Stack.postgresJdbcUrl(),
                "--spring.datasource.username=" + user,
                "--parity-admin-console.environment=test",
                "--parity-admin-console.instance=console-role-" + name,
                "--parity-admin-console.db.password-file=" + passwordFile,
                "--parity-admin-console.kafka.bootstrap-servers=" + Stack.kafka(),
                "--parity-admin-console.lifecycle.healthy-file=" + dir.resolve("role-" + name + ".healthy"),
                "--parity-admin-console.lifecycle.drained-file=" + dir.resolve("role-" + name + ".drained"),
                "--parity-admin-console.auth.issuer=http://127.0.0.1:9/realms/parity",
                "--parity-admin-console.auth.jwks-uri=http://127.0.0.1:9/realms/parity/protocol/openid-connect/certs",
                "--server.port=0", "--management.server.port=0"));
        Process p = new ProcessBuilder(cmd).redirectErrorStream(true).redirectOutput(dir.resolve("role-" + name + ".log").toFile()).start();
        try {
            assertThat(p.waitFor(60, TimeUnit.SECONDS)).as("the console refused to start as " + name).isTrue();
            return p.exitValue();
        } finally {
            p.destroyForcibly();
        }
    }
}
