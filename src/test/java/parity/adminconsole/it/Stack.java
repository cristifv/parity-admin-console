package parity.adminconsole.it;

import java.io.IOException;
import java.io.InputStream;
import java.io.UncheckedIOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermissions;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.SecureRandom;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.Statement;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Base64;
import java.util.HexFormat;
import java.util.List;
import java.util.Map;
import java.util.concurrent.TimeUnit;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.testcontainers.containers.GenericContainer;
import org.testcontainers.containers.wait.strategy.Wait;
import org.testcontainers.postgresql.PostgreSQLContainer;
import org.testcontainers.redpanda.RedpandaContainer;
import org.testcontainers.utility.DockerImageName;
import org.testcontainers.utility.MountableFile;

/**
 * The integration tests' stack, started once per JVM, on random host ports, labelled
 * {@code parity.test=parity-admin-console} (scripts/ci.sh removes leftovers):
 * <ul>
 *   <li>Postgres 16 by digest: the console's database (owner = the container user, app role
 *       {@code parity_admin_console_app} created here with a random password) and parity-store's;</li>
 *   <li>Redpanda v26.2.3 (ci.sh checks its digest);</li>
 *   <li>Keycloak 26.8.1 by digest, importing parity-deploy's {@code realm-parity.json} (the realm as
 *       code), with a test service-account certificate; the realm's staff account ({@code platform.admin}
 *       in the {@code platform} organization) is made by parity-deploy's {@code dev-platform-admin.py}
 *       (review MF-1: no person in the realm file), with a random password, only to prove that the
 *       tenant-only console refuses its token (user decision D2, 2026-11-03);</li>
 *   <li>the real parity-store jar, as a process, on that Postgres and Redpanda.</li>
 * </ul>
 * Every password and key is made at random for the run, written under target/ (600), never printed.
 */
public final class Stack {

    public static final String LABEL = "parity.test";
    public static final String LABEL_VALUE = "parity-admin-console";
    static final DockerImageName POSTGRES = DockerImageName.parse(
            "postgres@sha256:721873c34ceb9f8d8fc265984940dc982404c105f19ad51be9fdc5970a6080ea").asCompatibleSubstituteFor("postgres");
    static final DockerImageName REDPANDA = DockerImageName.parse("docker.redpanda.com/redpandadata/redpanda:v26.2.3");
    // Keycloak 26.8.1 (tag 26.8.1-0, 2026-10-13): the newest 26.x patch at least 14 days old (SAML-PLAN step 1).
    static final DockerImageName KEYCLOAK = DockerImageName.parse(
            "quay.io/keycloak/keycloak@sha256:79c623a22abacf3fe6c00a5fb30f5b7843d717b234033b80995891c06116d244");
    public static final String CONSOLE_URL = "http://admin.localhost:18095";

    private static PostgreSQLContainer postgres;
    private static RedpandaContainer redpanda;
    private static GenericContainer<?> keycloak;
    private static Process store;
    private static Process rs;
    private static Path dir;
    private static String appPassword;
    private static String platformAdminPassword;
    private static String keycloakAdminPassword;

    private Stack() {}

    public static synchronized void start() {
        if (postgres != null) {
            return;
        }
        try {
            dir = Path.of("target", "it-stack").toAbsolutePath();
            Files.createDirectories(dir);
            appPassword = random();
            platformAdminPassword = random();
            keycloakAdminPassword = random();
            String saCert = serviceAccountKey();

            postgres = new PostgreSQLContainer(POSTGRES).withDatabaseName("parity_admin_console")
                    .withUsername("parity_admin_console").withLabel(LABEL, LABEL_VALUE);
            redpanda = new RedpandaContainer(REDPANDA).withLabel(LABEL, LABEL_VALUE);
            String realm = System.getProperty("parity.realm.file", "../parity-deploy/compose/keycloak/realm-parity.json");
            keycloak = new GenericContainer<>(KEYCLOAK).withExposedPorts(8080)
                    .withLabel(LABEL, LABEL_VALUE)
                    .withCopyFileToContainer(MountableFile.forHostPath(Path.of(realm).toAbsolutePath()), "/opt/keycloak/data/import/realm-parity.json")
                    .withEnv(Map.of("KC_BOOTSTRAP_ADMIN_USERNAME", "kc-bootstrap", "KC_BOOTSTRAP_ADMIN_PASSWORD", keycloakAdminPassword,
                            "PARITY_ADMIN_CONSOLE_SA_CERT", saCert, "PARITY_ADMIN_CONSOLE_URL", CONSOLE_URL))
                    .withCommand("start-dev", "--import-realm")
                    .waitingFor(Wait.forHttp("/realms/parity/.well-known/openid-configuration").forPort(8080)
                            .withStartupTimeout(Duration.ofMinutes(3)));
            List<Thread> starting = new ArrayList<>();
            for (GenericContainer<?> c : List.of(postgres, redpanda, keycloak)) {
                starting.add(Thread.ofPlatform().start(c::start));
            }
            for (Thread t : starting) {
                t.join();
            }
            if (!postgres.isRunning() || !redpanda.isRunning() || !keycloak.isRunning()) {
                throw new IllegalStateException("a test container didn't start");
            }
            try (Connection c = DriverManager.getConnection(postgres.getJdbcUrl(), postgres.getUsername(), postgres.getPassword());
                    Statement s = c.createStatement()) {
                s.execute("CREATE ROLE parity_admin_console_app LOGIN PASSWORD '" + appPassword + "'");
                s.execute("CREATE DATABASE parity_store");
            }
            write("app-password", appPassword);
            write("owner-password", postgres.getPassword());
            platformAdmin(Path.of(realm).toAbsolutePath().getParent().resolve("dev-platform-admin.py"));
            startStore();
            startRs();
            Runtime.getRuntime().addShutdownHook(new Thread(Stack::stop));
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        } catch (java.sql.SQLException e) {
            throw new IllegalStateException("can't prepare the test database", e);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new IllegalStateException(e);
        }
    }

    /** The realm's staff account, through parity-deploy's script (its secrets in a 700 directory of 600 files). */
    private static void platformAdmin(Path script) throws IOException, InterruptedException {
        Path secrets = dir.resolve("kc-secrets");
        if (!Files.isDirectory(secrets)) {
            Files.createDirectory(secrets, PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rwx------")));
        }
        Files.setPosixFilePermissions(secrets, PosixFilePermissions.fromString("rwx------"));
        write("kc-secrets/admin-password", keycloakAdminPassword);
        write("kc-secrets/platform-admin-password", platformAdminPassword);
        Process p = new ProcessBuilder("python3", "-I", script.toString(), "--keycloak", keycloakUrl(), "--secrets", secrets.toString())
                .redirectErrorStream(true).redirectOutput(dir.resolve("dev-platform-admin.log").toFile()).start();
        if (!p.waitFor(60, TimeUnit.SECONDS) || p.exitValue() != 0) {
            throw new IllegalStateException("dev-platform-admin.py failed (see target/it-stack/dev-platform-admin.log)");
        }
    }

    private static void startStore() throws IOException, InterruptedException {
        String jar = System.getProperty("parity.store.jar", "../parity-store/target/parity-store-0.1.0.jar");
        if (!Files.exists(Path.of(jar))) {
            throw new IllegalStateException("parity-store's jar is missing (scripts/ci.sh builds it)");
        }
        Path healthy = dir.resolve("store.healthy");
        Files.deleteIfExists(healthy);
        String storeDb = postgres.getJdbcUrl().replace("/parity_admin_console", "/parity_store");
        List<String> cmd = List.of(Path.of(System.getProperty("java.home"), "bin", "java").toString(), "-Xmx384m", "-jar",
                Path.of(jar).toAbsolutePath().toString(),
                "--spring.datasource.url=" + storeDb,
                "--spring.datasource.username=" + postgres.getUsername(),
                "--parity-store.db.password-file=" + dir.resolve("owner-password"),
                "--parity-store.kafka.bootstrap-servers=" + redpanda.getBootstrapServers(),
                "--parity-store.kafka.create-topics=true",
                "--parity-store.instance=store-it",
                "--parity-store.lifecycle.healthy-file=" + healthy,
                "--parity-store.lifecycle.drained-file=" + dir.resolve("store.drained"),
                "--server.port=0");
        store = new ProcessBuilder(cmd).redirectErrorStream(true).redirectOutput(dir.resolve("parity-store.log").toFile()).start();
        long deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(90);
        while (!Files.exists(healthy)) {
            if (!store.isAlive()) {
                throw new IllegalStateException("parity-store exited (see target/it-stack/parity-store.log)");
            }
            if (System.nanoTime() > deadline) {
                throw new IllegalStateException("parity-store isn't healthy after 90 s (see target/it-stack/parity-store.log)");
            }
            Thread.sleep(200);
        }
    }

    /**
     * parity-rs's real jar (2026-11-03: it places new tenants): zone eu1a of the shared test topology,
     * single leadership and in-memory assignments (its test profile: no etcd in this stack).
     */
    private static void startRs() throws IOException, InterruptedException {
        String jar = System.getProperty("parity.rs.jar", "../parity-rs/target/parity-rs.jar");
        if (!Files.exists(Path.of(jar))) {
            throw new IllegalStateException("parity-rs's jar is missing (scripts/ci.sh builds it)");
        }
        String contracts = System.getProperty("parity.contracts.dir", "../parity-contracts");
        Path healthy = dir.resolve("rs.healthy");
        Files.deleteIfExists(healthy);
        List<String> cmd = List.of(Path.of(System.getProperty("java.home"), "bin", "java").toString(), "-Xmx256m", "-jar",
                Path.of(jar).toAbsolutePath().toString(), "--spring.profiles.active=test",
                "--parity-rs.zone=eu1a", "--parity-rs.region=eu1", "--parity-rs.instance=rs-it",
                "--parity-rs.topology-file=" + Path.of(contracts, "tenants/test-topology.v1.json").toAbsolutePath(),
                "--parity-rs.kafka.bootstrap-servers=" + redpanda.getBootstrapServers(),
                "--parity-rs.kafka.create-topics=true", "--parity-rs.leadership.mode=single",
                "--parity-rs.etcd.endpoints=memory", "--parity-rs.lifecycle.healthy-file=" + healthy,
                "--parity-rs.lifecycle.drained-file=" + dir.resolve("rs.drained"), "--server.port=0");
        rs = new ProcessBuilder(cmd).redirectErrorStream(true).redirectOutput(dir.resolve("parity-rs.log").toFile()).start();
        long deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(90);
        while (!Files.exists(healthy)) {
            if (!rs.isAlive()) {
                throw new IllegalStateException("parity-rs exited (see target/it-stack/parity-rs.log)");
            }
            if (System.nanoTime() > deadline) {
                throw new IllegalStateException("parity-rs isn't ready after 90 s (see target/it-stack/parity-rs.log)");
            }
            Thread.sleep(200);
        }
    }

    private static void stop() {
        if (rs != null) {
            rs.destroy();
        }
        if (store != null) {
            store.destroy();
        }
        for (GenericContainer<?> c : new GenericContainer<?>[] {keycloak, redpanda, postgres}) {
            if (c != null) {
                c.stop();
            }
        }
    }

    /** The console's settings for this stack. */
    public static void properties(DynamicPropertyRegistry r) {
        start();
        r.add("spring.datasource.url", postgres::getJdbcUrl);
        r.add("spring.datasource.username", () -> "parity_admin_console_app");
        r.add("parity-admin-console.environment", () -> "test");
        r.add("parity-admin-console.instance", () -> "console-it");
        r.add("parity-admin-console.db.password-file", () -> dir.resolve("app-password").toString());
        r.add("parity-admin-console.db.flyway-user", postgres::getUsername);
        r.add("parity-admin-console.db.flyway-password-file", () -> dir.resolve("owner-password").toString());
        r.add("parity-admin-console.kafka.bootstrap-servers", redpanda::getBootstrapServers);
        r.add("parity-admin-console.kafka.create-topics", () -> "true");
        r.add("parity-admin-console.lifecycle.healthy-file", () -> dir.resolve("console.healthy").toString());
        r.add("parity-admin-console.lifecycle.drained-file", () -> dir.resolve("console.drained").toString());
        r.add("parity-admin-console.auth.issuer", Stack::issuer);
        r.add("parity-admin-console.auth.jwks-uri", () -> issuer() + "/protocol/openid-connect/certs");
        r.add("parity-admin-console.identity.enabled", () -> "true");
        r.add("parity-admin-console.identity.keycloak-url", Stack::keycloakUrl);
        r.add("parity-admin-console.identity.key-file", () -> dir.resolve("sa.key.pem").toString());
        r.add("parity-admin-console.identity.tenant-url-template", () -> "http://{tenant}.{region}.localhost:18090");
        r.add("parity-admin-console.identity.regions", () -> "eu1,eu2");
        r.add("parity-admin-console.identity.apply-interval", () -> "500ms");
        r.add("parity-admin-console.identity.check-enabled", () -> "false");
        r.add("management.server.port", () -> "0");
    }

    public static String keycloakUrl() {
        return "http://localhost:" + keycloak.getMappedPort(8080);
    }

    public static String issuer() {
        return keycloakUrl() + "/realms/parity";
    }

    public static String kafka() {
        return redpanda.getBootstrapServers();
    }

    public static String platformAdminPassword() {
        return platformAdminPassword;
    }

    public static String keycloakAdminPassword() {
        return keycloakAdminPassword;
    }

    /** JDBC as the app role (rule 4's test) or the owner. */
    public static Connection connect(boolean owner) throws java.sql.SQLException {
        return owner ? DriverManager.getConnection(postgres.getJdbcUrl(), postgres.getUsername(), postgres.getPassword())
                : DriverManager.getConnection(postgres.getJdbcUrl(), "parity_admin_console_app", appPassword);
    }

    public static Path dir() {
        return dir;
    }

    public static String postgresJdbcUrl() {
        return postgres.getJdbcUrl();
    }

    public static String postgresOwner() {
        return postgres.getUsername();
    }

    /** A test-only RSA key and self-signed certificate (keytool): the key file for the console, the cert for the realm import. */
    private static String serviceAccountKey() throws IOException, InterruptedException {
        Path p12 = dir.resolve("sa.p12");
        Files.deleteIfExists(p12);
        String pass = random();
        ProcessBuilder pb = new ProcessBuilder(Path.of(System.getProperty("java.home"), "bin", "keytool").toString(),
                "-genkeypair", "-alias", "sa", "-keyalg", "RSA", "-keysize", "2048", "-dname", "CN=parity-admin-console",
                "-validity", "30", "-storetype", "PKCS12", "-keystore", p12.toString(), "-storepass:env", "KS_PASS",
                "-keypass:env", "KS_PASS").redirectErrorStream(true).redirectOutput(ProcessBuilder.Redirect.DISCARD);
        // The key store's password through the environment, never the command line.
        pb.environment().put("KS_PASS", pass);
        Process k = pb.start();
        k.getOutputStream().close();
        if (!k.waitFor(60, TimeUnit.SECONDS) || k.exitValue() != 0) {
            throw new IllegalStateException("keytool failed");
        }
        return certificateFrom(p12, pass);
    }

    private static String certificateFrom(Path p12, String pass) throws IOException {
        try (InputStream in = Files.newInputStream(p12)) {
            KeyStore ks = KeyStore.getInstance("PKCS12");
            ks.load(in, pass.toCharArray());
            PrivateKey key = (PrivateKey) ks.getKey("sa", pass.toCharArray());
            String pem = "-----BEGIN PRIVATE KEY-----\n" + Base64.getMimeEncoder(64, "\n".getBytes(StandardCharsets.US_ASCII))
                    .encodeToString(key.getEncoded()) + "\n-----END PRIVATE KEY-----\n";
            write("sa.key.pem", pem);
            return Base64.getEncoder().encodeToString(ks.getCertificate("sa").getEncoded());
        } catch (java.security.GeneralSecurityException e) {
            throw new IllegalStateException("can't read the test key store", e);
        }
    }

    private static void write(String name, String value) throws IOException {
        Path f = dir.resolve(name);
        Files.deleteIfExists(f);
        Files.createFile(f, PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rw-------")));
        Files.writeString(f, value, StandardCharsets.UTF_8);
    }

    private static String random() {
        byte[] b = new byte[24];
        new SecureRandom().nextBytes(b);
        return HexFormat.of().formatHex(b);
    }
}
