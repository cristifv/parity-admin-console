package parity.adminconsole.it;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.sql.Connection;
import java.sql.ResultSet;
import java.sql.Statement;
import java.time.Duration;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HexFormat;
import java.util.List;
import java.util.Map;
import java.util.Properties;
import org.apache.kafka.clients.consumer.ConsumerRecord;
import org.apache.kafka.clients.consumer.KafkaConsumer;
import org.apache.kafka.clients.producer.KafkaProducer;
import org.apache.kafka.clients.producer.ProducerRecord;
import org.apache.kafka.common.TopicPartition;
import org.apache.kafka.common.header.Header;
import org.apache.kafka.common.serialization.StringDeserializer;
import org.apache.kafka.common.serialization.StringSerializer;
import org.junit.jupiter.api.MethodOrderer;
import org.junit.jupiter.api.Order;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestMethodOrder;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import parity.adminconsole.ParityAdminConsoleApplication;
import parity.adminconsole.backend.BackendException;
import parity.adminconsole.identity.IdentityCheck;
import parity.adminconsole.identity.LocalAccounts;
import parity.adminconsole.tenants.OpsActor;
import parity.adminconsole.tenants.ServiceIdentity;
import parity.adminconsole.tenants.TenantService;
import parity.adminconsole.web.ApiException;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.json.JsonMapper;
import tools.jackson.databind.node.ObjectNode;

/**
 * Console steps 0, 2 and 9 and SAML-PLAN steps 3 and 4, end to end on the real pieces: Keycloak with
 * the realm as code, parity-store's and parity-rs's jars, Postgres and Redpanda (see {@link Stack}).
 * The tests run in order and build on each other: sign-in, tenants, accounts, the multi-tenant rules,
 * suspension, the nightly check, deletion.
 * <p>admin-console is the public, tenant-only tool (user decisions D1-D2, 2026-11-03): no HTTP route
 * creates, suspends or deletes a tenant or assigns its numbers. Those run in-process here, as the
 * service identities their future consumers will be ({@link ServiceIdentity#PROVISIONING} for billing's
 * {@code admin.provisioning.requests}, an {@link OpsActor} for parity-cc-tools' {@code admin.ops.requests});
 * the staff account the realm still has ({@code platform.admin}, parity-deploy's dev script) is only
 * signed in to prove that its token is refused.
 */
@SpringBootTest(classes = ParityAdminConsoleApplication.class, webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@TestMethodOrder(MethodOrderer.OrderAnnotation.class)
class ConsoleIT {

    private static final JsonMapper JSON = JsonMapper.builder().build();
    private static final String REDIRECT = Stack.CONSOLE_URL + "/";
    private static final String PASSWORD = "It-" + HexFormat.of().formatHex(new SecureRandom().generateSeed(12));
    private static final ServiceIdentity PROVISIONING = ServiceIdentity.PROVISIONING;
    private static final OpsActor OPS = new OpsActor("0d6f4c1e-8a2b-4e7f-9c3d-5b1a2e3f4a5b", "ops.it", "019a4a5e-7c3b-7d2e-9f10-00000000a001");
    private static final KcTestAdmin kc = new KcTestAdmin();
    private static final Map<String, String> tokens = new HashMap<>();
    private static final Map<String, String> userIds = new HashMap<>();

    @DynamicPropertySource
    static void properties(DynamicPropertyRegistry r) {
        Stack.properties(r);
    }

    @LocalServerPort
    int port;

    @Autowired
    TenantService tenants;

    @Autowired
    LocalAccounts accounts;

    @Autowired
    IdentityCheck identityCheck;

    private Api api() {
        return new Api(port);
    }

    /** The realm's staff account (platform organization, platform-admin): its token must be refused. */
    private static String staff() {
        return tokens.computeIfAbsent("platform", k ->
                Browser.login(Stack.issuer(), "admin-console", REDIRECT, "platform.admin", Stack.platformAdminPassword()));
    }

    private static String token(String username) {
        return tokens.computeIfAbsent(username, u -> Browser.login(Stack.issuer(), "admin-console", REDIRECT, u, PASSWORD));
    }

    private static ObjectNode obj() {
        return JSON.createObjectNode();
    }

    private static OpsActor ops(String opSuffix) {
        return new OpsActor(OPS.subject(), OPS.username(), "019a4a5e-7c3b-7d2e-9f10-00000000" + opSuffix);
    }

    // ------------------------------------------------------------------ step 0 / SAML step 3: the login

    /** D2: the realm's staff (the platform organization, platform-admin) gets nothing here. */
    @Test
    @Order(1)
    void aStaffTokenIsRefused() {
        String t = staff();
        JsonNode claims = Browser.claims(t);
        assertThat(claims.path("iss").asString()).isEqualTo(Stack.issuer());
        assertThat(claims.path("organization").get(0).asString()).isEqualTo("platform");
        assertThat(claims.path("realm_access").path("roles").toString()).contains("platform-admin");
        for (String path : List.of("/api/me", "/api/tenants/platform", "/api/audit")) {
            assertThat(api().get(t, path).status()).as(path).isEqualTo(401);
        }
        assertThat(api().get(null, "/api/config").status()).isEqualTo(200);
    }

    @Test
    @Order(2)
    void tokensWithoutTheRightIssuerOrClientAreRefused() {
        assertThat(api().get(null, "/api/me").status()).isEqualTo(401);
        assertThat(api().get("not.a.jwt", "/api/me").status()).isEqualTo(401);
        // Another realm on the same Keycloak, with the same client and claims: its issuer isn't ours.
        ObjectNode realm = obj().put("realm", "other").put("enabled", true);
        ObjectNode client = realm.putArray("clients").addObject().put("clientId", "admin-console").put("publicClient", true)
                .put("standardFlowEnabled", true).put("directAccessGrantsEnabled", false);
        client.putArray("redirectUris").add(REDIRECT);
        client.putObject("attributes").put("pkce.code.challenge.method", "S256");
        client.putArray("protocolMappers").addObject().put("name", "aud").put("protocol", "openid-connect")
                .put("protocolMapper", "oidc-audience-mapper").putObject("config")
                .put("included.client.audience", "admin-console").put("access.token.claim", "true");
        kc.post("/realms", realm);
        kc.post("/realms/other/roles", obj().put("name", "platform-admin"));
        kc.createUser("other", "intruder", PASSWORD, null, List.of("platform-admin"));
        String foreign = Browser.login(Stack.keycloakUrl() + "/realms/other", "admin-console", REDIRECT, "intruder", PASSWORD);
        assertThat(Browser.claims(foreign).path("iss").asString()).endsWith("/realms/other");
        assertThat(api().get(foreign, "/api/me").status()).isEqualTo(401);
    }

    // ------------------------------------------------------------------ step 9: tenants through parity-store

    @Test
    @Order(10)
    void provisioningCreatesTenantsWithTheirOrganizationAndDesktopClient() throws InterruptedException {
        for (TenantService.CreateTenant req : List.of(
                new TenantService.CreateTenant("acme", "Acme Ltd", "small", null, "onboarding"),
                new TenantService.CreateTenant("globex", "Globex GmbH", "mid", null, null),
                new TenantService.CreateTenant("initech", "Initech Group", "enterprise", null, null),
                new TenantService.CreateTenant("initech-de", "Initech Germany", null, "initech", null),
                new TenantService.CreateTenant("initech-uk", "Initech UK", null, "initech", null))) {
            Map<String, Object> created = tenants.create(PROVISIONING, req);
            @SuppressWarnings("unchecked")
            Map<String, Object> identity = (Map<String, Object>) created.get("identity");
            assertThat(identity.get("applied")).as(req.tenantId()).isEqualTo(true);
            assertThat(identity.get("organization")).as(req.tenantId()).isEqualTo(true);
            assertThat(created).as("no link to the internal tool").doesNotContainKey("routing_url");
        }
        assertThatThrownBy(() -> tenants.create(PROVISIONING, new TenantService.CreateTenant("platform", "x", null, null, null)))
                .isInstanceOf(ApiException.class).extracting(e -> ((ApiException) e).code()).isEqualTo(ApiException.Code.RESERVED_TENANT_ID);
        assertThatThrownBy(() -> tenants.create(PROVISIONING, new TenantService.CreateTenant("acme", "Again", null, null, null)))
                .isInstanceOf(BackendException.class).extracting(e -> ((BackendException) e).kind().status()).isEqualTo(409);

        // parity-rs places them (place_tenant, 2026-11-03): its saga lands the placement in parity-store.
        long until = System.nanoTime() + java.util.concurrent.TimeUnit.SECONDS.toNanos(30);
        while (tenants.get("acme").get("placement") == null || tenants.get("globex").get("placement") == null) {
            assertThat(System.nanoTime()).as("parity-rs placed acme and globex").isLessThan(until);
            Thread.sleep(200);
        }
        JsonNode acme = (JsonNode) tenants.get("acme").get("placement");
        assertThat(acme.path("cell").asString()).isEqualTo("eu1a");
        assertThat(acme.path("zone").asString()).isEqualTo("eu1a"); // parity-rs writes zone = cell
        assertThat(acme.path("deployment_unit").asString()).isEqualTo("bin-a"); // the live unit
        assertThat(tenants.get("initech").get("placement")).isNull();
        Map<String, Object> de = tenants.get("initech-de");
        assertThat(de.get("parent")).isEqualTo("initech");
        assertThat(de.get("tier")).isEqualTo("enterprise");

        // In Keycloak: the organization (alias = tenant id, no domains) and desktop-<tenant>, PKCE, every region.
        assertThat(kc.orgId("acme")).isNotNull();
        JsonNode client = kc.get("/realms/parity/clients?clientId=desktop-acme").get(0);
        assertThat(client.path("publicClient").asBoolean()).isTrue();
        assertThat(client.path("attributes").path("pkce.code.challenge.method").asString()).isEqualTo("S256");
        assertThat(client.path("redirectUris").toString()).contains("http://acme.eu1.localhost:18090/*", "http://acme.eu2.localhost:18090/*");
        assertThat(client.path("fullScopeAllowed").asBoolean()).isFalse();
    }

    @Test
    @Order(11)
    void provisioningAssignsNumbersAndSipDomainsThroughTheAdminTopic() {
        tenants.addNumber(PROVISIONING, "acme", "+15550100101", "bought");
        tenants.addNumber(PROVISIONING, "globex", "+15550100201", null);
        assertThatThrownBy(() -> tenants.addNumber(PROVISIONING, "globex", "+15550100101", null))
                .isInstanceOf(BackendException.class).extracting(e -> ((BackendException) e).rule()).isEqualTo("duplicate_number");
        tenants.addSipDomain(PROVISIONING, "acme", "acme.example", null);
        assertThat(tenants.numbers("acme", null, 100).path("numbers").get(0).path("number").asString()).isEqualTo("+15550100101");
        assertThat(tenants.sipDomains("acme", null, 100).path("sip_domains").toString()).contains("acme.example");
    }

    @Test
    @Order(20)
    void provisioningMakesTheFirstAdminsWhoMakeTheirTenantsAccounts() {
        for (String username : List.of("acme.admin", "globex.admin", "initech.admin", "initech-de.admin")) {
            String tenant = username.substring(0, username.indexOf('.'));
            Map<String, Object> a = accounts.create(PROVISIONING.actor(), tenant,
                    new LocalAccounts.NewAccount("admin", "Test", "Admin", null, List.of("tenant-admin")));
            assertThat(a.get("username")).isEqualTo(username);
            userIds.put(username, (String) a.get("id"));
            kc.password((String) a.get("id"), PASSWORD);
        }
        // The tenant's admin makes the rest, over the API.
        String acme = token("acme.admin");
        Map<String, List<String>> users = Map.of("acme.sup", List.of("supervisor"), "acme.agent", List.of("agent"));
        for (Map.Entry<String, List<String>> u : users.entrySet()) {
            ObjectNode body = obj().put("name", u.getKey().substring(u.getKey().indexOf('.') + 1)).put("first_name", "Test")
                    .put("last_name", "Person").put("tenant_id", "globex");
            u.getValue().forEach(body.putArray("roles")::add);
            Api.Answer a = api().post(acme, "/api/tenants/acme/users", body);
            assertThat(a.status()).as(u.getKey()).isEqualTo(201);
            assertThat(a.body().path("username").asString()).isEqualTo(u.getKey());
            userIds.put(u.getKey(), a.body().path("id").asString());
            kc.password(a.body().path("id").asString(), PASSWORD);
        }
        for (String role : List.of("platform-admin", "ops", "admin")) {
            ObjectNode bad = obj().put("name", "boss");
            bad.putArray("roles").add(role);
            assertThat(api().post(acme, "/api/tenants/acme/users", bad).code()).as(role).isEqualTo("role_not_allowed");
        }
        // Rule 1: the body's tenant_id changed nothing: acme's supervisor is acme's.
        JsonNode sup = kc.user("acme.sup");
        assertThat(sup.path("attributes").path("tenant_id").toString()).isEqualTo("[\"acme\"]");
        JsonNode claims = Browser.claims(token("acme.admin"));
        assertThat(claims.path("tenant_id").asString()).isEqualTo("acme");
        assertThat(claims.path("organization").toString()).isEqualTo("[\"acme\"]");
        Api.Answer me = api().get(token("acme.admin"), "/api/me");
        assertThat(me.body().path("roles").toString()).isEqualTo("[\"tenant-admin\"]");
        assertThat(me.body().has("platform")).as("no staff flag").isFalse();
    }

    @Test
    @Order(21)
    void aTenantAdminReachesTheirTenantAndTheirSubTenantsOnly() {
        String acme = token("acme.admin");
        Api.Answer missing = api().get(acme, "/api/tenants/nosuch");
        assertThat(missing.status()).isEqualTo(404);
        ((ObjectNode) missing.body()).remove("instance");
        for (String path : List.of("/api/tenants/globex", "/api/tenants/globex/numbers", "/api/tenants/globex/sip-domains",
                "/api/tenants/globex/users", "/api/audit?tenant=globex", "/api/tenants/initech-de")) {
            Api.Answer a = api().get(acme, path);
            assertThat(a.status()).as(path).isEqualTo(404);
            ((ObjectNode) a.body()).remove("instance"); // the request's own path
            assertThat(a.body()).as("the same body as a tenant that doesn't exist: " + path).isEqualTo(missing.body());
        }
        assertThat(api().post(acme, "/api/tenants/globex/users", obj().put("name", "x")).status()).isEqualTo(404);
        Api.Answer own = api().get(acme, "/api/tenants/acme");
        assertThat(own.status()).isEqualTo(200);
        assertThat(own.body().path("name").asString()).isEqualTo("Acme Ltd");
        assertThat(own.body().has("routing_url")).as("no link to the internal tool").isFalse();
        assertThat(api().get(acme, "/api/tenants/acme/numbers").body().path("numbers").get(0).path("number").asString())
                .isEqualTo("+15550100101");
        assertThat(api().get(acme, "/api/tenants/acme/sip-domains").body().path("sip_domains").toString()).contains("acme.example");

        String parent = token("initech.admin");
        List<String> subs = new ArrayList<>();
        api().get(parent, "/api/tenants/initech").body().path("sub_tenants").forEach(n -> subs.add(n.asString()));
        assertThat(subs).containsExactlyInAnyOrder("initech-de", "initech-uk");
        assertThat(api().get(parent, "/api/tenants/initech-de").status()).isEqualTo(200);
        assertThat(api().get(parent, "/api/tenants/initech-de/users").status()).isEqualTo(200);
        ObjectNode sub = obj().put("name", "lead");
        sub.putArray("roles").add("supervisor");
        assertThat(api().post(parent, "/api/tenants/initech-uk/users", sub).status()).isEqualTo(201);
        assertThat(api().get(parent, "/api/tenants/acme").status()).isEqualTo(404);
        assertThat(api().get(parent, "/api/tenants/globex/users").status()).isEqualTo(404);

        String child = token("initech-de.admin");
        assertThat(api().get(child, "/api/tenants/initech").status()).isEqualTo(404);
        assertThat(api().get(child, "/api/tenants/initech-uk").status()).isEqualTo(404);
        assertThat(api().get(child, "/api/tenants/initech-de").status()).isEqualTo(200);

        String supervisor = token("acme.sup");
        assertThat(api().get(supervisor, "/api/tenants/acme").status()).isEqualTo(200);
        assertThat(api().get(supervisor, "/api/tenants/acme/numbers").status()).isEqualTo(200);
        assertThat(api().get(supervisor, "/api/tenants/acme/users").status()).isEqualTo(403);
        assertThat(api().get(supervisor, "/api/audit").status()).isEqualTo(403);
        assertThat(api().get(token("acme.agent"), "/api/me").status()).as("agent only: no console role").isEqualTo(403);
    }

    @Test
    @Order(22)
    void numberDestinationsStayInTheirTenant() {
        String acme = token("acme.admin");
        ObjectNode d = obj().put("number", "+15550100101").put("kind", "queue").put("target", "sales").put("tenant_id", "globex");
        Api.Answer set = api().put(acme, "/api/tenants/acme/number-destinations", d);
        assertThat(set.status()).isEqualTo(200);
        assertThat(api().get(acme, "/api/tenants/acme/numbers").body().path("numbers").get(0).path("destination").path("target").asString())
                .isEqualTo("sales");
        // globex's number, through acme's path: not acme's, so not found.
        Api.Answer other = api().put(acme, "/api/tenants/acme/number-destinations", obj().put("number", "+15550100201").put("kind", "queue").put("target", "x"));
        assertThat(other.status()).isEqualTo(404);
        assertThat(api().get(token("globex.admin"), "/api/tenants/globex/numbers").body().path("numbers").get(0).path("destination").isNull()).isTrue();
        assertThat(api().put(token("acme.sup"), "/api/tenants/acme/number-destinations", d).status()).isEqualTo(403);
    }

    @Test
    @Order(23)
    void tokensFromAnotherClientOrWithMismatchedClaimsAreRefused() {
        // Rule 9: the desktop client names the tenant; its tokens aren't the console's.
        String desktop = Browser.login(Stack.issuer(), "desktop-acme", "http://acme.eu1.localhost:18090/", "acme.agent", PASSWORD);
        assertThat(Browser.claims(desktop).path("azp").asString()).isEqualTo("desktop-acme");
        assertThat(Browser.claims(desktop).path("aud").toString()).contains("parity-gateway");
        assertThat(api().get(desktop, "/api/me").status()).isEqualTo(401);

        // A tenant_id that isn't the account's organization (planted straight in Keycloak).
        String spy = kc.createUser("parity", "acme.spy", PASSWORD, "acme", List.of("tenant-admin"));
        kc.addMember(kc.orgId("globex"), spy);
        String planted = Browser.login(Stack.issuer(), "admin-console", REDIRECT, "acme.spy", PASSWORD);
        assertThat(Browser.claims(planted).path("organization").toString()).isEqualTo("[\"globex\"]");
        assertThat(api().get(planted, "/api/tenants/acme").status()).isEqualTo(401);
        // F9: listed by neither tenant: acme's tenant_id, globex's organization, so it's nobody's.
        for (String[] admin : new String[][] {{"acme.admin", "acme"}, {"globex.admin", "globex"}}) {
            JsonNode listed = api().get(token(admin[0]), "/api/tenants/" + admin[1] + "/users").body().path("users");
            listed.forEach(u -> assertThat(u.path("username").asString()).as(admin[1]).isNotEqualTo("acme.spy"));
            assertThat(listed.size()).as(admin[1]).isPositive();
        }
        assertThat(api().post(token("acme.admin"), "/api/tenants/acme/users/" + spy + "/disable", obj()).status()).isEqualTo(404);

        // D2: platform-admin planted on a tenant's account (in its own organization): refused.
        String rogue = kc.createUser("parity", "acme.rogue", PASSWORD, "acme", List.of("platform-admin", "tenant-admin"));
        kc.addMember(kc.orgId("acme"), rogue);
        String rogueToken = Browser.login(Stack.issuer(), "admin-console", REDIRECT, "acme.rogue", PASSWORD);
        assertThat(Browser.claims(rogueToken).path("organization").toString()).isEqualTo("[\"acme\"]");
        for (String path : List.of("/api/me", "/api/tenants/acme", "/api/tenants/acme/users", "/api/audit")) {
            assertThat(api().get(rogueToken, path).status()).as(path).isEqualTo(401);
        }

        // No role: no access.
        String bare = kc.createUser("parity", "acme.bare", PASSWORD, "acme", List.of());
        kc.addMember(kc.orgId("acme"), bare);
        String bareToken = Browser.login(Stack.issuer(), "admin-console", REDIRECT, "acme.bare", PASSWORD);
        assertThat(api().get(bareToken, "/api/me").status()).isEqualTo(403);
    }

    @Test
    @Order(24)
    void everyKafkaRequestCarriesItsTenantAsKeyAndHeader() {
        int checked = 0;
        for (String topic : List.of("tenant.store.admin.requests", "tenant.store.requests")) {
            for (ConsumerRecord<String, String> r : readAll(topic)) {
                JsonNode body = JSON.readTree(r.value());
                if (!body.path("reply_to").asString("").equals("replies.admin-console")) {
                    continue;
                }
                checked++;
                assertThat(header(r, "schema_version")).isEqualTo("1");
                String cmd = body.path("cmd").asString();
                String named = body.has("tenant_id") ? body.path("tenant_id").asString() : body.has("parent") ? body.path("parent").asString() : null;
                String header = header(r, "tenant_id");
                if (named != null) {
                    assertThat(header).as(cmd).isEqualTo(named);
                }
                if (header != null) {
                    // The tenant the command acts on (for lookup_number: the tenant whose page asked) is key and header.
                    assertThat(r.key()).as(cmd).isEqualTo(header);
                } else {
                    assertThat(cmd).as("only the nightly check's list names no tenant").isEqualTo("list_tenants");
                    assertThat(r.key()).isEqualTo(body.path("id").asString());
                }
                if (topic.equals("tenant.store.requests")) {
                    assertThat(body.path("cmd").asString()).as("reads only on the read topic")
                            .isIn("get_tenant", "list_tenants", "list_numbers", "list_sip_domains", "lookup_number", "get_placement");
                }
            }
        }
        assertThat(checked).isGreaterThan(20);
    }

    @Test
    @Order(25)
    void everyChangeHasTwoAuditRowsAndTenantsSeeOnlyTheirOwn() {
        JsonNode rows = api().get(token("acme.admin"), "/api/audit?action=tenant.create").body().path("rows");
        // The first create (ok) and the second (refused: the tenant exists), two rows each.
        assertThat(rows.size()).isEqualTo(4);
        Map<String, List<String>> byRequest = new HashMap<>();
        String requestId = null;
        for (JsonNode r : rows) {
            byRequest.computeIfAbsent(r.path("request_id").asString(), k -> new ArrayList<>()).add(r.path("phase").asString());
            assertThat(r.path("actor").asString()).as("a service identity, never a person").isEqualTo("system:provisioning");
            if ("ok".equals(r.path("outcome").asString(""))) {
                requestId = r.path("request_id").asString();
            }
        }
        byRequest.values().forEach(phases -> assertThat(phases).containsExactlyInAnyOrder("requested", "answered"));
        assertThat(requestId).isNotNull();
        final String okRequest = requestId;
        assertThat(readAll("tenant.store.admin.requests").stream().anyMatch(r -> r.value().contains(okRequest)))
                .as("the audit row names the Kafka request").isTrue();
        JsonNode mine = api().get(token("acme.admin"), "/api/audit").body().path("rows");
        assertThat(mine.size()).isGreaterThan(0);
        mine.forEach(r -> assertThat(r.path("tenant_id").asString()).isEqualTo("acme"));
        JsonNode parentView = api().get(token("initech.admin"), "/api/audit?tenant=initech-uk").body().path("rows");
        assertThat(parentView.size()).isGreaterThan(0);
        parentView.forEach(r -> assertThat(r.path("tenant_id").asString()).isEqualTo("initech-uk"));
    }

    /**
     * The coordinator's D2 test: a tenant-realm token (acme's tenant admin and supervisor) reaches no other
     * tenant (globex: its tenant, numbers, SIP domains, users, number destinations, audit: 403 or 404,
     * never its data, and nothing changes) and no platform-wide data or action (the removed staff routes:
     * 403, 404 or 405, never 2xx or 500); the staff token is refused (401).
     */
    @Test
    @Order(26)
    void aTenantRealmTokenReachesNoOtherTenantAndNoPlatformWideData() {
        String globexAdmin = userIds.get("globex.admin");
        List<String> globexData = List.of("Globex GmbH", "+15550100201", "globex.admin", globexAdmin);
        for (String who : List.of("acme.admin", "acme.sup")) {
            String t = token(who);
            // Another tenant's reads: refused, and nothing of it in the answer.
            for (String path : List.of("/api/tenants/globex", "/api/tenants/globex/numbers", "/api/tenants/globex/sip-domains",
                    "/api/tenants/globex/users", "/api/tenants/globex/users?first=0&max=100", "/api/audit?tenant=globex",
                    "/api/audit?tenant=globex&action=tenant.create", "/api/tenants/initech", "/api/tenants/initech-de/users")) {
                Api.Answer a = api().get(t, path);
                assertThat(a.status()).as(who + " GET " + path).isIn(403, 404);
                globexData.forEach(x -> assertThat(answered(a)).as(who + " GET " + path).doesNotContain(x));
            }
            // Another tenant's writes: refused, through its path or through the caller's own.
            ObjectNode dest = obj().put("number", "+15550100201").put("kind", "queue").put("target", "stolen");
            ObjectNode user = obj().put("name", "mole");
            user.putArray("roles").add("tenant-admin");
            for (Object[] w : new Object[][] {
                    {"PUT", "/api/tenants/globex/number-destinations", dest},
                    {"PUT", "/api/tenants/acme/number-destinations", dest},
                    {"POST", "/api/tenants/globex/users", user},
                    {"POST", "/api/tenants/globex/users/" + globexAdmin + "/disable", obj()},
                    {"POST", "/api/tenants/globex/users/" + globexAdmin + "/enable", obj()},
                    {"POST", "/api/tenants/acme/users/" + globexAdmin + "/disable", obj()}}) {
                Api.Answer a = api().send(t, (String) w[0], (String) w[1], w[2]);
                assertThat(a.status()).as(who + " " + w[0] + " " + w[1]).isIn(403, 404);
                globexData.forEach(x -> assertThat(answered(a)).as(who + " " + w[1]).doesNotContain(x));
            }
            // The platform-wide routes are gone (D2): every tenant, create, delete, suspend, numbers, domains, staff jobs.
            for (Object[] w : new Object[][] {
                    {"GET", "/api/tenants", null}, {"GET", "/api/tenants?limit=500", null},
                    {"POST", "/api/tenants", obj().put("tenant_id", "evil").put("name", "Evil").put("tier", "small")},
                    {"DELETE", "/api/tenants/globex?reason=closing&confirm=globex", null},
                    {"DELETE", "/api/tenants/acme?reason=closing&confirm=acme", null},
                    {"POST", "/api/tenants/globex/suspend", obj().put("reason", "x").put("confirm", "globex")},
                    {"POST", "/api/tenants/acme/suspend", obj().put("reason", "x").put("confirm", "acme")},
                    {"POST", "/api/tenants/acme/unsuspend", obj().put("reason", "x")},
                    {"POST", "/api/tenants/acme/numbers", obj().put("number", "+15550100109").put("reason", "x")},
                    {"POST", "/api/tenants/acme/numbers/remove", obj().put("number", "+15550100101").put("reason", "x")},
                    {"POST", "/api/tenants/acme/sip-domains", obj().put("domain", "evil.example").put("reason", "x")},
                    {"DELETE", "/api/tenants/acme/sip-domains/acme.example?reason=x", null},
                    {"POST", "/api/platform/identity-check", obj()}, {"GET", "/api/platform/tenants", null},
                    {"PUT", "/api/tenants/globex/placement", obj().put("reason", "x")}}) {
                Api.Answer a = api().send(t, (String) w[0], (String) w[1], w[2]);
                assertThat(a.status()).as(who + " " + w[0] + " " + w[1]).isIn(403, 404, 405);
                globexData.forEach(x -> assertThat(answered(a)).as(who + " " + w[1]).doesNotContain(x));
            }
            // No every-tenant audit: without a tenant it is the caller's own (or 403 for a supervisor).
            Api.Answer all = api().get(t, "/api/audit?limit=200");
            if (who.equals("acme.admin")) {
                assertThat(all.status()).isEqualTo(200);
                all.body().path("rows").forEach(r -> assertThat(r.path("tenant_id").asString()).isEqualTo("acme"));
            } else {
                assertThat(all.status()).isEqualTo(403);
            }
            assertThat(api().get(t, "/api/audit?tenant=").status()).isIn(403, 404);
        }
        // Nothing changed: no tenant made, globex's account and number untouched, acme's number and domain kept.
        assertThatThrownBy(() -> tenants.get("evil")).isInstanceOf(BackendException.class)
                .extracting(e -> ((BackendException) e).kind()).isEqualTo(BackendException.Kind.NOT_FOUND);
        assertThat(kc.user("globex.admin").path("enabled").asBoolean()).isTrue();
        assertThat(kc.user("globex.mole")).isNull();
        assertThat(tenants.numbers("globex", null, 100).path("numbers").get(0).path("destination").isNull()).isTrue();
        assertThat(tenants.numbers("acme", null, 100).path("numbers").size()).isEqualTo(1);
        assertThat(tenants.sipDomains("acme", null, 100).path("sip_domains").toString()).contains("acme.example").doesNotContain("evil");
        assertThat(((Map<?, ?>) tenants.get("acme").get("identity")).get("state")).isEqualTo("active");
        // The staff token, now that tenants exist: still refused everywhere.
        for (String path : List.of("/api/tenants/acme", "/api/tenants/globex/users", "/api/audit?tenant=acme", "/api/me")) {
            assertThat(api().get(staff(), path).status()).as("staff GET " + path).isEqualTo(401);
        }
    }

    // ------------------------------------------------------------------ SAML step 4: suspend, check, delete

    /**
     * Suspension is staff's, through parity-cc-tools (no HTTP route here; the {@code admin.ops.requests}
     * consumer is the next slice): called in-process as that consumer will, with an ops actor.
     */
    @Test
    @Order(30)
    void suspendingATenantBlocksItsLoginsAndLiftingItRestoresOnlyThose() {
        // An account the tenant's admin disabled before: it stays disabled after the suspension is lifted.
        assertThat(api().post(token("acme.admin"), "/api/tenants/acme/users/" + userIds.get("acme.sup") + "/disable", obj()).status())
                .isEqualTo(200);
        Map<String, Object> s = tenants.setSuspended(ops("a101"), "acme", true, "unpaid");
        @SuppressWarnings("unchecked")
        Map<String, Object> identity = (Map<String, Object>) s.get("identity");
        assertThat(identity.get("state")).isEqualTo("suspended");
        assertThat(identity.get("applied")).isEqualTo(true);
        assertThat(kc.get("/realms/parity/organizations/" + kc.orgId("acme")).path("enabled").asBoolean()).isFalse();
        assertThatThrownBy(() -> Browser.login(Stack.issuer(), "admin-console", REDIRECT, "acme.admin", PASSWORD)).isInstanceOf(Browser.Refused.class);
        assertThatThrownBy(() -> accounts.create(PROVISIONING.actor(), "acme", new LocalAccounts.NewAccount("late", null, null, null, List.of("agent"))))
                .isInstanceOf(ApiException.class).extracting(e -> ((ApiException) e).code()).isEqualTo(ApiException.Code.TENANT_SUSPENDED);
        // Decision 2026-10-31 (AC-007): a token issued before the suspension is refused from the next request.
        String oldToken = token("acme.admin");
        for (String path : List.of("/api/me", "/api/tenants/acme", "/api/tenants/acme/users", "/api/audit")) {
            Api.Answer a = api().get(oldToken, path);
            assertThat(a.status()).as(path).isEqualTo(403);
            assertThat(a.code()).as(path).isEqualTo("tenant_suspended");
        }
        assertThat(api().post(oldToken, "/api/tenants/acme/users/" + userIds.get("acme.agent") + "/disable", obj()).status()).isEqualTo(403);
        // A suspended sub-tenant is refused to its parent's admin too; the parent's own tenant still works.
        tenants.setSuspended(ops("a102"), "initech-uk", true, "test");
        assertThat(api().get(token("initech.admin"), "/api/tenants/initech-uk").code()).isEqualTo("tenant_suspended");
        assertThat(api().get(token("initech.admin"), "/api/tenants/initech").status()).isEqualTo(200);
        tenants.setSuspended(ops("a103"), "initech-uk", false, "test");

        tenants.setSuspended(ops("a104"), "acme", false, "paid");
        assertThat(Browser.login(Stack.issuer(), "admin-console", REDIRECT, "acme.admin", PASSWORD)).isNotBlank();
        assertThat(kc.user("acme.sup").path("enabled").asBoolean()).isFalse();
        assertThat(kc.user("acme.agent").path("enabled").asBoolean()).isTrue();
        assertThat(api().get(oldToken, "/api/tenants/acme").status()).as("lifted: the same token works again").isEqualTo(200);
        // Ruling 2: the rows name the ops identity and its op_id (parity-cc-tools' audit joins on it).
        JsonNode rows = api().get(oldToken, "/api/audit?action=tenant.suspend").body().path("rows");
        assertThat(rows.size()).isEqualTo(2);
        rows.forEach(r -> {
            assertThat(r.path("actor").asString()).isEqualTo("ops:" + OPS.subject());
            assertThat(r.path("actor_roles").toString()).isEqualTo("[\"ops\"]");
            assertThat(r.path("request_id").asString()).isEqualTo("ops:019a4a5e-7c3b-7d2e-9f10-00000000a101");
        });
    }

    @Test
    @Order(40)
    void theNightlyCheckDisablesMismatchedAndStaffAccountsAndRepairsDrift() throws Exception {
        // Plant a mismatch: acme's agent now says globex, but stays in acme's organization.
        ObjectNode agent = (ObjectNode) kc.user("acme.agent");
        ((ObjectNode) agent.path("attributes")).putArray("tenant_id").add("globex");
        kc.put("/realms/parity/users/" + agent.path("id").asString(), agent);
        // Drift: globex's desktop client deleted behind admin-api's back.
        kc.delete("/realms/parity/clients/" + kc.get("/realms/parity/clients?clientId=desktop-globex").get(0).path("id").asString());
        // A parity-store tenant with no identity (a create that died between parity-store and Postgres).
        try (KafkaProducer<String, String> p = producer()) {
            ObjectNode put = obj().put("schema_version", 1).put("cmd", "put_tenant").put("id", "it:hooli-1")
                    .put("reply_to", "replies.admin-console").put("tenant_id", "hooli").put("name", "Hooli").put("tier", "small");
            p.send(new ProducerRecord<>("tenant.store.admin.requests", "hooli", put.toString())).get();
        }
        long deadline = System.nanoTime() + Duration.ofSeconds(20).toNanos();
        while (!storeHas("hooli") && System.nanoTime() < deadline) {
            Thread.sleep(200);
        }
        IdentityCheck.Summary run = identityCheck.run();
        // acme.agent, acme.spy (mismatches), acme.rogue (platform-admin), platform.admin (the staff organization: D2).
        assertThat(run.accountsDisabled()).isGreaterThanOrEqualTo(4);
        assertThat(run.identitiesCreated()).isEqualTo(1);
        assertThat(run.repaired()).isGreaterThanOrEqualTo(1);

        assertThat(kc.user("acme.agent").path("enabled").asBoolean()).isFalse();
        assertThat(kc.user("acme.spy").path("enabled").asBoolean()).isFalse();
        assertThat(kc.user("acme.rogue").path("enabled").asBoolean()).isFalse();
        assertThat(kc.user("platform.admin").path("enabled").asBoolean()).as("D2: no staff in the tenant realm").isFalse();
        assertThat(kc.user("acme.admin").path("enabled").asBoolean()).as("a correct account is left alone").isTrue();
        assertThat(kc.get("/realms/parity/clients?clientId=desktop-globex").size()).isEqualTo(1);
        assertThat(kc.orgId("hooli")).isNotNull();
        try (Connection c = Stack.connect(true); Statement st = c.createStatement();
                ResultSet rs = st.executeQuery("SELECT set_config('app.platform', 'on', false), count(*), min(actor), max(actor), count(*) FILTER (WHERE reason = 'reserved_tenant_id'), "
                        + "count(*) FILTER (WHERE reason = 'platform_admin_role') FROM audit_log WHERE action = 'identity.account_disabled' "
                        + "AND phase = 'requested'")) {
            rs.next();
            assertThat(rs.getInt(2)).isGreaterThanOrEqualTo(4);
            assertThat(rs.getString(3)).isEqualTo("system:identity-check");
            assertThat(rs.getString(4)).isEqualTo("system:identity-check");
            assertThat(rs.getInt(5)).as("platform.admin").isEqualTo(1);
            assertThat(rs.getInt(6)).as("acme.rogue").isEqualTo(1);
        }
        // A mismatch's row is no tenant's: globex (named by acme.agent's planted tenant_id) and acme
        // (named by acme.spy's, which sits in globex's organization) see neither row. acme.rogue is
        // wholly acme's (its one organization is acme), so acme sees its row.
        JsonNode globexSees = api().get(token("globex.admin"), "/api/audit?action=identity.account_disabled").body().path("rows");
        assertThat(globexSees.size()).isZero();
        JsonNode acmeSees = api().get(token("acme.admin"), "/api/audit?action=identity.account_disabled").body().path("rows");
        assertThat(acmeSees.size()).isEqualTo(2); // requested + answered
        acmeSees.forEach(r -> assertThat(r.path("target").asString()).isEqualTo(kc.user("acme.rogue").path("id").asString()));
    }

    /** Deletion is billing's deprovision saga's, through provisioning (coordinator ruling 3): in-process here. */
    @Test
    @Order(50)
    void deletingATenantRemovesItsAccountsClientAndOrganization() {
        String globexToken = Browser.login(Stack.issuer(), "admin-console", REDIRECT, "globex.admin", PASSWORD);
        assertThatThrownBy(() -> tenants.delete(PROVISIONING, "initech", "closing")).isInstanceOf(BackendException.class)
                .extracting(e -> ((BackendException) e).rule()).isEqualTo("has_sub_tenants");
        tenants.delete(PROVISIONING, "globex", "closing");
        assertThat(storeHas("globex")).isFalse();
        assertThat(kc.orgId("globex")).isNull();
        assertThat(kc.get("/realms/parity/clients?clientId=desktop-globex").size()).isZero();
        assertThat(kc.user("globex.admin")).isNull();
        assertThat(kc.user("acme.admin")).isNotNull();
        // Its admin's token outlives the account by minutes: refused from the next request.
        Api.Answer late = api().get(globexToken, "/api/tenants/globex");
        assertThat(late.status()).isEqualTo(403);
        assertThat(late.code()).isEqualTo("tenant_deleted");
        // MF-3 (decision 2026-10-31): a deleted tenant's id is retired; nothing reaches parity-store.
        long before = readAll("tenant.store.admin.requests").stream().filter(r -> "globex".equals(r.key())).count();
        assertThatThrownBy(() -> tenants.create(PROVISIONING, new TenantService.CreateTenant("globex", "Globex again", "small", null, null)))
                .isInstanceOf(ApiException.class).extracting(e -> ((ApiException) e).code()).isEqualTo(ApiException.Code.TENANT_ID_RETIRED);
        assertThat(storeHas("globex")).isFalse();
        assertThat(readAll("tenant.store.admin.requests").stream().filter(r -> "globex".equals(r.key())).count()).isEqualTo(before);
        assertThat(kc.orgId("globex")).isNull();
    }

    @Test
    @Order(3)
    void theRealmTakesNoPasswordGrantNoAccountRolesAndLogsNoEvents() throws Exception {
        // F11: the realm's admin-cli refuses the password grant (a real account's password, even).
        String form = "grant_type=password&client_id=admin-cli&username=platform.admin&password="
                + java.net.URLEncoder.encode(Stack.platformAdminPassword(), StandardCharsets.UTF_8);
        java.net.http.HttpResponse<String> r = java.net.http.HttpClient.newHttpClient().send(java.net.http.HttpRequest
                .newBuilder(java.net.URI.create(Stack.issuer() + "/protocol/openid-connect/token"))
                .header("Content-Type", "application/x-www-form-urlencoded")
                .POST(java.net.http.HttpRequest.BodyPublishers.ofString(form)).build(), java.net.http.HttpResponse.BodyHandlers.ofString());
        assertThat(r.statusCode()).isEqualTo(400);
        assertThat(JSON.readTree(r.body()).path("error").asString()).isEqualTo("unauthorized_client");
        // S2: no account-console role by default; F12: no event listener (usernames and IPs on stdout).
        List<String> defaults = new ArrayList<>();
        kc.get("/realms/parity/roles/default-roles-parity/composites").forEach(x -> defaults.add(x.path("name").asString()));
        assertThat(defaults).containsExactlyInAnyOrder("offline_access", "uma_authorization");
        assertThat(kc.get("/realms/parity").path("eventsListeners").size()).isZero();
        assertThat(kc.get("/realms/parity").path("eventsEnabled").asBoolean()).isTrue();
        // MF-1: the realm file brought no person; the platform admin is dev-platform-admin.py's.
        List<String> members = new ArrayList<>();
        kc.get("/realms/parity/organizations/" + kc.orgId("platform") + "/members").forEach(m -> members.add(m.path("username").asString()));
        assertThat(members).containsExactly("platform.admin");
    }

    // ------------------------------------------------------------------ helpers

    /** An answer's body without {@code instance} (the caller's own request path, echoed back). */
    private static String answered(Api.Answer a) {
        JsonNode body = a.body().deepCopy();
        if (body instanceof ObjectNode o) {
            o.remove("instance");
        }
        return body.toString();
    }

    private boolean storeHas(String tenant) {
        try {
            tenants.get(tenant);
            return true;
        } catch (BackendException e) {
            if (e.kind() == BackendException.Kind.NOT_FOUND) {
                return false;
            }
            throw e;
        }
    }

    private static String header(ConsumerRecord<String, String> r, String name) {
        Header h = r.headers().lastHeader(name);
        return h == null ? null : new String(h.value(), StandardCharsets.UTF_8);
    }

    private static List<ConsumerRecord<String, String>> readAll(String topic) {
        Properties p = new Properties();
        p.put("bootstrap.servers", Stack.kafka());
        try (KafkaConsumer<String, String> c = new KafkaConsumer<>(p, new StringDeserializer(), new StringDeserializer())) {
            List<TopicPartition> parts = c.partitionsFor(topic).stream().map(i -> new TopicPartition(topic, i.partition())).toList();
            c.assign(parts);
            c.seekToBeginning(parts);
            Map<TopicPartition, Long> end = c.endOffsets(parts);
            List<ConsumerRecord<String, String>> out = new ArrayList<>();
            long deadline = System.nanoTime() + Duration.ofSeconds(20).toNanos();
            while (parts.stream().anyMatch(tp -> c.position(tp) < end.get(tp)) && System.nanoTime() < deadline) {
                c.poll(Duration.ofMillis(200)).forEach(out::add);
            }
            return out;
        }
    }

    private static KafkaProducer<String, String> producer() {
        Properties p = new Properties();
        p.put("bootstrap.servers", Stack.kafka());
        return new KafkaProducer<>(p, new StringSerializer(), new StringSerializer());
    }
}
