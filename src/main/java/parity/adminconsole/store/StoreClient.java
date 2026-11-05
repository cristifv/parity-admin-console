package parity.adminconsole.store;

import java.util.Set;
import org.springframework.stereotype.Component;
import parity.adminconsole.backend.BackendClient;
import parity.adminconsole.config.AdminConsoleProperties;
import parity.adminconsole.contracts.Schemas;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.json.JsonMapper;
import tools.jackson.databind.node.ObjectNode;

/**
 * parity-store's Kafka API (parity-contracts CONVENTIONS.md "parity-store API"). Reads go to
 * {@code tenant.store.requests}; writes ({@code x-admin} in the schema) only to
 * {@code tenant.store.admin.requests}, which only admin-console may write (Kafka ACL). A command sent
 * to the wrong topic is a bug: refused here before anything is sent.
 */
@Component
public class StoreClient {

    public static final String BACKEND = "parity-store";
    private static final JsonMapper JSON = JsonMapper.builder().build();

    private final BackendClient backend;
    private final AdminConsoleProperties.Kafka kafka;
    private final Set<String> writes;

    public StoreClient(BackendClient backend, AdminConsoleProperties properties, Schemas schemas) {
        this.backend = backend;
        this.kafka = properties.kafka();
        this.writes = schemas.commands(Schemas.STORE_REQUESTS, "x-admin");
        if (writes.isEmpty()) {
            throw new IllegalStateException("the store schema marks no write command");
        }
    }

    /** A command body: {@code {"cmd": name}}. */
    public static ObjectNode command(String name) {
        ObjectNode n = JSON.createObjectNode();
        n.put("cmd", name);
        return n;
    }

    /** A read command, on the read topic. */
    public JsonNode read(String tenantId, ObjectNode body) {
        String cmd = body.path("cmd").asString("");
        if (writes.contains(cmd)) {
            throw new IllegalArgumentException("a write command can't go to the read topic");
        }
        return backend.request(BACKEND, kafka.storeReadTopic(), Schemas.STORE_REQUESTS, tenantId, body,
                backend.newRequestId());
    }

    /** A write command, on the admin topic, with the id its audit row already names. */
    public JsonNode write(String tenantId, ObjectNode body, String requestId) {
        String cmd = body.path("cmd").asString("");
        if (!writes.contains(cmd)) {
            throw new IllegalArgumentException("only write commands go to the admin topic");
        }
        return backend.request(BACKEND, kafka.storeAdminTopic(), Schemas.STORE_REQUESTS, tenantId, body, requestId);
    }

    /** A write command checked against parity-store's schema, before its audit row (review F8). */
    public void validateWrite(ObjectNode body, String requestId) {
        if (!writes.contains(body.path("cmd").asString(""))) {
            throw new IllegalArgumentException("only write commands go to the admin topic");
        }
        backend.validate(Schemas.STORE_REQUESTS, body, requestId);
    }

    public String newRequestId() {
        return backend.newRequestId();
    }

    /** {@code get_tenant}: the tenant record ({@code result.tenant}); 404 as {@code BackendException}. */
    public JsonNode getTenant(String tenantId) {
        ObjectNode c = command("get_tenant");
        c.put("tenant_id", tenantId);
        return read(tenantId, c).path("tenant");
    }

    /** {@code list_tenants}: a page ({@code tenants}, {@code next_after}). */
    public JsonNode listTenants(String after, int limit, String parent) {
        ObjectNode c = command("list_tenants");
        if (after != null) {
            c.put("after", after);
        }
        c.put("limit", limit);
        if (parent != null) {
            c.put("parent", parent);
        }
        return read(parent, c);
    }

    /** A text field, or null when absent or JSON null. */
    public static String text(JsonNode node, String field) {
        JsonNode v = node.get(field);
        return v == null || v.isNull() ? null : v.asString();
    }
}
