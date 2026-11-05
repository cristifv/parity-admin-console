package parity.adminconsole.routing;

import java.security.SecureRandom;
import java.util.UUID;
import org.springframework.stereotype.Component;
import parity.adminconsole.backend.BackendClient;
import parity.adminconsole.config.AdminConsoleProperties;
import parity.adminconsole.contracts.Schemas;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.json.JsonMapper;
import tools.jackson.databind.node.ObjectNode;

/**
 * parity-rs's onboarding API (parity-contracts 0.16.0, CONVENTIONS "Tenant routing API"): the console
 * asks parity-rs to place a new tenant ({@code place_tenant} with a hint) on its zone's onboarding
 * topic, which only admin-console may write. parity-rs decides the zone, unit, media track and
 * failover zone; the console never writes a placement itself (2026-11-03: placement editing is
 * parity-cc-tools'). The answer is {@code accepted} at once; the placement lands in parity-store
 * when parity-rs's saga finishes.
 */
@Component
public class RoutingClient {

    public static final String BACKEND = "parity-rs";
    private static final JsonMapper JSON = JsonMapper.builder().build();
    private static final SecureRandom RANDOM = new SecureRandom();

    private final BackendClient backend;
    private final AdminConsoleProperties.Kafka kafka;
    private final AdminConsoleProperties.Tenants tenants;

    public RoutingClient(BackendClient backend, AdminConsoleProperties properties) {
        this.backend = backend;
        this.kafka = properties.kafka();
        this.tenants = properties.tenants();
    }

    /** A UUIDv7 (the op_id and saga_id of one onboarding). */
    public static String uuid7() {
        long ms = System.currentTimeMillis();
        long msb = (ms & 0xFFFFFFFFFFFFL) << 16 | 0x7000L | (RANDOM.nextInt() & 0x0FFFL);
        long lsb = 0x8000000000000000L | (RANDOM.nextLong() & 0x3FFFFFFFFFFFFFFFL);
        return new UUID(msb, lsb).toString();
    }

    /**
     * The place_tenant command for a new tenant, checked against parity-rs's schema before any audit row.
     * The actor is this service: a tenant is created by billing's provisioning, never by a person here (D2).
     */
    public ObjectNode placeCommand(String tenantId, String reason, String sagaId, String opId) {
        ObjectNode c = JSON.createObjectNode();
        c.put("cmd", "place_tenant").put("tenant_id", tenantId).put("saga_id", sagaId).put("op_id", opId);
        c.putObject("actor").put("system", "parity-admin-console");
        c.put("reason", reason == null || reason.length() < 10 ? "a new tenant provisioned by admin-console" : reason);
        ObjectNode hint = c.putObject("hint").put("residency", tenants.residency());
        if (tenants.preferredZone() != null && !tenants.preferredZone().isBlank()) {
            hint.put("preferred_zone", tenants.preferredZone());
        }
        return c;
    }

    public void validate(ObjectNode command, String requestId) {
        backend.validate(Schemas.ROUTING_REQUESTS, command, requestId);
    }

    /** Sends place_tenant; the result is {@code {accepted, saga_id, placement, changed}}. */
    public JsonNode place(String tenantId, ObjectNode command, String requestId) {
        return backend.request(BACKEND, kafka.routingOnboardingTopic(), Schemas.ROUTING_REQUESTS, tenantId, command, requestId);
    }

    public String newRequestId() {
        return backend.newRequestId();
    }
}
