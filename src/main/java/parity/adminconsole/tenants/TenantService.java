package parity.adminconsole.tenants;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.function.Supplier;
import java.util.regex.Pattern;
import org.springframework.stereotype.Service;
import parity.adminconsole.audit.AuditLog;
import parity.adminconsole.backend.BackendException;
import parity.adminconsole.identity.IdentityApplier;
import parity.adminconsole.identity.TenantIdentities;
import parity.adminconsole.security.Caller;
import parity.adminconsole.security.ReservedTenantIds;
import parity.adminconsole.security.TenantNotFoundException;
import parity.adminconsole.store.StoreClient;
import parity.adminconsole.web.ApiException;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.json.JsonMapper;
import tools.jackson.databind.node.ObjectNode;

/**
 * Tenants (console step 9): parity-store holds the tenant, its tier and parent, placement, numbers and
 * SIP domains, written only on its admin topic; the console holds the tenant's identity state
 * ({@link TenantIdentities}, applied to Keycloak by {@link IdentityApplier}) and each number's
 * destination. Every change: the command checked against its schema, the {@code requested} audit row
 * (if it can't be written, nothing is sent), the command, then the {@code answered} row, on every path,
 * exceptions included (review F8).
 * <p>Two kinds of caller (user decisions D1-D2, 2026-11-03):
 * <ul>
 *   <li>a tenant's person through the HTTP API, for their own tenant (reads, number destinations); the
 *       scope checks are the controller's;</li>
 *   <li>with no HTTP route: billing's provisioning ({@link ServiceIdentity#PROVISIONING}: create,
 *       delete at the end of its deprovision saga, numbers and SIP domains) and staff through
 *       parity-cc-tools ({@link OpsActor}: suspend, lift a suspension). Their consumers
 *       ({@code admin.provisioning.requests}, {@code admin.ops.requests}) are the next slices; until
 *       then only the tests call these.</li>
 * </ul>
 */
@Service
public class TenantService {

    private static final JsonMapper JSON = JsonMapper.builder().build();
    private static final Pattern TENANT = Pattern.compile("^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$");

    private final StoreClient store;
    private final parity.adminconsole.routing.RoutingClient routing;
    private final AuditLog audit;
    private final TenantIdentities identities;
    private final IdentityApplier applier;
    private final NumberDestinations destinations;
    private final ReservedTenantIds reserved;

    public TenantService(StoreClient store, parity.adminconsole.routing.RoutingClient routing, AuditLog audit,
            TenantIdentities identities, IdentityApplier applier, NumberDestinations destinations,
            ReservedTenantIds reserved) {
        this.routing = routing;
        this.store = store;
        this.audit = audit;
        this.identities = identities;
        this.applier = applier;
        this.destinations = destinations;
        this.reserved = reserved;
    }

    // ------------------------------------------------------------------ reads

    /** One tenant, with its identity state. */
    public Map<String, Object> get(String tenantId) {
        return view(store.getTenant(tenantId), identities.get(tenantId).orElse(null));
    }

    // ------------------------------------------------------------------ tenant lifecycle

    /**
     * A new tenant: parity-store's tenant, then its organization and desktop client, then parity-rs
     * places it ({@code place_tenant}: parity-rs decides the zone, unit and failover zone; a top-level
     * enterprise tenant, a parent to be, gets no placement). Billing's provisioning only (D2): there is
     * no HTTP route. Its {@code admin.provisioning.requests} consumer, the next slice, calls this.
     */
    public Map<String, Object> create(ServiceIdentity by, CreateTenant req) {
        by.require(ServiceIdentity.PROVISIONING);
        String id = req.tenantId();
        if (id == null || !TENANT.matcher(id).matches()) {
            throw ApiException.badRequest("tenant_id");
        }
        if (reserved.contains(id)) {
            throw ApiException.of(ApiException.Code.RESERVED_TENANT_ID);
        }
        if (req.name() == null || req.name().isBlank() || req.name().length() > 200) {
            throw ApiException.badRequest("name");
        }
        if (req.tier() != null && !Set.of("small", "mid", "enterprise").contains(req.tier())) {
            throw ApiException.badRequest("tier");
        }
        if (req.parent() != null && !TENANT.matcher(req.parent()).matches()) {
            throw ApiException.badRequest("parent");
        }
        if (identities.retired(id)) {
            // Before any audit row or command: parity-store would bring its tombstone back (review MF-3).
            throw ApiException.of(ApiException.Code.TENANT_ID_RETIRED);
        }
        boolean mayBeParent = req.parent() == null && "enterprise".equals(req.tier());
        ObjectNode asked = JSON.createObjectNode().put("tenant_id", id).put("name", req.name());
        if (req.tier() != null) {
            asked.put("tier", req.tier());
        }
        if (req.parent() != null) {
            asked.put("parent", req.parent());
        }
        String requestId = store.newRequestId();
        ObjectNode put = StoreClient.command("put_tenant").put("tenant_id", id).put("name", req.name()).put("expected_version", 0);
        if (req.tier() != null) {
            put.put("tier", req.tier());
        }
        if (req.parent() != null) {
            put.put("parent", req.parent());
        }
        ObjectNode place = null;
        String placeRequestId = null;
        if (!mayBeParent) {
            String opId = parity.adminconsole.routing.RoutingClient.uuid7();
            place = routing.placeCommand(id, req.reason(), parity.adminconsole.routing.RoutingClient.uuid7(), opId);
            placeRequestId = routing.newRequestId();
            routing.validate(place, placeRequestId);
            asked.put("op_id", opId);
            asked.set("placement", JSON.createObjectNode().put("by", "parity-rs").set("hint", place.path("hint")));
        }
        // Both commands checked before the audit row: one that could never be sent leaves no row (F8).
        store.validateWrite(put, requestId);
        AuditLog.Ticket t = audit.requested(by.actor(), id, "tenant.create", id, req.reason(), asked, requestId);
        try {
            store.write(id, put, requestId);
            // The identity row right after the tenant exists: from here the apply job (and the nightly
            // check, for a crash in between) bring the organization and client to it.
            identities.create(id, req.name());
            applier.apply(id);
            // Then parity-rs places it: accepted at once, its saga lands the placement in parity-store.
            if (place != null) {
                routing.place(id, place, placeRequestId);
            }
        } catch (BackendException e) {
            answer(t, e);
            throw e;
        } catch (RuntimeException e) {
            audit.answered(t, AuditLog.Outcome.ERROR, "internal");
            throw e;
        }
        audit.answered(t, AuditLog.Outcome.OK, null);
        return view(store.getTenant(id), identities.get(id).orElse(null));
    }

    /**
     * Suspends or lifts the suspension: the organization and the tenant's accounts are disabled, or
     * enabled again. Staff operations only (D2, no HTTP route; admin-console stays the only writer of
     * the tenant realm): parity-cc-tools' {@code admin.ops.requests} consumer (the next slice) calls
     * this with the ops identity and the operation's op_id, both in the audit rows.
     */
    public Map<String, Object> setSuspended(OpsActor by, String tenantId, boolean suspended, String reason) {
        TenantIdentities.Row row = identities.get(tenantId).orElseThrow(TenantNotFoundException::new);
        if (row.state() == TenantIdentities.State.DELETED) {
            throw new TenantNotFoundException();
        }
        String action = suspended ? "tenant.suspend" : "tenant.unsuspend";
        ObjectNode asked = JSON.createObjectNode().put("tenant_id", tenantId).put("op_id", by.opId());
        asked.putObject("actor").put("sub", by.subject()).put("username", by.username());
        AuditLog.Ticket t = audit.requested(by.actor(), tenantId, action, tenantId, reason, asked, by.requestId());
        IdentityApplier.Result r;
        try {
            identities.desire(tenantId, suspended ? TenantIdentities.State.SUSPENDED : TenantIdentities.State.ACTIVE);
            r = applier.apply(tenantId);
        } catch (RuntimeException e) {
            audit.answered(t, AuditLog.Outcome.ERROR, "internal");
            throw e;
        }
        audit.answered(t, r == IdentityApplier.Result.APPLIED || r == IdentityApplier.Result.UP_TO_DATE
                ? AuditLog.Outcome.OK : AuditLog.Outcome.NOT_CONFIRMED, null);
        return get(tenantId);
    }

    /**
     * Deletes the tenant: parity-store's tenant (it refuses a parent with sub-tenants: {@code has_sub_tenants}),
     * its number destinations, then its accounts, desktop client and organization. Its id is retired
     * for good. Nothing deletes a tenant directly (coordinator ruling 3): only billing's deprovision saga
     * (account closure by the tenant's admin, or by staff in parity-cc-tools), through provisioning.
     */
    public void delete(ServiceIdentity by, String tenantId, String reason) {
        by.require(ServiceIdentity.PROVISIONING);
        String requestId = store.newRequestId();
        ObjectNode cmd = StoreClient.command("delete_tenant").put("tenant_id", tenantId);
        store.validateWrite(cmd, requestId);
        AuditLog.Ticket t = audit.requested(by.actor(), tenantId, "tenant.delete", tenantId, reason,
                JSON.createObjectNode().put("tenant_id", tenantId), requestId);
        try {
            store.write(tenantId, cmd, requestId);
            destinations.deleteAll(tenantId);
            if (identities.desire(tenantId, TenantIdentities.State.DELETED)) {
                applier.apply(tenantId);
            }
        } catch (BackendException e) {
            answer(t, e);
            throw e;
        } catch (RuntimeException e) {
            audit.answered(t, AuditLog.Outcome.ERROR, "internal");
            throw e;
        }
        audit.answered(t, AuditLog.Outcome.OK, null);
    }

    // ------------------------------------------------------------------ placement, numbers, SIP domains

    public JsonNode numbers(String tenantId, String after, int limit) {
        ObjectNode c = StoreClient.command("list_numbers").put("tenant_id", tenantId).put("limit", limit);
        if (after != null) {
            if (!NumberDestinations.E164.matcher(after).matches()) {
                throw ApiException.badRequest("after");
            }
            c.put("after", after);
        }
        JsonNode page = store.read(tenantId, c);
        Map<String, NumberDestinations.Destination> dest = destinations.of(tenantId);
        ObjectNode out = JSON.createObjectNode();
        var rows = out.putArray("numbers");
        for (JsonNode n : page.path("numbers")) {
            ObjectNode row = rows.addObject().put("number", n.asString());
            NumberDestinations.Destination d = dest.get(n.asString());
            if (d != null) {
                row.putObject("destination").put("kind", d.kind()).put("target", d.target()).put("version", d.version());
            } else {
                row.putNull("destination");
            }
        }
        out.set("next_after", page.path("next_after"));
        return out;
    }

    /** Assigns a number to the tenant: billing's provisioning only (D2, no HTTP route). */
    public JsonNode addNumber(ServiceIdentity by, String tenantId, String number, String reason) {
        by.require(ServiceIdentity.PROVISIONING);
        requireNumber(number);
        return command(by, tenantId, "number.add", number, reason,
                StoreClient.command("add_number").put("tenant_id", tenantId).put("number", number));
    }

    /** Takes a number back, and its destination: billing's provisioning only (D2, no HTTP route). */
    public JsonNode removeNumber(ServiceIdentity by, String tenantId, String number, String reason) {
        by.require(ServiceIdentity.PROVISIONING);
        requireNumber(number);
        JsonNode r = command(by, tenantId, "number.remove", number, reason,
                StoreClient.command("remove_number").put("tenant_id", tenantId).put("number", number));
        destinations.delete(tenantId, number);
        return r;
    }

    /** A number's destination; the number must be the tenant's in parity-store (else 404). */
    public Map<String, Object> setDestination(Caller caller, String tenantId, String number, String kind, String target) {
        requireNumber(number);
        if (kind == null || !Set.of("flow", "queue", "app").contains(kind)) {
            throw ApiException.badRequest("kind");
        }
        if (target == null || !NumberDestinations.TARGET.matcher(target).matches()) {
            throw ApiException.badRequest("target");
        }
        JsonNode owner;
        try {
            owner = store.read(tenantId, StoreClient.command("lookup_number").put("number", number));
        } catch (BackendException e) {
            if (e.kind() == BackendException.Kind.NOT_FOUND) {
                throw new TenantNotFoundException();
            }
            throw e;
        }
        if (!tenantId.equals(StoreClient.text(owner, "tenant_id"))) {
            // Another tenant's number answers like an unknown one (rule 6).
            throw new TenantNotFoundException();
        }
        ObjectNode asked = JSON.createObjectNode().put("number", number).put("kind", kind).put("target", target);
        AuditLog.Ticket t = audit.requested(AuditLog.Actor.of(caller), tenantId, "number.destination.set", number, null,
                asked, "console:" + java.util.UUID.randomUUID());
        NumberDestinations.Destination d;
        try {
            d = destinations.set(tenantId, number, kind, target, caller.subject());
        } catch (RuntimeException e) {
            audit.answered(t, AuditLog.Outcome.ERROR, "internal");
            throw e;
        }
        audit.answered(t, AuditLog.Outcome.OK, null);
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("number", number);
        m.put("kind", d.kind());
        m.put("target", d.target());
        m.put("version", d.version());
        return m;
    }

    public JsonNode sipDomains(String tenantId, String after, int limit) {
        ObjectNode c = StoreClient.command("list_sip_domains").put("tenant_id", tenantId).put("limit", limit);
        if (after != null) {
            c.put("after", after);
        }
        return store.read(tenantId, c);
    }

    /** Assigns a SIP domain to the tenant: billing's provisioning only (D2, no HTTP route). */
    public JsonNode addSipDomain(ServiceIdentity by, String tenantId, String domain, String reason) {
        by.require(ServiceIdentity.PROVISIONING);
        return command(by, tenantId, "sip_domain.add", domain, reason,
                StoreClient.command("add_sip_domain").put("tenant_id", tenantId).put("domain", lower(domain)));
    }

    public JsonNode removeSipDomain(ServiceIdentity by, String tenantId, String domain, String reason) {
        by.require(ServiceIdentity.PROVISIONING);
        return command(by, tenantId, "sip_domain.remove", domain, reason,
                StoreClient.command("remove_sip_domain").put("tenant_id", tenantId).put("domain", lower(domain)));
    }

    // ------------------------------------------------------------------ helpers

    /** One audited write to parity-store's admin topic. */
    private JsonNode command(ServiceIdentity by, String tenantId, String action, String target, String reason, ObjectNode cmd) {
        if (cmd.has("domain") && !cmd.path("domain").asString().matches(
                "^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\\.)+[a-z](?:[a-z0-9-]{0,61}[a-z0-9])?$")) {
            throw ApiException.badRequest("domain");
        }
        String requestId = store.newRequestId();
        store.validateWrite(cmd, requestId);
        ObjectNode asked = cmd.deepCopy();
        asked.remove("cmd");
        AuditLog.Ticket t = audit.requested(by.actor(), tenantId, action, target, reason, asked, requestId);
        return ok(t, () -> store.write(tenantId, cmd, requestId));
    }

    private JsonNode ok(AuditLog.Ticket t, Supplier<JsonNode> call) {
        JsonNode r;
        try {
            r = call.get();
        } catch (BackendException e) {
            answer(t, e);
            throw e;
        } catch (RuntimeException e) {
            audit.answered(t, AuditLog.Outcome.ERROR, "internal");
            throw e;
        }
        audit.answered(t, AuditLog.Outcome.OK, null);
        return r;
    }

    private void answer(AuditLog.Ticket t, BackendException e) {
        if (e.kind() == BackendException.Kind.NOT_CONFIRMED) {
            audit.answered(t, AuditLog.Outcome.NOT_CONFIRMED, null);
        } else if (e.kind() == BackendException.Kind.NOT_SENT) {
            audit.answered(t, AuditLog.Outcome.ERROR, "not_sent");
        } else {
            audit.answered(t, AuditLog.Outcome.ERROR, e.error() != null ? e.error().code() : e.kind().code());
        }
    }

    private static void requireNumber(String number) {
        if (number == null || !NumberDestinations.E164.matcher(number).matches()) {
            throw ApiException.badRequest("number");
        }
    }

    private static String lower(String domain) {
        if (domain == null) {
            throw ApiException.badRequest("domain");
        }
        return domain.toLowerCase(java.util.Locale.ROOT);
    }

    private Map<String, Object> view(JsonNode t, TenantIdentities.Row identity) {
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("tenant_id", t.path("tenant_id").asString());
        m.put("name", t.path("name").asString());
        m.put("tier", t.path("tier").asString());
        m.put("parent", StoreClient.text(t, "parent"));
        List<String> subs = new ArrayList<>();
        t.path("sub_tenants").forEach(s -> subs.add(s.asString()));
        m.put("sub_tenants", subs);
        m.put("version", t.path("version").asLong());
        // Read-only here: routing (moves, failover, home zone) is staff's, in parity-cc-tools (internal).
        m.put("placement", t.path("placement").isNull() || t.path("placement").isMissingNode() ? null : t.path("placement"));
        m.put("numbers", t.path("numbers").asLong());
        m.put("sip_domains", t.path("sip_domains").asLong());
        if (identity != null) {
            Map<String, Object> i = new LinkedHashMap<>();
            i.put("state", identity.state().name().toLowerCase(java.util.Locale.ROOT));
            i.put("applied", identity.applied());
            i.put("organization", identity.organizationId() != null);
            i.put("desktop_client", identity.desktopClientId() != null ? "desktop-" + identity.tenantId() : null);
            i.put("last_apply_error", identity.lastApplyError());
            m.put("identity", i);
        }
        return m;
    }

    /** A new tenant, as provisioning asks for it. */
    public record CreateTenant(String tenantId, String name, String tier, String parent, String reason) {}
}
