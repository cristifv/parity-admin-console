package parity.adminconsole.tenants;

import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.ArgumentMatchers.isNull;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.util.List;
import java.util.Map;
import java.util.Optional;
import org.junit.jupiter.api.Test;
import parity.adminconsole.audit.AuditLog;
import parity.adminconsole.config.AdminConsoleProperties;
import parity.adminconsole.identity.IdentityApplier;
import parity.adminconsole.identity.TenantIdentities;
import parity.adminconsole.security.ReservedTenantIds;
import parity.adminconsole.store.StoreClient;

/**
 * Review F8: a command that can't pass its schema leaves no audit row; once the {@code requested} row is
 * written, every way out writes its {@code answered} row, unexpected exceptions included. D2: the
 * lifecycle runs as a service identity (provisioning) or an ops actor, never a person's token.
 */
class TenantServiceAuditTest {

    private final StoreClient store = mock(StoreClient.class);
    private final AuditLog audit = mock(AuditLog.class);
    private final TenantIdentities identities = mock(TenantIdentities.class);
    private final IdentityApplier applier = mock(IdentityApplier.class);
    private final NumberDestinations destinations = mock(NumberDestinations.class);
    private static final ServiceIdentity PROVISIONING = ServiceIdentity.PROVISIONING;
    private final OpsActor ops = new OpsActor("f6b7c3d2-0b1e-4c55-9a51-2f0f3c1d9e01", "ops.jane",
            "019a4a5e-7c3b-7d2e-9f10-0123456789ab");
    private final AuditLog.Ticket ticket = new AuditLog.Ticket("r-1", PROVISIONING.actor(), "acme", "number.add", "+15550100101");
    private final parity.adminconsole.backend.BackendClient backend = mock(parity.adminconsole.backend.BackendClient.class);
    private final TenantService service;

    TenantServiceAuditTest() {
        AdminConsoleProperties properties = mock(AdminConsoleProperties.class);
        when(properties.tenants()).thenReturn(new AdminConsoleProperties.Tenants(List.of("admin"), "eu", null));
        when(properties.kafka()).thenReturn(new AdminConsoleProperties.Kafka("x:9092", null, null, Map.of(),
                "replies.admin-console", "tenant.store.requests", "tenant.store.admin.requests",
                "tenant.routing.onboarding.requests.eu1a", java.time.Duration.ofSeconds(5), java.time.Duration.ofSeconds(3), false));
        when(store.newRequestId()).thenReturn("r-1");
        when(audit.requested(any(), anyString(), anyString(), any(), any(), any(), anyString())).thenReturn(ticket);
        when(backend.newRequestId()).thenReturn("r-2");
        service = new TenantService(store, new parity.adminconsole.routing.RoutingClient(backend, properties), audit, identities,
                applier, destinations, new ReservedTenantIds(properties));
    }

    /** 2026-11-03: parity-rs places a new tenant (place_tenant with a hint); the console writes no placement. */
    @Test
    void aNewTenantIsPlacedByParityRsAndAParentToBeIsNot() {
        tools.jackson.databind.node.ObjectNode tenant = tools.jackson.databind.json.JsonMapper.builder().build().createObjectNode()
                .put("tenant_id", "acme").put("name", "Acme").put("tier", "small");
        when(store.getTenant(anyString())).thenReturn(tenant);
        when(identities.get(anyString())).thenReturn(Optional.empty());
        service.create(PROVISIONING, new TenantService.CreateTenant("acme", "Acme", "small", null, "onboarding a tenant"));
        verify(backend).request(eq("parity-rs"), eq("tenant.routing.onboarding.requests.eu1a"),
                eq(parity.adminconsole.contracts.Schemas.ROUTING_REQUESTS), eq("acme"),
                org.mockito.ArgumentMatchers.argThat(c -> "place_tenant".equals(c.path("cmd").asString())
                        && "eu".equals(c.path("hint").path("residency").asString())
                        && "parity-admin-console".equals(c.path("actor").path("system").asString())), anyString());
        // The audit row's actor is the service identity, not a person.
        verify(audit).requested(eq(AuditLog.Actor.system("provisioning")), eq("acme"), eq("tenant.create"), eq("acme"), any(), any(), anyString());
        verify(store, never()).write(any(), org.mockito.ArgumentMatchers.argThat(c -> c != null
                && c.path("cmd").asString("").endsWith("_placement")), any());
        org.mockito.Mockito.clearInvocations(backend);
        service.create(PROVISIONING, new TenantService.CreateTenant("initech", "Initech", "enterprise", null, "a parent"));
        verify(backend, never()).request(any(), any(), any(), any(), any(), any());
    }

    @Test
    void aCommandThatFailsItsSchemaWritesNoAuditRowAndIsNotSent() {
        doThrow(new IllegalStateException("a backend request failed its schema")).when(store).validateWrite(any(), anyString());
        assertThatThrownBy(() -> service.addNumber(PROVISIONING, "acme", "+15550100101", null)).isInstanceOf(IllegalStateException.class);
        verify(audit, never()).requested(any(), any(), any(), any(), any(), any(), any());
        verify(store, never()).write(any(), any(), any());
    }

    @Test
    void anUnexpectedFailureAfterTheRequestedRowIsAnswered() {
        when(store.write(any(), any(), any())).thenThrow(new IllegalArgumentException("not a backend answer"));
        assertThatThrownBy(() -> service.addNumber(PROVISIONING, "acme", "+15550100101", null)).isInstanceOf(IllegalArgumentException.class);
        verify(audit).answered(ticket, AuditLog.Outcome.ERROR, "internal");
    }

    @Test
    void aSuspensionThatFailsInTheDatabaseIsAnswered() {
        when(identities.get("acme")).thenReturn(Optional.of(new TenantIdentities.Row("acme", TenantIdentities.State.ACTIVE, "Acme",
                1, 1, "org-1", "client-1", null, 0)));
        when(identities.desire(eq("acme"), any())).thenThrow(new IllegalStateException("database down"));
        assertThatThrownBy(() -> service.setSuspended(ops, "acme", true, "unpaid")).isInstanceOf(IllegalStateException.class);
        verify(audit).answered(ticket, AuditLog.Outcome.ERROR, "internal");
        verify(applier, never()).apply(anyString());
        verify(audit, never()).answered(any(), eq(AuditLog.Outcome.OK), isNull());
    }

    /** Ruling 2: a suspension's audit rows name the ops identity and link to parity-cc-tools' by op_id. */
    @Test
    void aSuspensionIsAuditedAsTheOpsActorWithItsOpId() {
        when(identities.get("acme")).thenReturn(Optional.of(new TenantIdentities.Row("acme", TenantIdentities.State.ACTIVE, "Acme",
                1, 1, "org-1", "client-1", null, 0)));
        when(store.getTenant("acme")).thenReturn(tools.jackson.databind.json.JsonMapper.builder().build().createObjectNode()
                .put("tenant_id", "acme").put("name", "Acme"));
        when(applier.apply("acme")).thenReturn(IdentityApplier.Result.APPLIED);
        service.setSuspended(ops, "acme", true, "unpaid invoices");
        verify(audit).requested(eq(new AuditLog.Actor("ops:f6b7c3d2-0b1e-4c55-9a51-2f0f3c1d9e01", List.of("ops"))), eq("acme"),
                eq("tenant.suspend"), eq("acme"), eq("unpaid invoices"),
                org.mockito.ArgumentMatchers.argThat(r -> "019a4a5e-7c3b-7d2e-9f10-0123456789ab".equals(r.path("op_id").asString())
                        && "ops.jane".equals(r.path("actor").path("username").asString())),
                eq("ops:019a4a5e-7c3b-7d2e-9f10-0123456789ab"));
        verify(audit).answered(ticket, AuditLog.Outcome.OK, null);
    }

    /** D2: the reserved ids, the staff organization among them, are never created; nothing is sent. */
    @Test
    void theStaffOrganizationIsNeverATenant() {
        for (String id : List.of("platform", "admin")) {
            assertThatThrownBy(() -> service.create(PROVISIONING, new TenantService.CreateTenant(id, "X", "small", null, null)))
                    .isInstanceOf(parity.adminconsole.web.ApiException.class)
                    .extracting(e -> ((parity.adminconsole.web.ApiException) e).code()).isEqualTo(parity.adminconsole.web.ApiException.Code.RESERVED_TENANT_ID);
        }
        verify(audit, never()).requested(any(), any(), any(), any(), any(), any(), any());
        verify(store, never()).write(any(), any(), any());
    }

    @Test
    void anOpsActorNeedsItsIdentityAndOpId() {
        assertThatThrownBy(() -> new OpsActor("sub", "ops.jane", "not-a-uuid")).isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> new OpsActor(null, "ops.jane", "019a4a5e-7c3b-7d2e-9f10-0123456789ab")).isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> new OpsActor("sub", "a b", "019a4a5e-7c3b-7d2e-9f10-0123456789ab")).isInstanceOf(IllegalArgumentException.class);
    }
}
