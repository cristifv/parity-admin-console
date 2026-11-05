package parity.adminconsole.security;

import org.springframework.stereotype.Component;
import parity.adminconsole.backend.BackendException;
import parity.adminconsole.identity.TenantIdentities;
import parity.adminconsole.store.StoreClient;
import parity.adminconsole.web.ApiException;
import java.util.Optional;
import org.springframework.beans.factory.annotation.Autowired;

/**
 * The tenant scope, worked out per request (PLAN.md "Security and tenancy"; multi-tenant rules 2 and 6).
 * There is no every-tenant scope (user decision D2, 2026-11-03: staff work in parity-cc-tools):
 * <ul>
 *   <li>{@code tenant-admin}: their own tenant, and its sub-tenants (parity-store's {@code parent},
 *       asked fresh on every such request, so a sub-tenant moved to another parent is out of scope at
 *       once; a tenant whose parent is any other tenant, or none, is out of scope);</li>
 *   <li>{@code supervisor}: their own tenant.</li>
 * </ul>
 * Out of scope is {@link TenantNotFoundException} (404); in scope without the role for the action is
 * {@link ForbiddenException} (403). A sub-tenant in scope that is suspended is 403 {@code tenant_suspended},
 * a deleted one 404 (decision 2026-10-31; the caller's own tenant is gated by {@link TenantStateGate}).
 */
@Component
public class TenantScope {

    /** A tenant's parent, asked fresh: empty for a tenant without one or that doesn't exist. */
    @FunctionalInterface
    public interface Parents {
        Optional<String> of(String tenantId);
    }

    /** A tenant's identity state, if it has a row. */
    @FunctionalInterface
    public interface States {
        Optional<TenantIdentities.State> of(String tenantId);
    }

    private final Parents parents;
    private final States states;

    @Autowired
    public TenantScope(StoreClient store, TenantIdentities identities) {
        this(tenantId -> {
            try {
                return Optional.ofNullable(StoreClient.text(store.getTenant(tenantId), "parent"));
            } catch (BackendException e) {
                if (e.kind() == BackendException.Kind.NOT_FOUND) {
                    return Optional.empty();
                }
                throw e;
            }
        }, tenantId -> identities.get(tenantId).map(TenantIdentities.Row::state));
    }

    public TenantScope(Parents parents, States states) {
        this.parents = parents;
        this.states = states;
    }

    /** Without states (every tenant active): unit tests of the scope alone. */
    public TenantScope(Parents parents) {
        this(parents, tenantId -> Optional.empty());
    }

    /** The caller may see {@code tenantId}, or 404. */
    public void requireVisible(Caller caller, String tenantId) {
        if (tenantId == null || !TokenChecks.TENANT.matcher(tenantId).matches() || caller.tenantId() == null) {
            throw new TenantNotFoundException();
        }
        if (tenantId.equals(caller.tenantId())) {
            return;
        }
        if (caller.has(Role.TENANT_ADMIN) && isSubTenantOf(tenantId, caller.tenantId())) {
            // In scope: only now may its state show (out of scope stays a plain 404).
            switch (states.of(tenantId).orElse(TenantIdentities.State.ACTIVE)) {
                case ACTIVE -> { }
                case SUSPENDED -> throw ApiException.of(ApiException.Code.SUSPENDED_TENANT_ACCESS);
                case DELETED -> throw new TenantNotFoundException();
            }
            return;
        }
        throw new TenantNotFoundException();
    }

    /** Visible, and the caller administers it (a tenant-admin in scope); else 404 or 403. */
    public void requireAdmin(Caller caller, String tenantId) {
        requireVisible(caller, tenantId);
        if (!caller.has(Role.TENANT_ADMIN)) {
            throw new ForbiddenException();
        }
    }

    private boolean isSubTenantOf(String tenantId, String parent) {
        return parents.of(tenantId).map(parent::equals).orElse(false);
    }
}
