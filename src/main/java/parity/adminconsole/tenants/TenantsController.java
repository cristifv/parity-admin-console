package parity.adminconsole.tenants;

import java.util.List;
import java.util.Map;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import parity.adminconsole.audit.AuditLog;
import parity.adminconsole.identity.LocalAccounts;
import parity.adminconsole.security.Caller;
import parity.adminconsole.security.TenantScope;
import parity.adminconsole.web.ApiException;
import tools.jackson.databind.JsonNode;

/**
 * The tenants API (console step 9, SAML-PLAN step 4), tenant-scoped only: admin-console is the public,
 * tenant-only tool (user decisions D1-D2, 2026-11-03). Every path names a tenant, checked against the
 * caller's scope first ({@link TenantScope}: 404 outside it), then against the action's role (403). The
 * tenant always comes from the path, checked, never from a body (rule 1): a body's {@code tenant_id} is
 * ignored.
 * <ul>
 *   <li>tenant admins, for their tenant and its sub-tenants: read, numbers and SIP domains (read),
 *       number destinations, local accounts;</li>
 *   <li>supervisors: read their own tenant, its numbers and SIP domains.</li>
 * </ul>
 * No route lists every tenant, creates, suspends or deletes one, or assigns numbers or SIP domains:
 * those are billing's provisioning and parity-cc-tools' ({@link ServiceIdentity}).
 */
@RestController
public class TenantsController {

    private final TenantService tenants;
    private final TenantScope scope;
    private final LocalAccounts accounts;

    public TenantsController(TenantService tenants, TenantScope scope, LocalAccounts accounts) {
        this.tenants = tenants;
        this.scope = scope;
        this.accounts = accounts;
    }

    @GetMapping("/api/tenants/{id}")
    public Map<String, Object> get(@AuthenticationPrincipal Caller caller, @PathVariable String id) {
        scope.requireVisible(caller, id);
        return tenants.get(id);
    }

    @GetMapping("/api/tenants/{id}/numbers")
    public JsonNode numbers(@AuthenticationPrincipal Caller caller, @PathVariable String id,
            @RequestParam(required = false) String after, @RequestParam(defaultValue = "100") int limit) {
        scope.requireVisible(caller, id);
        if (limit < 1 || limit > 500) {
            throw ApiException.badRequest("limit");
        }
        return tenants.numbers(id, after, limit);
    }

    public record DestinationChange(String number, String kind, String target) {}

    @PutMapping("/api/tenants/{id}/number-destinations")
    public Map<String, Object> destination(@AuthenticationPrincipal Caller caller, @PathVariable String id,
            @RequestBody DestinationChange body) {
        scope.requireAdmin(caller, id);
        return tenants.setDestination(caller, id, body.number(), body.kind(), body.target());
    }

    @GetMapping("/api/tenants/{id}/sip-domains")
    public JsonNode sipDomains(@AuthenticationPrincipal Caller caller, @PathVariable String id,
            @RequestParam(required = false) String after, @RequestParam(defaultValue = "100") int limit) {
        scope.requireVisible(caller, id);
        if (limit < 1 || limit > 500) {
            throw ApiException.badRequest("limit");
        }
        return tenants.sipDomains(id, after, limit);
    }

    // ------------------------------------------------------------------ local accounts

    @GetMapping("/api/tenants/{id}/users")
    public Map<String, Object> users(@AuthenticationPrincipal Caller caller, @PathVariable String id,
            @RequestParam(defaultValue = "0") int first, @RequestParam(defaultValue = "50") int max) {
        scope.requireAdmin(caller, id);
        if (first < 0 || max < 1 || max > 100) {
            throw ApiException.badRequest("max");
        }
        List<Map<String, Object>> users = accounts.list(id, first, max);
        return Map.of("users", users);
    }

    public record NewUser(String name, String firstName, String lastName, String email, List<String> roles) {}

    @PostMapping("/api/tenants/{id}/users")
    public ResponseEntity<Map<String, Object>> createUser(@AuthenticationPrincipal Caller caller, @PathVariable String id,
            @RequestBody NewUser body) {
        scope.requireAdmin(caller, id);
        return ResponseEntity.status(HttpStatus.CREATED).body(accounts.create(AuditLog.Actor.of(caller), id,
                new LocalAccounts.NewAccount(body.name(), body.firstName(), body.lastName(), body.email(), body.roles())));
    }

    @PostMapping("/api/tenants/{id}/users/{user}/disable")
    public Map<String, Object> disableUser(@AuthenticationPrincipal Caller caller, @PathVariable String id, @PathVariable String user) {
        scope.requireAdmin(caller, id);
        return accounts.setEnabled(caller, id, user, false);
    }

    @PostMapping("/api/tenants/{id}/users/{user}/enable")
    public Map<String, Object> enableUser(@AuthenticationPrincipal Caller caller, @PathVariable String id, @PathVariable String user) {
        scope.requireAdmin(caller, id);
        return accounts.setEnabled(caller, id, user, true);
    }
}
