package parity.adminconsole.audit;

import java.sql.Array;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.time.Instant;
import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import java.time.format.DateTimeParseException;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.regex.Pattern;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import parity.adminconsole.db.Rls;
import parity.adminconsole.security.Caller;
import parity.adminconsole.security.ForbiddenException;
import parity.adminconsole.security.Role;
import parity.adminconsole.security.TenantScope;
import parity.adminconsole.web.ApiException;

/**
 * {@code GET /api/audit}: search by tenant, actor, action, source and time, newest first, paged with a
 * cursor (PLAN.md "Audit log"). A tenant admin searches one tenant at a time, their own by default or a
 * sub-tenant (404 outside the scope); a supervisor not at all. There is no every-tenant search here
 * (user decision D2, 2026-11-03: the cross-tenant audit is parity-cc-tools'): every query runs in its
 * one tenant's row-level-security scope (rule 4). A {@code requested} row without its {@code answered}
 * row comes back with {@code answered: false}: shown as "not confirmed".
 */
@RestController
public class AuditController {

    private static final Pattern ACTION = Pattern.compile("^[a-z][a-z0-9_.]{0,63}$");
    private static final Pattern SOURCE = Pattern.compile("^(console|mcp|keycloak)$");

    private final Rls rls;
    private final TenantScope scope;

    public AuditController(Rls rls, TenantScope scope) {
        this.rls = rls;
        this.scope = scope;
    }

    @GetMapping("/api/audit")
    public Map<String, Object> search(@AuthenticationPrincipal Caller caller,
            @RequestParam(required = false) String tenant,
            @RequestParam(required = false) String actor,
            @RequestParam(required = false) String action,
            @RequestParam(required = false) String source,
            @RequestParam(required = false) String from,
            @RequestParam(required = false) String to,
            @RequestParam(required = false) String before,
            @RequestParam(defaultValue = "50") int limit) {
        if (!caller.has(Role.TENANT_ADMIN)) {
            throw new ForbiddenException();
        }
        String t = tenant == null ? caller.tenantId() : tenant;
        scope.requireAdmin(caller, t);
        if (limit < 1 || limit > 200) {
            throw ApiException.badRequest("limit");
        }
        StringBuilder sql = new StringBuilder("""
                SELECT a.id, a.at, a.source, a.phase, a.request_id, a.actor, a.actor_roles, a.tenant_id, a.action,
                       a.target, a.reason, a.request::text AS request, a.outcome, a.error_code,
                       CASE WHEN a.phase = 'requested' THEN EXISTS (
                           SELECT 1 FROM audit_log b WHERE b.request_id = a.request_id AND b.phase = 'answered')
                       END AS answered
                FROM audit_log a WHERE true""");
        List<Object> params = new ArrayList<>();
        sql.append(" AND a.tenant_id = ?");
        params.add(t);
        if (actor != null) {
            if (actor.length() > 200) {
                throw ApiException.badRequest("actor");
            }
            sql.append(" AND a.actor = ?");
            params.add(actor);
        }
        if (action != null) {
            if (!ACTION.matcher(action).matches()) {
                throw ApiException.badRequest("action");
            }
            sql.append(" AND a.action = ?");
            params.add(action);
        }
        if (source != null) {
            if (!SOURCE.matcher(source).matches()) {
                throw ApiException.badRequest("source");
            }
            sql.append(" AND a.source = ?");
            params.add(source);
        }
        if (from != null) {
            sql.append(" AND a.at >= ?");
            params.add(time(from, "from"));
        }
        if (to != null) {
            sql.append(" AND a.at < ?");
            params.add(time(to, "to"));
        }
        if (before != null) {
            String[] cursor = before.split("_", 2);
            if (cursor.length != 2) {
                throw ApiException.badRequest("before");
            }
            OffsetDateTime at = time(cursor[0], "before");
            UUID id;
            try {
                id = UUID.fromString(cursor[1]);
            } catch (IllegalArgumentException e) {
                throw ApiException.badRequest("before");
            }
            sql.append(" AND (a.at, a.id) < (?, ?)");
            params.add(at);
            params.add(id);
        }
        sql.append(" ORDER BY a.at DESC, a.id DESC LIMIT ?");
        params.add(limit + 1);
        List<Map<String, Object>> rows = rls.tenant(t, db -> db.sql(sql.toString()).params(params)
                .query((rs, n) -> row(rs)).list());
        String next = null;
        if (rows.size() > limit) {
            rows = rows.subList(0, limit);
            Map<String, Object> last = rows.get(limit - 1);
            next = last.get("at") + "_" + last.get("id");
        }
        Map<String, Object> out = new LinkedHashMap<>();
        out.put("rows", rows);
        out.put("next", next);
        return out;
    }

    private static OffsetDateTime time(String value, @com.google.errorprone.annotations.CompileTimeConstant String field) {
        try {
            return OffsetDateTime.ofInstant(Instant.parse(value), ZoneOffset.UTC);
        } catch (DateTimeParseException e) {
            throw ApiException.badRequest(field);
        }
    }

    private static Map<String, Object> row(ResultSet rs) throws SQLException {
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("id", rs.getObject("id", UUID.class).toString());
        m.put("at", rs.getObject("at", OffsetDateTime.class).toInstant().toString());
        m.put("source", rs.getString("source"));
        m.put("phase", rs.getString("phase"));
        m.put("request_id", rs.getString("request_id"));
        m.put("actor", rs.getString("actor"));
        Array roles = rs.getArray("actor_roles");
        m.put("actor_roles", roles == null ? List.of() : List.of((String[]) roles.getArray()));
        m.put("tenant_id", rs.getString("tenant_id"));
        m.put("action", rs.getString("action"));
        m.put("target", rs.getString("target"));
        m.put("reason", rs.getString("reason"));
        String request = rs.getString("request");
        m.put("request", request == null ? null : tools.jackson.databind.json.JsonMapper.builder().build().readTree(request));
        m.put("outcome", rs.getString("outcome"));
        m.put("error_code", rs.getString("error_code"));
        Object answered = rs.getObject("answered");
        if (answered != null) {
            m.put("answered", answered);
        }
        return m;
    }
}
