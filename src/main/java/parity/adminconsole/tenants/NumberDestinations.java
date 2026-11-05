package parity.adminconsole.tenants;

import java.time.Clock;
import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.regex.Pattern;
import org.springframework.stereotype.Component;
import parity.adminconsole.db.Rls;

/** {@code number_destination} (V2): each number's destination, a flow, a queue or a CPaaS app. */
@Component
public class NumberDestinations {

    static final Pattern E164 = Pattern.compile("^\\+[1-9][0-9]{6,14}$");
    static final Pattern TARGET = Pattern.compile("^[A-Za-z0-9_.-]{1,64}$");

    /** One destination and its version. */
    public record Destination(String kind, String target, long version) {}

    private final Rls rls;
    private final Clock clock;

    public NumberDestinations(Rls rls, Clock clock) {
        this.rls = rls;
        this.clock = clock;
    }

    public Map<String, Destination> of(String tenantId) {
        Map<String, Destination> out = new LinkedHashMap<>();
        rls.tenant(tenantId, db -> {
            db.sql("SELECT number, kind, target, version FROM number_destination WHERE tenant_id = ?")
                    .param(tenantId).query(rs -> {
                        out.put(rs.getString("number"), new Destination(rs.getString("kind"), rs.getString("target"), rs.getLong("version")));
                    });
            return null;
        });
        return out;
    }

    public Destination set(String tenantId, String number, String kind, String target, String by) {
        OffsetDateTime now = OffsetDateTime.now(clock).withOffsetSameInstant(ZoneOffset.UTC);
        return rls.tenant(tenantId, db -> db.sql("""
                INSERT INTO number_destination (tenant_id, number, kind, target, version, updated_by, updated_at)
                VALUES (?, ?, ?, ?, 1, ?, ?)
                ON CONFLICT (tenant_id, number) DO UPDATE SET kind = EXCLUDED.kind, target = EXCLUDED.target,
                    version = number_destination.version + 1, updated_by = EXCLUDED.updated_by, updated_at = EXCLUDED.updated_at
                RETURNING kind, target, version""")
                .params(tenantId, number, kind, target, by, now)
                .query((rs, n) -> new Destination(rs.getString("kind"), rs.getString("target"), rs.getLong("version")))
                .single());
    }

    public void delete(String tenantId, String number) {
        rls.tenant(tenantId, db -> db.sql("DELETE FROM number_destination WHERE tenant_id = ? AND number = ?")
                .params(tenantId, number).update());
    }

    public void deleteAll(String tenantId) {
        rls.tenant(tenantId, db -> db.sql("DELETE FROM number_destination WHERE tenant_id = ?").param(tenantId).update());
    }
}
