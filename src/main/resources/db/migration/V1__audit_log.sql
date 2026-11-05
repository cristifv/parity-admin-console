-- parity-admin-console V1: the audit log (PLAN.md "Audit log", console step 2).
-- Two rows per command: `requested` before the command is sent, `answered` after (ok, error or
-- not_confirmed). The app role may only insert and read (no row is ever changed), and row-level
-- security filters every query: a transaction that set neither app.tenant_id nor app.platform sees
-- and writes nothing (multi-tenant rule 4). Monthly partitions, kept 24 months (ARCH §5.2).
-- ${appRole} is the role the application connects as (Flyway placeholder; parity-deploy creates it).

CREATE TABLE audit_log (
    id          uuid NOT NULL,                       -- UUIDv7
    at          timestamptz NOT NULL,
    source      text NOT NULL CHECK (source IN ('console', 'mcp', 'keycloak')),
    phase       text NOT NULL CHECK (phase IN ('requested', 'answered')),
    request_id  text NOT NULL CHECK (request_id ~ '^[A-Za-z0-9._:-]{1,200}$'),  -- links the two rows
    actor       text NOT NULL CHECK (length(actor) BETWEEN 1 AND 200),        -- the JWT subject, or system:<job>
    actor_roles text[] NOT NULL,
    tenant_id   text CHECK (tenant_id ~ '^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$'),  -- null: platform-wide
    action      text NOT NULL CHECK (action ~ '^[a-z][a-z0-9_.]{0,63}$'),     -- e.g. tenant.create
    target      text CHECK (length(target) <= 300),
    reason      text CHECK (length(reason) <= 500),
    request     jsonb,                               -- what was asked, without secrets
    outcome     text CHECK (outcome IN ('ok', 'error', 'not_confirmed')),
    error_code  text CHECK (error_code ~ '^[a-z][a-z0-9_]{0,63}$'),
    PRIMARY KEY (at, id),
    CHECK ((phase = 'requested') = (outcome IS NULL))
) PARTITION BY RANGE (at);

CREATE INDEX audit_log_tenant_at ON audit_log (tenant_id, at);
CREATE INDEX audit_log_actor_at ON audit_log (actor, at);
CREATE INDEX audit_log_request ON audit_log (request_id);

ALTER TABLE audit_log ENABLE ROW LEVEL SECURITY;
ALTER TABLE audit_log FORCE ROW LEVEL SECURITY;
CREATE POLICY audit_log_read ON audit_log FOR SELECT USING (
    current_setting('app.platform', true) = 'on'
    OR (tenant_id IS NOT NULL AND tenant_id = nullif(current_setting('app.tenant_id', true), '')));
CREATE POLICY audit_log_insert ON audit_log FOR INSERT WITH CHECK (
    current_setting('app.platform', true) = 'on'
    OR (tenant_id IS NOT NULL AND tenant_id = nullif(current_setting('app.tenant_id', true), '')));

-- Monthly partitions (UTC months), created ahead by the application through this function: the app
-- role can't create tables. SECURITY DEFINER runs it as the owner, with a fixed search_path; the
-- partition names come from dates only. One caller at a time (an advisory lock), so two instances
-- starting together don't collide. Dropping old partitions stays an owner's job (PLAN.md: dumped to
-- the backup host first), so no function here drops anything.
CREATE FUNCTION audit_log_ensure_partitions(months_ahead integer) RETURNS integer
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, public AS $$
DECLARE
    created integer := 0;
    m date := date_trunc('month', now() AT TIME ZONE 'UTC')::date;
    part text;
BEGIN
    IF months_ahead IS NULL OR months_ahead < 0 OR months_ahead > 24 THEN
        RAISE EXCEPTION 'months_ahead must be 0..24';
    END IF;
    PERFORM pg_advisory_xact_lock(hashtext('parity-admin-console:audit_log_partitions'));
    FOR i IN 0..months_ahead LOOP
        part := format('audit_log_y%sm%s', to_char(m, 'YYYY'), to_char(m, 'MM'));
        IF to_regclass('public.' || part) IS NULL THEN
            EXECUTE format('CREATE TABLE public.%I PARTITION OF public.audit_log FOR VALUES FROM (%L) TO (%L)',
                           part, (m::timestamp AT TIME ZONE 'UTC'), ((m + interval '1 month')::timestamp AT TIME ZONE 'UTC'));
            created := created + 1;
        END IF;
        m := (m + interval '1 month')::date;
    END LOOP;
    RETURN created;
END $$;
REVOKE ALL ON FUNCTION audit_log_ensure_partitions(integer) FROM PUBLIC;

SELECT audit_log_ensure_partitions(3);

GRANT USAGE ON SCHEMA public TO ${appRole};
GRANT SELECT, INSERT ON audit_log TO ${appRole};
GRANT EXECUTE ON FUNCTION audit_log_ensure_partitions(integer) TO ${appRole};
