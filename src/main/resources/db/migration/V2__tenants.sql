-- parity-admin-console V2: what admin-api keeps about tenants beside parity-store (console step 9,
-- SAML-PLAN step 4). parity-store owns the tenant, its tier, parent, placement, numbers and SIP
-- domains; the console owns the tenant's identity state (its Keycloak organization and desktop
-- client, active / suspended / deleted) and each number's destination. Row-level security on
-- tenant_id, as audit_log (rule 10).

-- The desired identity state per tenant, and what was applied to Keycloak (SAML-PLAN "How a change
-- reaches Keycloak"): version +1 per change; the apply job brings applied_version up to it.
CREATE TABLE tenant_identity (
    tenant_id           text PRIMARY KEY CHECK (tenant_id ~ '^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$'),
    state               text NOT NULL CHECK (state IN ('active', 'suspended', 'deleted')),
    name                text NOT NULL CHECK (length(name) BETWEEN 1 AND 200),
    version             bigint NOT NULL CHECK (version >= 1),
    applied_version     bigint NOT NULL DEFAULT 0,
    organization_id     text,                 -- Keycloak's id of the organization (alias = tenant_id)
    desktop_client_id   text,                 -- Keycloak's id of desktop-<tenant_id>
    last_apply_error    text CHECK (last_apply_error ~ '^[a-z][a-z0-9_]{0,63}$'),  -- a code, never a message
    attempts            integer NOT NULL DEFAULT 0,
    next_attempt_at     timestamptz NOT NULL DEFAULT now(),
    created_at          timestamptz NOT NULL,
    updated_at          timestamptz NOT NULL
);
CREATE INDEX tenant_identity_pending ON tenant_identity (next_attempt_at) WHERE applied_version < version;

-- The accounts a suspension disabled, so lifting it re-enables those and no others.
CREATE TABLE identity_suspension (
    tenant_id   text NOT NULL REFERENCES tenant_identity (tenant_id),
    user_id     text NOT NULL CHECK (user_id ~ '^[A-Za-z0-9-]{1,64}$'),
    disabled_at timestamptz NOT NULL,
    PRIMARY KEY (tenant_id, user_id)
);

-- Each number's destination (README finding 3: admin-api's): an IVR flow, a queue or a CPaaS app.
-- The flows and queues are console config (steps 5-7); until they exist the name isn't checked
-- against them.
CREATE TABLE number_destination (
    tenant_id  text NOT NULL CHECK (tenant_id ~ '^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$'),
    number     text NOT NULL CHECK (number ~ '^\+[1-9][0-9]{6,14}$'),
    kind       text NOT NULL CHECK (kind IN ('flow', 'queue', 'app')),
    target     text NOT NULL CHECK (target ~ '^[A-Za-z0-9_.-]{1,64}$'),
    version    bigint NOT NULL CHECK (version >= 1),
    updated_by text NOT NULL,
    updated_at timestamptz NOT NULL,
    PRIMARY KEY (tenant_id, number)
);

ALTER TABLE tenant_identity ENABLE ROW LEVEL SECURITY;
ALTER TABLE tenant_identity FORCE ROW LEVEL SECURITY;
ALTER TABLE identity_suspension ENABLE ROW LEVEL SECURITY;
ALTER TABLE identity_suspension FORCE ROW LEVEL SECURITY;
ALTER TABLE number_destination ENABLE ROW LEVEL SECURITY;
ALTER TABLE number_destination FORCE ROW LEVEL SECURITY;

CREATE POLICY tenant_identity_scope ON tenant_identity USING (
    current_setting('app.platform', true) = 'on'
    OR tenant_id = nullif(current_setting('app.tenant_id', true), ''));
CREATE POLICY identity_suspension_scope ON identity_suspension USING (
    current_setting('app.platform', true) = 'on'
    OR tenant_id = nullif(current_setting('app.tenant_id', true), ''));
CREATE POLICY number_destination_scope ON number_destination USING (
    current_setting('app.platform', true) = 'on'
    OR tenant_id = nullif(current_setting('app.tenant_id', true), ''));

GRANT SELECT, INSERT, UPDATE ON tenant_identity TO ${appRole};
GRANT SELECT, INSERT, DELETE ON identity_suspension TO ${appRole};
GRANT SELECT, INSERT, UPDATE, DELETE ON number_destination TO ${appRole};
