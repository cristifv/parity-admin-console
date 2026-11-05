# parity-admin-console: the admin console

parity-admin-console is the **tenants' own web UI**, public and tenant-only
(`../../contact-center-architecture/ARCHITECTURE.md` §3.9), together with **the API behind it**
(admin-api in the docs). Tenant admins configure their contact center; supervisors run it.
Every action is checked against the person's role and written to an audit log.

**Decided 2026-11-03 (the user):** after a tenant pays or starts a trial, billing's
provisioning saga creates the tenant (a service identity), and the tenant admin logs in and
configures their contact center (D1). Every staff and platform-admin function is in
parity-cc-tools, the private internal tool on the realm `ops` (D2): every-tenant views, manual
onboarding, suspension, billing's money commands, the signal feed, GeoIP lookups, the
cross-tenant audit. The console has no `platform` organization role and no platform-wide
endpoint. Support access is a read-only, audited view in parity-cc-tools; staff never edit tenant
config (D3). The code change is planned, not built. `PLAN.md` is newer than this file: where
this file names `platform-admin` below, it records the first plan.

**Status:** plan only, no code yet (2026-10-17). This file holds the assessment of the
architecture docs for the admin console, and the plan. Everything below marked *proposed*
is open to change.

**Changed since (2026-10-21):** parity-customer-context, one of this plan's backends, is gone.
- **What happened:** it was renamed parity-cc-mcp on 2026-10-19 and its code was dropped.
  customer-context (`ARCHITECTURE.md` §3.13) gets built later, from scratch.
- **What it breaks here:** the supervisor consultations (`consultation.requested`, `resolve`)
  in the backends table, finding 10, plan step 4 and the `/api/.../consultations` routes.
- **What took their place:** AI agents now hand a case to a supervisor with
  `parity_ask_person` (parity-cc-mcp, `ARCHITECTURE.md` §3.23), and the person's answer is
  final. How a supervisor sees and answers those questions isn't designed yet; it's an open
  question in `ARCHITECTURE.md` §10.
- **What's unchanged:** the rest of this plan.

## Requirements so far

From the user:
1. A new service in its own directory in `~/Repos`, starting with an assessment of the
   architecture and a plan.

From the platform's standing rules:
- Java services use Maven, Spring Boot and Lombok, in annotation style.
- Every service creates `/tmp/<service>.healthy` and `/tmp/<service>.drained` (§7.3).
- The message conventions of the other parity services (`cmd`, `id`, `reply_to`, `ok`).

## Assessment of the architecture for the admin console

### What the docs ask for

- **§3.9** lists 24 areas the console controls: platform, media fleet, bins and cells,
  tenants, numbers, routing, IVR, agents, live ops, recordings, CPaaS, channels, experience,
  analytics, privacy, billing, team chat, agentanalytics, signals, event calendar, goals and
  authority, lookup tools, and audit.
- **Roles:** `tenant-admin`, `supervisor`, `agent` (`platform-admin` goes, D2). The `tenant_id` comes
  from a Keycloak JWT claim that every service checks (§5.1).
- **How changes flow:**
  - a config change goes to Postgres first, then a `config.*` event lets the zone services
    reload;
  - an operational command (drain, failover, kill call, move a tenant) goes to the service
    that owns it, and is audited;
  - live data is streamed from Redpanda to the browser over WebSocket.
- **What admin-api owns:** the audit log (24 months, global Postgres, §5.2), the tenant event
  calendar, and the goals and authority model. In v1 it also carries billing (seats),
  privacy and the caller-history screen pop as modules (§9.1).
- **v1 scope (§9.1):**
  - tenants, numbers, queues, skills and agents;
  - a form-based IVR editor;
  - the live wallboard;
  - listen, whisper and barge;
  - force logout;
  - the audit log.
- **Flows:** onboarding (§6.11.1), a config change going live (§6.11.2), draining a media
  node (§6.11.3), troubleshooting a call with Homer (§6.11.6), bin and cell moves (§7.8,
  §7.9).

### What exists to control today

| Service | State | API | What the console can do with it |
|---|---|---|---|
| parity-rs | Built | Kafka, `tenant.routing.*` | List, view, set and delete a tenant's zone, cell, deployment unit and home zone; `route.changed` live |
| parity-store | Design only | Kafka, `tenant.store.*` (planned) | Tenants with tier and parent, placement, numbers, SIP domains |
| parity-geoip | Built | Kafka, `geoip.*` | IP → location, ASN, zones by distance |
| ~~parity-customer-context~~ | Dropped 2026-10-19 (see above) | Kafka, `customer.context.*` | Was: the supervisors' queue of consultations. Now: questions on cases from AI agents, once customer-context is built |
| parity-signal-detection | Built | Kafka, `signals` out | A live signal feed. Its settings are static YAML, so nothing to change from the console |
| parity-ms | Built | TCP control, no authentication; its own API to come | `list`, `stats`, `query`; `set_mode` for listen, whisper and barge |
| Everything else in §3.9 | Not built | | interaction-engine, routing-engine, agent-gateway, billing, privacy, keycloak setup |

### Findings

1. **The v1 console in §9.1 depends on services that don't exist yet.**
   - Queues, skills and agents belong to routing-engine.
   - The IVR editor compiles for interaction-engine.
   - The wallboard and force logout need routing-engine and agent-gateway.
   - Listen, whisper and barge need interaction-engine to drive parity-ms.

   So the first console can only manage what's built: **tenants and where they live**, and
   **supervisor consultations**. It grows one area per backend as they're built.
2. **The interfaces don't match.** The docs say the console calls admin-api over REST, and
   admin-api calls the owning services over gRPC/REST, with contracts in `proto/`. Every
   built parity service has a **Kafka request/response API** instead, and parity-ms has TCP.
   - admin-api is the first service that calls the others and waits for an answer. It needs
     a Kafka request/reply client that matches responses by `id`, with a timeout.
   - The browser side stays HTTPS and WebSocket.
3. **Who owns the tenant is unclear.** §3.9, §4.1 and §6.11.1 have admin-api write tenants,
   numbers and the home and failover zone to global Postgres. You decided that parity-store
   owns where tenants live. *Proposed split:*
   - **parity-store:** the tenant's id, name, tier and parent, its placement, its numbers and
     its SIP domains;
   - **admin-api:** the tenant's status (active, suspended), plan and limits, contacts, API
     keys, each number's destination (IVR flow, queue, CPaaS webhook), and the audit log.
4. **There are three ways to move a tenant:** parity-rs `set_route`, parity-store
   `set_placement` (planned), and a zone service's bin moves (§3.20, not built). The
   console's "Move tenant" needs one owner. This is the open question already in parity-rs
   and parity-store. **Answered (2026-11-02 and 2026-11-03):** parity-rs decides and executes
   every move (the zone service was folded into it), parity-store stores, and operators move
   tenants in parity-cc-tools, not in this console.
5. **Onboarding asks GeoIP for "the nearest zone for the tenant"** from an address
   (§6.11.1). parity-geoip only takes IP addresses (its open question 1). *Proposed:* the
   admin picks the home zone from a list. GeoIP is offered as a lookup tool on an IP address.
6. **The Kafka APIs have no authentication or authorization.** Anyone who can write to
   `tenant.routing.requests` can move a tenant, and parity-ms's control port is open (§10).
   The console's roles only protect anything if the request topics are writable by
   admin-api and the named services alone: Kafka ACLs with SASL on Redpanda.
7. **Live events must be filtered per tenant before they reach a browser.** Events come
   from Redpanda for every tenant. A tenant-admin or supervisor must only see their own
   tenant's events. Signals may have no `tenant_id` (`X-Tenant-ID` is optional in
   signal-detection), so they never reach the console (the signal feed is parity-cc-tools', D2).
8. **Global or zone.** admin-api is global in the docs, but §9.1 drops the global control
   plane until there's a second zone. So v1 runs in the one zone, with one Postgres and one
   Redpanda.
   - Later, customer-context and signal-detection run per zone and per bin. A global
     admin-api then has to reach the tenant's own zone and bin: "a shared service calling a
     binned one looks up the tenant's bin first" (§7.8).
9. **A slow answer isn't a failed change.** parity-rs retries a request on a Postgres or
   Kafka failure until it works, so a change can land after the console stopped waiting.
   - The console reports a timeout as **"not confirmed"**, not "failed".
   - The live event shows the real outcome.
   - `set_route` is idempotent, so trying again is safe.
10. **Nobody shows supervisors their consultations yet.** customer-context sends
    `consultation.requested` to "the agent or the supervisor", but neither agent-desktop nor
    agentanalytics' cockpit exists. The console's supervisor role is the natural first home
    for them.
11. **The Signals area has nothing to talk to.** §3.19 says signal settings arrive as
    `config.*` events. signal-detection reads its phrase lists and thresholds from
    `application.yml` only.
12. **The docs are out of date on the stack.** §7 says Spring Boot 3; the built services use
    Spring Boot 4.1. §8 puts admin-api in a Gradle multi-module `services-java/` and the
    console in `web/`. Each parity service is its own Maven repo.
13. **Draining a web service means WebSockets.** On SIGTERM the instance has to close its
    WebSockets so browsers reconnect to another instance (with jitter, as §10 asks for
    Cloudflare resets), and wait for its Kafka requests in flight.

### Verdict

The docs have the right **shape** for the console: one UI and one API, config to Postgres
first and then `config.*` events, commands to the owning service, an audit log, and live
data over WebSocket. But §3.9 is a list of 24 areas over about 20 services, most of them not
built. Build the console as a **thin shell that grows one area per backend**. Start with
what exists: the services' health, tenants and their placement, the audit log, and
supervisor consultations.

Three decisions are needed before the tenant screens can write anything: the tenant split
(finding 3), one owner for moving a tenant (finding 4), and Kafka ACLs (finding 6).

## The plan

### Shape (proposed)

**One deployable:** a Spring Boot application that serves the API and the built React app,
from one origin (no CORS) with one healthy file. The catalog's two names, admin-api and
admin-console, are its two halves. They can split later if they need to scale differently.

```
browser: React app ──HTTPS (REST) + WebSocket──▶ parity-admin-console (Spring Boot)
   │                                               │  Postgres: audit log
   └── login: Keycloak (OIDC, PKCE)                │  JWT check on every request
                                                   │
                         Kafka request/reply  ◀────┤────▶ parity-store, parity-rs,
                         (admin.console.replies)   │      parity-geoip, parity-customer-context
                                                   │
                         Kafka events  ────────────┘  tenant.routing.events, tenant.store.events,
                         (filtered per tenant → WS)   customer.context.events, signals
```

### Stack (proposed)

| Part | Choice |
|---|---|
| API | Java 21, Spring Boot 4.1, Maven, Lombok; Spring Web MVC, Spring WebSocket, Spring Security (OAuth2 resource server for Keycloak JWTs), Spring Kafka, Spring Data JPA, Flyway, Bean Validation |
| Store | PostgreSQL: the audit log, and later the tenant settings admin-api owns |
| Web app | React and TypeScript (§7), built with Vite, in `web/`. The Maven build runs the web build (frontend-maven-plugin) and puts it in the jar |
| Login | Keycloak: the browser logs in with OIDC and PKCE; the API checks the JWT and reads the roles and `tenant_id` |
| Tests | Embedded Kafka, Postgres in Testcontainers, as the other services do |

### Steps (proposed)

Each step is small. Stop after each one for your details, as with the other services.

| # | Step | Uses | Done when |
|---|---|---|---|
| 0 | **Skeleton:** the Spring Boot app, healthy and drained files, the Kafka request/reply client, login, and a **Services** page that pings every backend | All built services (`ping`) | The page shows which services answer, and how fast |
| 1 | **Tenants, read only:** the tenant list and a tenant's placement; live updates | parity-rs `list_routes`, `get_route`; `route.changed` | A route changed elsewhere shows up without a reload |
| 2 | **Audit log:** a row for every action, and a page to search it | Postgres | Every write in step 3 is in it, with who, what, when and the result |
| 3 | ~~**Tenants, write**~~: placement changes are parity-cc-tools' (2026-11-03) | — | — |
| 4 | **Supervisor consultations:** the waiting list, live arrivals, resolve, notes, the customer's record | parity-customer-context | A `consultation.requested` appears live and can be resolved |
| 5 | ~~**GeoIP lookup**~~: parity-cc-tools' (D2, 2026-11-03) | — | — |
| 6 | **parity-store:** tenants with tier and parent, numbers and SIP domains | parity-store, once it's built | Steps 1 and 3 read and write through parity-store |

**Later, each with its backend:** queues, skills and agents (routing-engine); the IVR editor
(interaction-engine); the wallboard and force logout (agent-gateway); listen, whisper and
barge (interaction-engine + parity-ms); billing; privacy; signal settings; the event
calendar; goals and authority. The media fleet, bins and cells went to parity-cc-tools
(2026-11-03).

### Browser API (proposed)

| Method and path | For | Roles |
|---|---|---|
| `GET /api/me` | The person's name, roles and tenant | all |
| `GET /api/services` | ~~Each backend's `ping`~~: parity-cc-tools' (D2) | — |
| `GET /api/tenants/{id}` | The tenant and its placement (read only) | tenant-admin (own tenant) |
| `GET /api/audit?actor=&action=&from=&to=` | Search the tenant's audit log | tenant-admin (own tenant) |
| `GET /api/tenants/{id}/consultations?status=` | Consultations | supervisor, tenant-admin (own tenant) |
| `POST /api/consultations/{id}/resolve` | Resolve with summary, risk and action | supervisor |
| `POST /api/tenants/{id}/notes`, `GET /api/tenants/{id}/customers/{key}` | Notes; a customer's signals, notes and assessments | supervisor |
| `WS /api/live` | Live events, filtered to what the person may see | all |

- **Identity comes from the token, never from the form.** customer-context's `by` and
  `role` on `resolve` and `add_note` are filled in from the JWT.
- **Errors:** a backend's `bad_request` → 400, `not_found` → 404, `conflict` → 409,
  `internal` → 502; no answer in time → 504 with `not_confirmed`.

### Kafka request/reply (proposed)

- **One reply topic, `admin.console.replies`,** read in full by every instance (all
  partitions, no consumer group, from the latest offset).
- Each request's `id` is `<instance-id>:<uuid>`. An instance keeps only the replies whose
  id it's waiting for, and drops the rest.
- **Why not a topic per instance:** the parity services don't create `reply_to` topics, so
  each instance would need its own topic created and removed by the orchestrator.
- **Timeout:** 5 s by default, per request.
- **Requests in flight** are tracked in a map of id → future, so a drain can wait for them.

### Audit log (proposed)

```sql
CREATE TABLE audit_log (
    id          uuid PRIMARY KEY,         -- UUIDv7
    at          timestamptz NOT NULL,
    actor       text NOT NULL,            -- the JWT subject
    actor_roles text[] NOT NULL,
    tenant_id   text,                     -- null for platform-wide actions
    action      text NOT NULL,            -- e.g. placement.set, consultation.resolve
    target      text,                     -- e.g. the tenant or consultation id
    request     jsonb NOT NULL,           -- what was asked, without secrets
    outcome     text NOT NULL CHECK (outcome IN ('ok', 'error', 'not_confirmed')),
    error_code  text
);
CREATE INDEX ON audit_log (tenant_id, at);
CREATE INDEX ON audit_log (actor, at);
```

- Written when the backend answers or the request times out.
- Kept 24 months (§5.2); old rows are removed by a monthly job, or the table is
  range-partitioned by month like the CDR tables (§4.1).

### Roles (proposed)

| Role | In the console |
|---|---|
| `tenant-admin` | Their own tenant: its placement (read only), its audit log, its consultations |
| `supervisor` | Their own tenant's consultations, notes and customer records |
| `agent` | Nothing: agents use agent-desktop. Consultations sent `to: agent` wait for it |

### Startup and graceful shutdown

- `/tmp/parity-admin-console.healthy` after startup; `/tmp/parity-admin-console.drained`
  after a drain; both removed at startup.
- **On SIGTERM:**
  1. remove the healthy file and stop taking new requests;
  2. close every WebSocket with code 1001 ("going away"), so the browsers reconnect to
     another instance after a random delay;
  3. wait for the Kafka requests in flight to be answered or to time out;
  4. create the drained file.
- 30 s drain timeout and a 45 s grace period, as for the other Java services.

### Settings (proposed)

| Setting | Default |
|---|---|
| `parity-admin-console.replies-topic` | `admin.console.replies` |
| `parity-admin-console.request-timeout` | `5s` |
| `parity-admin-console.backends.<name>.requests-topic` | `tenant.routing.requests`, `geoip.requests`, `customer.context.requests` (and `tenant.store.requests` later) |
| `parity-admin-console.live.topics` | `tenant.routing.events`, `customer.context.events`, `signals` |
| `parity-admin-console.lifecycle.healthy-file` / `drained-file` / `drain-timeout` | `/tmp/parity-admin-console.healthy` / `.drained` / `30s` |
| `spring.security.oauth2.resourceserver.jwt.issuer-uri` | The Keycloak realm |

## Architecture docs to update (when you say so)

- §3.9 and the catalog: built as `parity-admin-console`, one deployable with both halves,
  Kafka to the backends.
- §4.1 and §6.11.1: tenants, numbers and placement in parity-store; admin-api's part.
- §7 (Spring Boot 4.1) and §8 (its own Maven repo).
- §10: Kafka ACLs on the request topics.

## Open questions

1. **The name and the shape:** is `parity-admin-console` right? Is one deployable (API and
   web app together) fine, or do you want admin-api and admin-console as two services, as
   in the catalog?
2. **The tenant split** between parity-store and admin-api (finding 3).
3. **One owner for moving a tenant:** parity-rs, parity-store or the zone's bin service
   (finding 4). **Answered:** parity-rs decides and executes (2026-11-02 and 2026-11-03).
4. **Login in the first steps:** Keycloak from the start (a container for development), or a
   development login first and Keycloak later?
5. **Kafka ACLs:** now, as part of step 0, or later (finding 6)?
6. **Supervisor consultations** in the console until agentanalytics' cockpit exists
   (finding 10)?
7. **parity-ms:** should the console talk to it at all before its own API exists? Its TCP
   control has no authentication.
8. **The first slice:** is step 0 (Services page) then step 1 (tenants, read only) the right
   start?
9. **The web app:** plain React, or a component library (MUI, Mantine…)?
10. **Drains:** coordinated between instances over Kafka like parity-rs, or only the two
    files?
11. **Zones:** v1 as one zone and one Redpanda, with a global admin-api only once there's a
    second zone?
