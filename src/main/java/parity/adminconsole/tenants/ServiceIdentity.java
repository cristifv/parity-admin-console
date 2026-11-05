package parity.adminconsole.tenants;

import parity.adminconsole.audit.AuditLog;

/**
 * The service identities that may run a tenant's lifecycle, never a person's token (user decisions
 * D1-D2, 2026-11-03: admin-console is the public, tenant-only tool, and no HTTP route creates or
 * deletes a tenant, or assigns its numbers and SIP domains). Each is the consumer of one narrow Kafka
 * topic whose ACL names its only writer; it isn't built yet. The audit rows name the identity as
 * {@code system:<name>}. Staff operations (suspension) are an {@link OpsActor}'s.
 */
public enum ServiceIdentity {
    /**
     * parity-billing's provisioning: the consumer of {@code admin.provisioning.requests} (writer
     * parity-billing only; CONVENTIONS "Provisioning"). Creates tenants and their first admin, assigns
     * numbers and SIP domains, and deletes a tenant at the end of billing's deprovision saga (account
     * closure, by the tenant's admin or by staff: coordinator ruling 3).
     */
    PROVISIONING("provisioning");

    private final String system;

    ServiceIdentity(String system) {
        this.system = system;
    }

    /** The audit log's actor: {@code system:<name>}. */
    public AuditLog.Actor actor() {
        return AuditLog.Actor.system(system);
    }

    /** Refuses any other identity: a wiring mistake, never a caller's input. */
    void require(ServiceIdentity allowed) {
        if (this != allowed) {
            throw new IllegalArgumentException("this tenant operation isn't this service identity's");
        }
    }
}
