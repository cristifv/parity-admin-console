package parity.adminconsole.security;

import java.util.List;
import java.util.Set;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;
import parity.adminconsole.config.AdminConsoleProperties;

/**
 * Ids no tenant may have ({@code parity-admin-console.tenants.reserved-ids}), and the realm's staff
 * organization ({@value #STAFF_ORGANIZATION}, Keycloak-as-code's), reserved whatever the setting says.
 * No tenant is ever created with one, so a token whose organization is one is nobody's tenant and is
 * refused ({@link TokenChecks}); the identity jobs never apply one and disable an account that names one.
 */
@Component
public class ReservedTenantIds {

    /** The realm's staff organization (parity-deploy's realm-parity.json): never a tenant's. */
    public static final String STAFF_ORGANIZATION = "platform";

    private final Set<String> ids;

    @Autowired
    public ReservedTenantIds(AdminConsoleProperties properties) {
        this(properties.tenants().reservedIds());
    }

    public ReservedTenantIds(List<String> configured) {
        this.ids = Set.copyOf(configured);
    }

    public boolean contains(String tenantId) {
        return STAFF_ORGANIZATION.equals(tenantId) || ids.contains(tenantId);
    }
}
