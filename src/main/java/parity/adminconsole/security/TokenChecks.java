package parity.adminconsole.security;

import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2TokenValidator;
import org.springframework.security.oauth2.core.OAuth2TokenValidatorResult;
import org.springframework.security.oauth2.jwt.Jwt;
import parity.adminconsole.config.AdminConsoleProperties;
import parity.adminconsole.obs.ConsoleMetrics;

/**
 * The checks on a Keycloak access token beyond its signature, issuer and expiry (Spring's own
 * validators run those first): SAML-PLAN multi-tenant rules 5 and 9.
 * <ul>
 *   <li>an access token ({@code typ} {@code Bearer}), never an ID token, with an expiry ({@code exp});</li>
 *   <li>issued to a client this API takes ({@code azp}) and for its audience ({@code aud});</li>
 *   <li>rule 9: a client named for a tenant ({@code desktop-<tenant_id>}) counts only for that tenant;</li>
 *   <li>{@code tenant_id} is a tenant id and the caller's <b>one</b> organization is that tenant (rule 2);</li>
 *   <li>no staff (user decision D2, 2026-11-03: this is the public, tenant-only console): a token that
 *       carries {@code platform-admin} is refused wherever it comes from, and so is one whose
 *       organization is a reserved id, the realm's staff organization {@code platform} among them
 *       ({@link ReservedTenantIds}). Every caller left has exactly its own tenant.</li>
 * </ul>
 * A refused token is answered 401 like any invalid one; the reason is counted, never told.
 */
public final class TokenChecks implements OAuth2TokenValidator<Jwt> {

    static final Pattern TENANT = Pattern.compile("^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$");
    private static final Pattern TENANT_CLIENT = Pattern.compile("^desktop-([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)$");
    private static final OAuth2Error REFUSED = new OAuth2Error("invalid_token", "The token is not accepted here", null);
    /** The realm's staff role: never accepted here (D2). */
    static final String STAFF_ROLE = "platform-admin";

    private final AdminConsoleProperties.Auth auth;
    private final ReservedTenantIds reserved;
    private final ConsoleMetrics metrics;

    public TokenChecks(AdminConsoleProperties.Auth auth, ReservedTenantIds reserved, ConsoleMetrics metrics) {
        this.auth = auth;
        this.reserved = reserved;
        this.metrics = metrics;
    }

    @Override
    public OAuth2TokenValidatorResult validate(Jwt jwt) {
        String reason = refusal(jwt, auth, reserved);
        if (reason == null) {
            return OAuth2TokenValidatorResult.success();
        }
        if (metrics != null) {
            metrics.tokenRefused(reason);
        }
        return OAuth2TokenValidatorResult.failure(REFUSED);
    }

    /** Why the token is refused, or null. */
    static String refusal(Jwt jwt, AdminConsoleProperties.Auth auth, ReservedTenantIds reserved) {
        if (!"Bearer".equals(jwt.getClaimAsString("typ"))) {
            return "typ";
        }
        if (jwt.getExpiresAt() == null) {
            // A token that never expires is never ours (review S1; also refused by the timestamp check).
            return "exp";
        }
        if (jwt.getSubject() == null || jwt.getSubject().isBlank()) {
            return "sub";
        }
        String azp = jwt.getClaimAsString("azp");
        if (azp == null || !auth.clients().contains(azp)) {
            return "azp";
        }
        List<String> aud = jwt.getAudience();
        if (aud == null || !aud.contains(auth.audience())) {
            return "aud";
        }
        if (realmRoles(jwt).contains(STAFF_ROLE)) {
            return "platform_admin";
        }
        String tenant = jwt.getClaimAsString("tenant_id");
        if (tenant == null || !TENANT.matcher(tenant).matches()) {
            return "tenant_id";
        }
        Matcher named = TENANT_CLIENT.matcher(azp);
        if (named.matches() && !named.group(1).equals(tenant)) {
            return "azp_tenant";
        }
        List<String> orgs;
        try {
            orgs = jwt.getClaimAsStringList("organization");
        } catch (RuntimeException e) {
            return "organization";
        }
        if (orgs == null || orgs.size() != 1 || !tenant.equals(orgs.get(0))) {
            return "organization";
        }
        if (reserved.contains(tenant)) {
            // The staff organization, or any id no tenant may have: nobody's tenant, so no access.
            return "reserved_organization";
        }
        return null;
    }

    /** {@code realm_access.roles}, or empty. */
    static Set<String> realmRoles(Jwt jwt) {
        Object access = jwt.getClaims().get("realm_access");
        Set<String> out = new HashSet<>();
        if (access instanceof Map<?, ?> m && m.get("roles") instanceof List<?> list) {
            for (Object o : list) {
                if (o instanceof String s) {
                    out.add(s);
                }
            }
        }
        return out;
    }
}
