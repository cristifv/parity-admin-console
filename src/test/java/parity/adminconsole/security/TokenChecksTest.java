package parity.adminconsole.security;

import static org.assertj.core.api.Assertions.assertThat;

import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.function.Consumer;
import org.junit.jupiter.api.Test;
import org.springframework.security.oauth2.jwt.Jwt;
import parity.adminconsole.config.AdminConsoleProperties;

/**
 * SAML-PLAN rules 5 and 9, the token's own shape, and no staff (user decision D2, 2026-11-03): each
 * refusal reason, and the accepted cases.
 */
class TokenChecksTest {

    private static final AdminConsoleProperties.Auth AUTH = new AdminConsoleProperties.Auth("https://id.example/realms/parity",
            "https://id.example/certs", List.of("admin-console", "desktop-acme"), "admin-console",
            "https://id.example/realms/parity", "admin-console");
    private static final ReservedTenantIds RESERVED = new ReservedTenantIds(List.of("admin", "system"));

    private static Jwt token(Consumer<Map<String, Object>> edit) {
        Map<String, Object> claims = new java.util.HashMap<>(Map.of(
                "typ", "Bearer", "sub", "u-1", "azp", "admin-console", "aud", List.of("admin-console"),
                "tenant_id", "acme", "organization", List.of("acme"),
                "realm_access", Map.of("roles", List.of("tenant-admin", "parity-user"))));
        edit.accept(claims);
        Jwt.Builder b = Jwt.withTokenValue("t").header("alg", "RS256").issuedAt(Instant.now()).expiresAt(Instant.now().plusSeconds(60));
        claims.forEach(b::claim);
        return b.build();
    }

    private static String refusal(Consumer<Map<String, Object>> edit) {
        return TokenChecks.refusal(token(edit), AUTH, RESERVED);
    }

    @Test
    void aTenantAdminsTokenIsAccepted() {
        assertThat(refusal(c -> { })).isNull();
    }

    @Test
    void aTokenWithoutAnExpiryIsRefused() {
        Jwt b = Jwt.withTokenValue("t").header("alg", "RS256").issuedAt(Instant.now()).claim("typ", "Bearer").claim("sub", "u-1")
                .claim("iss", AUTH.issuer()).claim("azp", "admin-console").claim("aud", List.of("admin-console"))
                .claim("tenant_id", "acme").claim("organization", List.of("acme"))
                .claim("realm_access", Map.of("roles", List.of("tenant-admin"))).build();
        assertThat(TokenChecks.refusal(b, AUTH, RESERVED)).isEqualTo("exp");
        // The whole chain (review S1): Spring's timestamp check alone would let it through.
        assertThat(SecurityConfig.validator(AUTH, RESERVED, null).validate(b).hasErrors()).isTrue();
        assertThat(SecurityConfig.validator(AUTH, RESERVED, null).validate(token(c -> c.put("iss", AUTH.issuer()))).hasErrors()).isFalse();
    }

    @Test
    void anIdTokenIsRefused() {
        assertThat(refusal(c -> c.put("typ", "ID"))).isEqualTo("typ");
    }

    @Test
    void anotherClientOrAudienceIsRefused() {
        assertThat(refusal(c -> c.put("azp", "account-console"))).isEqualTo("azp");
        assertThat(refusal(c -> c.remove("azp"))).isEqualTo("azp");
        assertThat(refusal(c -> c.put("aud", List.of("account")))).isEqualTo("aud");
    }

    @Test
    void rule9_aClientNamedForATenantCountsForThatTenantOnly() {
        assertThat(refusal(c -> c.put("azp", "desktop-acme"))).isNull();
        assertThat(refusal(c -> {
            c.put("azp", "desktop-acme");
            c.put("tenant_id", "globex");
            c.put("organization", List.of("globex"));
        })).isEqualTo("azp_tenant");
    }

    @Test
    void rule2_theTenantIsTheOneOrganization() {
        assertThat(refusal(c -> c.remove("tenant_id"))).isEqualTo("tenant_id");
        assertThat(refusal(c -> c.put("tenant_id", "Not_A_Tenant"))).isEqualTo("tenant_id");
        assertThat(refusal(c -> c.put("organization", List.of("globex")))).isEqualTo("organization");
        assertThat(refusal(c -> c.put("organization", List.of("acme", "globex")))).isEqualTo("organization");
        assertThat(refusal(c -> c.remove("organization"))).isEqualTo("organization");
    }

    /** D2: platform-admin is refused wherever it comes from, alone or beside a tenant role. */
    @Test
    void aTokenCarryingPlatformAdminIsRefused() {
        assertThat(refusal(c -> c.put("realm_access", Map.of("roles", List.of("platform-admin"))))).isEqualTo("platform_admin");
        assertThat(refusal(c -> c.put("realm_access", Map.of("roles", List.of("tenant-admin", "platform-admin")))))
                .isEqualTo("platform_admin");
        // The staff token as it was before D2: the platform organization, platform-admin.
        assertThat(refusal(c -> {
            c.put("tenant_id", "platform");
            c.put("organization", List.of("platform"));
            c.put("realm_access", Map.of("roles", List.of("platform-admin")));
        })).isEqualTo("platform_admin");
        // Through the whole chain, issuer and timestamps passing.
        assertThat(SecurityConfig.validator(AUTH, RESERVED, null).validate(token(c -> {
            c.put("iss", AUTH.issuer());
            c.put("realm_access", Map.of("roles", List.of("platform-admin")));
        })).hasErrors()).isTrue();
    }

    /** D2: the staff organization, or any reserved id, is nobody's tenant: refused whatever the roles. */
    @Test
    void aTokenOfTheStaffOrganizationOrAReservedIdIsRefused() {
        for (String org : List.of("platform", "admin", "system")) {
            assertThat(refusal(c -> {
                c.put("tenant_id", org);
                c.put("organization", List.of(org));
            })).as(org).isEqualTo("reserved_organization");
            assertThat(refusal(c -> {
                c.put("tenant_id", org);
                c.put("organization", List.of(org));
                c.put("realm_access", Map.of("roles", List.of("supervisor")));
            })).as(org).isEqualTo("reserved_organization");
        }
        // "platform" is reserved even when the setting leaves it out.
        assertThat(TokenChecks.refusal(token(c -> {
            c.put("tenant_id", "platform");
            c.put("organization", List.of("platform"));
        }), AUTH, new ReservedTenantIds(List.of()))).isEqualTo("reserved_organization");
        assertThat(SecurityConfig.validator(AUTH, RESERVED, null).validate(token(c -> {
            c.put("iss", AUTH.issuer());
            c.put("tenant_id", "platform");
            c.put("organization", List.of("platform"));
        })).hasErrors()).isTrue();
    }

    @Test
    void aTokenWithoutASubjectIsRefused() {
        assertThat(refusal(c -> c.remove("sub"))).isEqualTo("sub");
    }
}
