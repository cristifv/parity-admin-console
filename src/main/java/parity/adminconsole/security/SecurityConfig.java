package parity.adminconsole.security;

import java.net.URI;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.oauth2.core.DelegatingOAuth2TokenValidator;
import org.springframework.security.oauth2.core.OAuth2TokenValidator;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtIssuerValidator;
import org.springframework.security.oauth2.jwt.JwtTimestampValidator;
import org.springframework.security.oauth2.jose.jws.SignatureAlgorithm;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtValidators;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;
import parity.adminconsole.config.AdminConsoleProperties;
import parity.adminconsole.obs.ConsoleMetrics;

/**
 * PLAN.md "Security and tenancy": every {@code /api} request carries a Keycloak access token (bearer,
 * so no cookies, no CSRF tokens and no session); the token's signature (RS256, the realm's keys fetched
 * on first use and again on an unknown key id), issuer, expiry and {@link TokenChecks} are checked
 * (a staff token is refused there: user decision D2, 2026-11-03); then a console role is required,
 * {@code tenant-admin} or {@code supervisor}: no role, or only {@code agent}, is 403 (rule 5: no role
 * means no access). The web shell is static and public; its Content-Security-Policy lets it talk to
 * this origin and to Keycloak only.
 */
@Configuration
public class SecurityConfig {

    @Bean
    JwtDecoder jwtDecoder(AdminConsoleProperties properties, ReservedTenantIds reserved, ConsoleMetrics metrics) {
        NimbusJwtDecoder decoder = NimbusJwtDecoder.withJwkSetUri(properties.auth().jwksUri())
                .jwsAlgorithm(SignatureAlgorithm.RS256).build();
        decoder.setJwtValidator(validator(properties.auth(), reserved, metrics));
        return decoder;
    }

    /**
     * Spring's default checks with the issuer, where a token must carry {@code exp} (Spring allows a
     * token without one by default: review S1), then {@link TokenChecks}.
     */
    static OAuth2TokenValidator<Jwt> validator(AdminConsoleProperties.Auth auth, ReservedTenantIds reserved, ConsoleMetrics metrics) {
        JwtTimestampValidator timestamps = new JwtTimestampValidator();
        timestamps.setAllowEmptyExpiryClaim(false);
        return new DelegatingOAuth2TokenValidator<>(
                JwtValidators.createDefaultWithValidators(java.util.List.of(timestamps, new JwtIssuerValidator(auth.issuer()))),
                new TokenChecks(auth, reserved, metrics));
    }

    @Bean
    @Order(1)
    SecurityFilterChain api(HttpSecurity http, JwtDecoder decoder) throws Exception {
        http.securityMatcher("/api/**")
                .authorizeHttpRequests(a -> a
                        .requestMatchers(HttpMethod.GET, "/api/config").permitAll()
                        .anyRequest().hasAnyRole(Role.TENANT_ADMIN.claim(), Role.SUPERVISOR.claim()))
                .oauth2ResourceServer(o -> o.jwt(j -> j.decoder(decoder).jwtAuthenticationConverter(new CallerAuthentication.FromJwt())))
                .sessionManagement(s -> s.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .csrf(c -> c.disable())
                .requestCache(c -> c.disable())
                .headers(h -> h.contentSecurityPolicy(c -> c.policyDirectives("default-src 'none'; frame-ancestors 'none'")));
        return http.build();
    }

    @Bean
    @Order(2)
    SecurityFilterChain web(HttpSecurity http, AdminConsoleProperties properties) throws Exception {
        URI issuer = URI.create(properties.auth().browserIssuer());
        String keycloak = issuer.getScheme() + "://" + issuer.getAuthority();
        http.authorizeHttpRequests(a -> a.anyRequest().permitAll())
                .sessionManagement(s -> s.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .csrf(c -> c.disable())
                .requestCache(c -> c.disable())
                .headers(h -> h.contentSecurityPolicy(c -> c.policyDirectives(
                        "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self'; connect-src 'self' "
                                + keycloak + "; frame-ancestors 'none'; base-uri 'none'; form-action 'self' " + keycloak)));
        return http.build();
    }

    /** None: logins are Keycloak's. Declared so Spring Boot makes no default user with a logged password. */
    @Bean
    UserDetailsService noUsers() {
        return new InMemoryUserDetailsManager();
    }
}
