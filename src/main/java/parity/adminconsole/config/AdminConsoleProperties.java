package parity.adminconsole.config;

import jakarta.validation.Valid;
import jakarta.validation.constraints.Min;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotEmpty;
import jakarta.validation.constraints.NotNull;
import java.time.Duration;
import java.util.List;
import java.util.Map;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.validation.annotation.Validated;

/** {@code parity-admin-console.*} (application.yml documents each one). */
@Validated
@ConfigurationProperties("parity-admin-console")
public record AdminConsoleProperties(
        @NotNull Environment environment,
        @NotBlank String instance,
        String version,
        @Valid @NotNull Db db,
        @Valid @NotNull Kafka kafka,
        @Valid @NotNull Lifecycle lifecycle,
        @Valid @NotNull Readiness readiness,
        @Valid @NotNull Auth auth,
        @Valid @NotNull Identity identity,
        @Valid @NotNull Tenants tenants,
        @Valid @NotNull Audit audit) {

    /** Where it runs: create-topics and test switches are refused in {@code prod}. */
    public enum Environment { PROD, DEV, TEST }

    /** Passwords from files only: the app role's, and the owner's for Flyway when it runs in the app. */
    public record Db(String passwordFile, String flywayUser, String flywayPasswordFile, @NotBlank String appRole) {}

    public record Kafka(
            @NotBlank String bootstrapServers,
            String username,
            String passwordFile,
            Map<String, String> client,
            @NotBlank String repliesTopic,
            @NotBlank String storeReadTopic,
            @NotBlank String storeAdminTopic,
            // parity-rs (0.16.0): place_tenant on the zone's onboarding topic (Kafka ACL: admin-console only).
            @NotBlank String routingOnboardingTopic,
            @NotNull Duration requestTimeout,
            @NotNull Duration sendTimeout,
            boolean createTopics) {}

    public record Lifecycle(@NotBlank String healthyFile, @NotBlank String drainedFile,
            @NotNull Duration deregistrationDelay, @NotNull Duration drainTimeout) {}

    public record Readiness(@NotNull Duration pollInterval) {}

    /**
     * The token checks (SAML-PLAN rules 5 and 9): one issuer (the global realm), its keys from
     * {@code jwks-uri} (fetched on first use, so Keycloak being down doesn't stop the start), the clients
     * whose tokens the API takes ({@code azp}) and the audience they must carry. No staff organization:
     * a tenant-only console refuses it (user decision D2, 2026-11-03; {@code tenants.reserved-ids}).
     * {@code browser-*}: what the web shell uses to sign in.
     */
    public record Auth(
            @NotBlank String issuer,
            @NotBlank String jwksUri,
            @NotEmpty List<String> clients,
            @NotBlank String audience,
            @NotBlank String browserIssuer,
            @NotBlank String browserClientId) {}

    /**
     * Keycloak's Admin REST API (SAML-PLAN step 4): the service account {@code client-id} signs a JWT
     * with the key in {@code key-file} (no shared secret). {@code tenant-url-template} gives each
     * desktop client's redirect URIs, one per region in {@code regions} (a tenant's home zone may change
     * without touching its client: user decision 2026-10-31).
     */
    public record Identity(
            boolean enabled,
            @NotBlank String keycloakUrl,
            @NotBlank String realm,
            @NotBlank String clientId,
            String keyFile,
            @NotBlank String tenantUrlTemplate,
            @NotEmpty List<String> regions,
            @NotNull Duration applyInterval,
            @NotNull Duration requestTimeout,
            @Min(1) int applyBatch,
            @NotNull Duration backoffMin,
            @NotNull Duration backoffMax,
            boolean checkEnabled,
            @NotBlank String checkCron) {}

    /**
     * Tenants (console step 9): ids no tenant may take (a token whose organization is one is refused;
     * {@code platform} is reserved whatever this says); the residency (and GeoIP's preferred zone, if
     * any) parity-rs places a new tenant by.
     */
    public record Tenants(@NotNull List<String> reservedIds, @NotBlank String residency, String preferredZone) {}

    /** Monthly partitions created this many months ahead, checked at start and then every interval. */
    public record Audit(@Min(1) int partitionsAhead, @NotNull Duration partitionInterval) {}
}
