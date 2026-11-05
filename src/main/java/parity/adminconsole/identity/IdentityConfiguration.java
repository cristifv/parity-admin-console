package parity.adminconsole.identity;

import java.time.Clock;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import parity.adminconsole.config.AdminConsoleProperties;

/** Keycloak's Admin REST API, when {@code parity-admin-console.identity.enabled} (local-dev and up). */
@Configuration
public class IdentityConfiguration {

    @Bean
    @ConditionalOnProperty(name = "parity-admin-console.identity.enabled", havingValue = "true")
    KeycloakAdmin keycloakAdmin(AdminConsoleProperties properties, Clock clock) {
        return new KeycloakAdmin(properties, clock);
    }
}
