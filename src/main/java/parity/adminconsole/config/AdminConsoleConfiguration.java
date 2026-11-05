package parity.adminconsole.config;

import com.zaxxer.hikari.HikariDataSource;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Clock;
import org.springframework.beans.factory.config.BeanPostProcessor;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import javax.sql.DataSource;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.flyway.autoconfigure.FlywayDataSource;
import org.springframework.boot.flyway.autoconfigure.FlywayMigrationStrategy;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.env.Environment;
import parity.adminconsole.contracts.Schemas;
import parity.adminconsole.lifecycle.ConfigurationRefusedException;

/**
 * The shared beans: the clock, the contracts' schemas, the database passwords from files (the app
 * role's for the pool, the owner's for Flyway when the migration runs in the app), and the start-up
 * refusals (exit 2).
 */
@Configuration
public class AdminConsoleConfiguration {

    @Bean
    @ConditionalOnMissingBean
    Clock clock() {
        return Clock.systemUTC();
    }

    @Bean
    Schemas schemas(AdminConsoleProperties properties) {
        if (properties.kafka().createTopics() && properties.environment() == AdminConsoleProperties.Environment.PROD) {
            throw new ConfigurationRefusedException("parity-admin-console.kafka.create-topics is for dev and test only");
        }
        if (properties.identity().enabled() && (properties.identity().keyFile() == null || properties.identity().keyFile().isBlank())) {
            throw new ConfigurationRefusedException("parity-admin-console.identity.key-file is required when identity is enabled");
        }
        return new Schemas();
    }

    /** {@code parity-admin-console.db.password-file}: the app role's password from a file, never logged. */
    @Bean
    static BeanPostProcessor databasePasswordFile(Environment environment) {
        return new BeanPostProcessor() {
            @Override
            public Object postProcessBeforeInitialization(Object bean, String beanName) {
                String file = environment.getProperty("parity-admin-console.db.password-file");
                if (bean instanceof HikariDataSource ds && !"flyway".equals(ds.getPoolName()) && file != null && !file.isBlank()) {
                    ds.setPassword(read(file));
                }
                return bean;
            }
        };
    }

    /**
     * Flyway as the owner role, when {@code parity-admin-console.db.flyway-user} is set (local-dev, tests):
     * its own small pool, its password from {@code db.flyway-password-file}. Deployments run the migration
     * apart and set {@code spring.flyway.enabled: false}. Not a default candidate, so the app's own pool
     * (the app role) stays the one everything else gets.
     */
    @Bean(defaultCandidate = false)
    @FlywayDataSource
    @ConditionalOnProperty("parity-admin-console.db.flyway-user")
    DataSource flywayDataSource(Environment environment) {
        HikariDataSource ds = new HikariDataSource();
        ds.setPoolName("flyway");
        ds.setJdbcUrl(environment.getRequiredProperty("spring.datasource.url"));
        ds.setUsername(environment.getRequiredProperty("parity-admin-console.db.flyway-user"));
        String file = environment.getProperty("parity-admin-console.db.flyway-password-file");
        if (file != null && !file.isBlank()) {
            ds.setPassword(read(file));
        }
        ds.setMaximumPoolSize(2);
        return ds;
    }

    /**
     * Flyway runs only as the owner (review F7): with {@code parity-admin-console.db.flyway-user} set
     * (local-dev, tests). Without it, the app role's pool would be Flyway's: a deployment migrates apart,
     * and the app never tries DDL as the app role.
     */
    @Bean
    FlywayMigrationStrategy migrateOnlyAsOwner(Environment environment) {
        return flyway -> {
            String owner = environment.getProperty("parity-admin-console.db.flyway-user");
            if (owner != null && !owner.isBlank()) {
                flyway.migrate();
            } else {
                org.slf4j.LoggerFactory.getLogger(AdminConsoleConfiguration.class).atInfo()
                        .addKeyValue("event", "db.migrations_skipped").log("migrations not run here: parity-admin-console.db.flyway-user isn't set");
            }
        };
    }

    private static String read(String file) {
        try {
            return Files.readString(Path.of(file), StandardCharsets.UTF_8).strip();
        } catch (IOException e) {
            throw new ConfigurationRefusedException("a database password file can't be read");
        }
    }
}
