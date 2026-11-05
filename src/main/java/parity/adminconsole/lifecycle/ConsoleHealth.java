package parity.adminconsole.lifecycle;

import org.springframework.boot.health.contributor.Health;
import org.springframework.boot.health.contributor.HealthIndicator;
import org.springframework.stereotype.Component;

/** {@code /readyz}: the readiness checks pass and no drain has started. */
@Component("console")
public class ConsoleHealth implements HealthIndicator {

    private final LifecycleFiles files;

    public ConsoleHealth(LifecycleFiles files) {
        this.files = files;
    }

    @Override
    public Health health() {
        return files.ready() ? Health.up().build() : Health.down().withDetails(files.failures()).build();
    }
}
