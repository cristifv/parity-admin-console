package parity.adminconsole;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.context.properties.ConfigurationPropertiesScan;
import org.springframework.context.ConfigurableApplicationContext;
import org.springframework.scheduling.annotation.EnableScheduling;
import parity.adminconsole.lifecycle.ExitCodes;
import parity.adminconsole.lifecycle.ShutdownSignals;

/**
 * parity-admin-console: admin-api and the admin console (ARCH §3.9, PLAN.md), one deployable. Exit
 * codes: 0 drained, 1 failed (or not drained in time), 2 configuration, 128 + n on a second signal.
 */
@SpringBootApplication
@ConfigurationPropertiesScan
@EnableScheduling
public class ParityAdminConsoleApplication {

    public static void main(String[] args) {
        ShutdownSignals.install();
        ConfigurableApplicationContext context;
        try {
            context = new SpringApplication(ParityAdminConsoleApplication.class).run(args);
        } catch (Throwable failure) {
            System.exit(ExitCodes.forStartupFailure(failure));
            return;
        }
        ShutdownSignals.started(context);
    }
}
