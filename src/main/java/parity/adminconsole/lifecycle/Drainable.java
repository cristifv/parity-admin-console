package parity.adminconsole.lifecycle;

import java.time.Duration;

/** Work the drain waits for: the Kafka requests in flight (their answered audit rows), the identity jobs. */
public interface Drainable {

    /** Stops taking new work and waits for the work in progress; false if time ran out. */
    boolean drain(Duration timeout) throws InterruptedException;
}
