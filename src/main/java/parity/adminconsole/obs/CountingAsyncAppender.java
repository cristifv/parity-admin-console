package parity.adminconsole.obs;

import ch.qos.logback.classic.AsyncAppender;
import ch.qos.logback.classic.spi.ILoggingEvent;
import java.util.concurrent.atomic.AtomicLong;

/**
 * Logback's {@link AsyncAppender} with {@code neverBlock}: a full queue drops the line instead
 * of making the caller wait (a request must never wait on stdout). The drops are
 * counted here and exported as {@code admin_log_lines_dropped_total}. The count
 * is taken when the queue is seen full, so it can be off by the few lines raced in parallel.
 */
public class CountingAsyncAppender extends AsyncAppender {

    private static final AtomicLong DROPPED = new AtomicLong();

    public static long dropped() {
        return DROPPED.get();
    }

    @Override
    protected void append(ILoggingEvent event) {
        if (isStarted() && getRemainingCapacity() == 0) {
            DROPPED.incrementAndGet();
        }
        super.append(event);
    }
}
