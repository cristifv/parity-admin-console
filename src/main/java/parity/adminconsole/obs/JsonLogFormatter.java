package parity.adminconsole.obs;

import ch.qos.logback.classic.Level;
import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.classic.spi.IThrowableProxy;
import ch.qos.logback.classic.spi.StackTraceElementProxy;
import java.security.SecureRandom;
import java.time.Instant;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;
import java.util.HexFormat;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.atomic.AtomicLong;
import org.slf4j.event.KeyValuePair;
import org.springframework.boot.logging.structured.StructuredLogFormatter;
import org.springframework.core.env.Environment;

/**
 * log-record.v1 (parity-contracts CONVENTIONS "Logging", 2026-11-03): one JSON object per line, at
 * most 16000 bytes. {@code event} is the call site's {@code event} key-value pair (the catalogue is
 * {@code logging/events.parity-admin-console.v1.json}); a record of this service without one is
 * {@code log.unclassified} (no catalogue lists it: CI refuses it); a library's record is
 * {@code library.logged} with its logger in {@code component}. The correlation fields go to the top
 * level, every other key-value pair and MDC entry to {@code attrs}; every value goes through
 * {@link Pii#maskField}. An exception's message is kept (this service's messages are compile-time
 * constants: the NoDataInMessages check), masked as free text, with the stack at {@code error}.
 */
public class JsonLogFormatter implements StructuredLogFormatter<ILoggingEvent> {

    private static final Set<String> TOP = Set.of("trace_id", "span_id", "tenant_id", "request_id", "command_id",
            "event_id", "op_id", "saga_id", "parent_saga_id", "session_id", "agent_id", "xsid", "op",
            "duration_ms", "attempt", "from_state", "to_state");
    private static final DateTimeFormatter TS =
            DateTimeFormatter.ofPattern("yyyy-MM-dd'T'HH:mm:ss.SSS'Z'").withZone(ZoneOffset.UTC);
    private static final AtomicLong SEQ = new AtomicLong();
    private static final String INCARNATION;

    static {
        byte[] b = new byte[6];
        new SecureRandom().nextBytes(b);
        INCARNATION = HexFormat.of().formatHex(b);
    }

    private final String service;
    private final String version;
    private final String instance;

    public JsonLogFormatter(Environment environment) {
        this.service = environment.getProperty("spring.application.name", "parity-admin-console");
        this.version = environment.getProperty("parity-admin-console.version", "unknown");
        this.instance = environment.getProperty("parity-admin-console.instance", "unknown");
    }

    @Override
    public String format(ILoggingEvent event) {
        // Spring Boot logs the start under the application (or test) class's name: a library's record.
        String logger = event.getLoggerName();
        boolean ours = logger.startsWith("parity.adminconsole.") && !logger.endsWith(".ParityAdminConsoleApplication")
                && !logger.startsWith("parity.adminconsole.it.");
        Map<String, Object> line = new LinkedHashMap<>();
        line.put("ts", TS.format(Instant.ofEpochMilli(event.getTimeStamp())));
        line.put("level", level(event.getLevel()));
        line.put("service", service);
        line.put("version", version);
        line.put("instance", instance);
        line.put("incarnation", INCARNATION);
        line.put("seq", SEQ.incrementAndGet());
        Map<String, Object> attrs = new LinkedHashMap<>();
        String name = null;
        List<KeyValuePair> pairs = event.getKeyValuePairs();
        Map<String, Object> top = new LinkedHashMap<>();
        if (pairs != null) {
            for (KeyValuePair p : pairs) {
                if (p.value == null) {
                    continue;
                }
                if ("event".equals(p.key)) {
                    name = String.valueOf(p.value);
                } else if (TOP.contains(p.key)) {
                    top.put(p.key, Pii.maskField(p.key, p.value));
                } else {
                    attrs.put(snake(p.key), Pii.maskField(p.key, p.value));
                }
            }
        }
        Map<String, String> mdc = event.getMDCPropertyMap();
        if (mdc != null) {
            mdc.forEach((k, v) -> attrs.put(snake(k), Pii.maskField(k, v)));
        }
        line.put("event", name != null ? name : ours ? "log.unclassified" : "library.logged");
        line.put("msg", ours ? event.getMessage() : "a library logged a record");
        line.put("thread", event.getThreadName());
        line.put("component", component(logger));
        line.putAll(top);
        if (!ours) {
            attrs.put("library_message", scrub(shorten(event.getFormattedMessage(), 500)));
        }
        IThrowableProxy t = event.getThrowableProxy();
        if (t != null) {
            Map<String, Object> error = new LinkedHashMap<>();
            error.put("kind", t.getClassName());
            if (t.getMessage() != null) {
                error.put("message", scrub(shorten(t.getMessage(), 1000)));
            }
            if (event.getLevel().isGreaterOrEqual(Level.ERROR)) {
                error.put("stack", stack(t));
            }
            line.put("error", error);
        }
        if (!attrs.isEmpty()) {
            line.put("attrs", attrs);
        }
        StringBuilder out = new StringBuilder(256);
        Json.value(out, line);
        if (out.length() > 15_900) {
            line.remove("attrs");
            out.setLength(0);
            Json.value(out, line);
        }
        out.append('\n');
        return out.toString();
    }

    private static final java.util.regex.Pattern NUMBER = java.util.regex.Pattern.compile("\\+?\\d[\\d .()-]{5,}\\d");
    private static final java.util.regex.Pattern EMAIL =
            java.util.regex.Pattern.compile("[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\\.[A-Za-z]{2,}");

    /** Free text: no phone-like digit run (7 or more digits), no email address (log-record.v1's free-text rule). */
    static String scrub(String text) {
        if (text == null) {
            return null;
        }
        String t = EMAIL.matcher(text).replaceAll(Pii.EMAIL_MASK);
        java.util.regex.Matcher m = NUMBER.matcher(t);
        StringBuilder out = new StringBuilder();
        while (m.find()) {
            String digits = m.group().replaceAll("\\D", "");
            m.appendReplacement(out, digits.length() >= 7 ? "***" : java.util.regex.Matcher.quoteReplacement(m.group()));
        }
        m.appendTail(out);
        return out.toString();
    }

    private static String level(Level l) {
        return switch (l.toInt()) {
            case Level.ERROR_INT -> "error";
            case Level.WARN_INT -> "warn";
            case Level.INFO_INT -> "info";
            case Level.DEBUG_INT -> "debug";
            default -> "trace";
        };
    }

    /** log-record.v1's component pattern: other characters become '_', at most 128. */
    private static String component(String logger) {
        String c = logger.replaceAll("[^A-Za-z0-9_.:/$-]", "_");
        if (c.isEmpty() || (!Character.isLetter(c.charAt(0)) && c.charAt(0) != '_')) {
            c = "_" + c;
        }
        return c.length() > 128 ? c.substring(0, 128) : c;
    }

    private static String snake(String key) {
        return key.replaceAll("([a-z0-9])([A-Z])", "$1_$2").replace('-', '_').replace('.', '_').toLowerCase(java.util.Locale.ROOT);
    }

    private static String shorten(String s, int max) {
        return s == null || s.length() <= max ? s : s.substring(0, max - 14) + "...[truncated]";
    }

    private static String stack(IThrowableProxy t) {
        StringBuilder b = new StringBuilder();
        for (IThrowableProxy p = t; p != null && b.length() < 8000; p = p.getCause()) {
            if (!identical(p, t)) {
                b.append("caused by: ").append(p.getClassName()).append(": ").append(scrub(p.getMessage())).append('\n');
            }
            StackTraceElementProxy[] frames = p.getStackTraceElementProxyArray();
            for (int i = 0; i < Math.min(frames.length, 30); i++) {
                b.append("  at ").append(frames[i].getSTEAsString().replaceFirst("^at ", "")).append('\n');
            }
        }
        return shorten(b.toString(), 8192);
    }

    /** The outermost throwable is printed apart from its causes. */
    @SuppressWarnings("ReferenceEquality")
    private static boolean identical(Object a, Object b) {
        return a == b;
    }
}
