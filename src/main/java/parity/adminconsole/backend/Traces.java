package parity.adminconsole.backend;

import java.security.SecureRandom;
import java.util.HexFormat;
import java.util.regex.Pattern;

/** W3C trace context: a request's {@code traceparent} is kept when well formed, else a new one starts. */
public final class Traces {

    private static final Pattern TRACEPARENT = Pattern.compile("00-[0-9a-f]{32}-[0-9a-f]{16}-[0-9a-f]{2}");
    private static final SecureRandom RANDOM = new SecureRandom();

    private Traces() {}

    public static String orFresh(String header) {
        return header != null && TRACEPARENT.matcher(header).matches() ? header : fresh();
    }

    public static String fresh() {
        byte[] trace = new byte[16];
        byte[] span = new byte[8];
        RANDOM.nextBytes(trace);
        RANDOM.nextBytes(span);
        return "00-" + HexFormat.of().formatHex(trace) + "-" + HexFormat.of().formatHex(span) + "-01";
    }
}
