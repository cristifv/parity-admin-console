package parity.adminconsole.obs;

import java.util.ArrayList;
import java.util.Collection;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * Personal data in logs (ARCHITECTURE.md §5.2): parity-store's and interaction-engine's rules
 * ({@code masking/cases.v1.json}), plus the billing classes of {@code masking/billing.v1.json}:
 * <ul>
 *   <li>{@link #normalize}: camelCase split, ASCII lowercase, {@code -} → {@code _}, a leading
 *       {@code variable_} stripped;</li>
 *   <li>{@link #classify}: phone (last 3 digits), email ({@code [email]}: never the address or a hash
 *       of it, FE-044), secret ({@code [redacted]}: tokens, signatures, keys, the hosted Stripe URLs) or
 *       plain;</li>
 *   <li>{@link #maskField}: the policy applied to a value, at every depth.</li>
 * </ul>
 * parity-admin-console logs ids, never emails, numbers or payloads; this is the safety net under that rule.
 *
 * <p><b>Exception messages carry no data</b>: they reach logs unmasked (the formatter masks fields,
 * not messages).
 */
public final class Pii {

    /** What the formatter does with a field. */
    public enum FieldClass { PHONE, EMAIL, SECRET, PLAIN }

    public static final String REDACTED = "[redacted]";

    private static final List<String> PHONE_NAMES = List.of(
            "from", "to", "number", "phone", "caller", "callee", "caller_id", "callback_number",
            "destination", "ani", "dnis", "msisdn", "e164", "contact", "uri", "pai",
            "p_asserted_identity", "rpid", "remote_party_id", "diversion", "history_info", "user",
            "channel_name", "caller_channel_name", "caller_username", "rdnis", "dialed_extension",
            "originate_string", "dial_string", "sip_from_display", "caller_caller_id_name",
            "sip_destination_url", "sip_call_id");
    private static final List<String> SECRET_NAMES = List.of(
            "digits", "dtmf", "pin", "password", "secret", "token", "authorization", "api_key", "dek",
            "wrapped_dek", "sdp", "sip_body", "passwd", "credentials",
            // billing.v1.json
            "signature", "secret_key", "cf_turnstile_response", "checkout_url", "portal_url", "verification_url");
    private static final Set<String> SECRET_TOKENS = Set.of("dtmf", "digit", "digits");
    private static final Set<String> EXEMPT = Set.of("reply_to", "num_digits");

    private Pii() {}

    /** The name the policy sees (masking/cases.v1.json, "normalize"). */
    public static String normalize(String name) {
        StringBuilder b = new StringBuilder(name.length() + 4);
        for (int i = 0; i < name.length(); i++) {
            char c = name.charAt(i);
            if (upper(c) && i > 0) {
                char prev = name.charAt(i - 1);
                boolean next = i + 1 < name.length() && lower(name.charAt(i + 1));
                if (lower(prev) || asciiDigit(prev) || (upper(prev) && next)) {
                    b.append('_');
                }
            }
            if (upper(c)) {
                b.append((char) (c + ('a' - 'A')));
            } else if (c == '-') {
                b.append('_');
            } else {
                b.append(c);
            }
        }
        String lower = b.toString();
        return lower.startsWith("variable_") ? lower.substring("variable_".length()) : lower;
    }

    private static boolean matches(String name, String listed) {
        return name.equals(listed)
                || (name.length() > listed.length()
                        && name.endsWith(listed)
                        && name.charAt(name.length() - listed.length() - 1) == '_');
    }

    /** The policy for a field name (normalized first). */
    public static FieldClass classify(String name) {
        String n = normalize(name);
        if (EXEMPT.contains(n)) {
            return FieldClass.PLAIN;
        }
        for (String token : n.split("_", -1)) {
            if (SECRET_TOKENS.contains(token)) {
                return FieldClass.SECRET;
            }
        }
        if (SECRET_NAMES.stream().anyMatch(s -> matches(n, s))
                || n.endsWith("_secret") || n.endsWith("_token") || n.endsWith("_password")) {
            return FieldClass.SECRET;
        }
        if (matches(n, "email")) {
            return FieldClass.EMAIL;
        }
        if (PHONE_NAMES.stream().anyMatch(p -> matches(n, p))
                || n.endsWith("_number") || n.endsWith("_phone") || n.endsWith("_user")) {
            return FieldClass.PHONE;
        }
        return FieldClass.PLAIN;
    }

    private static boolean asciiDigit(char c) {
        return c >= '0' && c <= '9';
    }

    private static boolean upper(char c) {
        return c >= 'A' && c <= 'Z';
    }

    private static boolean lower(char c) {
        return c >= 'a' && c <= 'z';
    }

    /** Keeps the last 3 ASCII digits behind {@code ***} when there are at least 4; otherwise {@code ***}. */
    public static String maskPhone(String raw) {
        StringBuilder digits = new StringBuilder();
        for (int i = 0; i < raw.length(); i++) {
            if (asciiDigit(raw.charAt(i))) {
                digits.append(raw.charAt(i));
            }
        }
        int at = raw.indexOf("***");
        if (at >= 0) {
            StringBuilder tail = new StringBuilder();
            for (int i = at + 3; i < raw.length() && asciiDigit(raw.charAt(i)); i++) {
                tail.append(raw.charAt(i));
            }
            if (tail.length() > 0 && tail.length() <= 3 && tail.length() == digits.length()) {
                return "***" + tail;
            }
        }
        if (digits.length() >= 4) {
            return "***" + digits.substring(digits.length() - 3);
        }
        return "***";
    }

    /** What an email becomes in a log (masking/billing.v1.json, 0.10.2): nothing of it, not even a hash. */
    public static final String EMAIL_MASK = "[email]";

    /** An email in a log: always {@link #EMAIL_MASK} (a hash, keyed or not, would let a log reader test addresses). */
    public static String maskEmail(String raw) {
        return EMAIL_MASK;
    }

    /** Applies the policy to a value logged under {@code name}. */
    public static Object maskField(String name, Object value) {
        return switch (classify(name)) {
            case PLAIN -> maskNested(value);
            case SECRET -> REDACTED;
            case EMAIL -> value == null ? null : EMAIL_MASK;
            case PHONE -> maskAll(value);
        };
    }

    /** Recurses into maps and collections, applying the policy to every key. */
    public static Object maskNested(Object value) {
        if (value instanceof Map<?, ?> map) {
            Map<String, Object> out = new LinkedHashMap<>();
            map.forEach((k, v) -> out.put(String.valueOf(k), maskField(String.valueOf(k), v)));
            return out;
        }
        if (value instanceof Collection<?> items) {
            List<Object> out = new ArrayList<>(items.size());
            items.forEach(item -> out.add(maskNested(item)));
            return out;
        }
        return value;
    }

    /** Everything under a phone key is masked, scalars and nested values alike. */
    public static Object maskAll(Object value) {
        if (value == null) {
            return null;
        }
        if (value instanceof Map<?, ?> map) {
            Map<String, Object> out = new LinkedHashMap<>();
            map.forEach((k, v) -> out.put(String.valueOf(k), maskAll(v)));
            return out;
        }
        if (value instanceof Collection<?> items) {
            List<Object> out = new ArrayList<>(items.size());
            items.forEach(item -> out.add(maskAll(item)));
            return out;
        }
        if (value instanceof Boolean) {
            return value;
        }
        return maskPhone(String.valueOf(value));
    }
}
