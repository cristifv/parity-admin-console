package parity.adminconsole.backend;

import java.nio.charset.CharacterCodingException;
import java.nio.charset.CodingErrorAction;
import java.nio.charset.StandardCharsets;
import org.apache.kafka.common.header.Header;

/**
 * Kafka header values, read null-safely: a header that is absent, has a null value, isn't
 * UTF-8 or is longer than {@code max} bytes counts as missing (CONVENTIONS.md: a malformed header
 * counts as missing). Never throws.
 */
public final class Headers {

    private Headers() {}

    public static String text(org.apache.kafka.common.header.Headers headers, String name, int max) {
        if (headers == null) {
            return null;
        }
        Header h = headers.lastHeader(name);
        if (h == null) {
            return null;
        }
        byte[] v = h.value();
        if (v == null || v.length == 0 || v.length > max) {
            return null;
        }
        try {
            return StandardCharsets.UTF_8.newDecoder()
                    .onMalformedInput(CodingErrorAction.REPORT)
                    .onUnmappableCharacter(CodingErrorAction.REPORT)
                    .decode(java.nio.ByteBuffer.wrap(v)).toString();
        } catch (CharacterCodingException e) {
            return null;
        }
    }
}
