package parity.adminconsole.contracts;

import com.networknt.schema.Error;
import com.networknt.schema.Schema;
import com.networknt.schema.SchemaLocation;
import com.networknt.schema.SchemaRegistry;
import com.networknt.schema.dialect.Dialect;
import com.networknt.schema.dialect.Dialects;
import com.networknt.schema.keyword.AnnotationKeyword;
import com.networknt.schema.path.NodePath;
import java.io.IOException;
import java.io.InputStream;
import java.io.UncheckedIOException;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeSet;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.json.JsonMapper;

/**
 * parity-contracts' parity-store schemas, copied into the jar at build time ({@code contracts/}),
 * through networknt 3.0.8 with the contracts' annotation keywords registered. Writers validate
 * everything they write (CONVENTIONS.md "schema_version and evolution"): every request the console
 * sends to parity-store is checked against {@code store-requests.v1.json} first.
 */
public final class Schemas {

    public static final String STORE_REQUESTS = "store-requests";
    /** parity-rs's requests (parity-contracts 0.16.0): the console sends place_tenant on the onboarding topic. */
    public static final String ROUTING_REQUESTS = "routing-requests";
    public static final String STORE_REPLIES = "store-replies";

    private static final Map<String, String> FILES = Map.of(
            STORE_REQUESTS, "contracts/schemas/store/store-requests.v1.json",
            STORE_REPLIES, "contracts/schemas/store/store-replies.v1.json",
            ROUTING_REQUESTS, "contracts/schemas/tenant-routing/tenant-routing-requests.v1.json");
    private static final JsonMapper JSON = JsonMapper.builder().build();

    private final Map<String, Schema> schemas = new LinkedHashMap<>();
    private final Map<String, JsonNode> documents = new LinkedHashMap<>();

    public Schemas() {
        Dialect dialect = Dialect.builder(Dialects.getDraft202012())
                .keyword(new AnnotationKeyword("x-pii"))
                .keyword(new AnnotationKeyword("x-reserved"))
                .keyword(new AnnotationKeyword("x-admin"))
                .keyword(new AnnotationKeyword("x-web"))
                .keyword(new AnnotationKeyword("x-secret"))
                .keyword(new AnnotationKeyword("x-topics"))
                .keyword(new AnnotationKeyword("x-key"))
                .build();
        SchemaRegistry registry = SchemaRegistry.withDialect(dialect);
        ClassLoader loader = Schemas.class.getClassLoader();
        for (Map.Entry<String, String> e : FILES.entrySet()) {
            try (InputStream in = loader.getResourceAsStream(e.getValue())) {
                if (in == null) {
                    throw new IllegalStateException("the jar lacks a parity-contracts schema (built without parity-contracts?)");
                }
                JsonNode doc = JSON.readTree(in);
                documents.put(e.getKey(), doc);
                schemas.put(e.getKey(), registry.getSchema(SchemaLocation.of(doc.path("$id").asString()), doc));
            } catch (IOException ex) {
                throw new UncheckedIOException(ex);
            }
        }
    }

    /** One schema error: where (a JSON pointer) and which keyword. Never the value. */
    public record Problem(String at, String keyword) {}

    /** The errors of {@code instance} against the schema {@code name} (at most 50). */
    public List<Problem> check(String name, JsonNode instance) {
        Schema schema = schemas.get(name);
        if (schema == null) {
            throw new IllegalArgumentException("no such schema");
        }
        List<Error> errors = schema.validate(instance);
        return errors.stream().limit(50).map(e -> new Problem(pointer(e.getInstanceLocation()), e.getKeyword())).toList();
    }

    /** The parsed schema document (for annotations such as {@code x-web}). */
    public JsonNode document(String name) {
        return documents.get(name);
    }

    /** The commands of a requests schema whose definition carries {@code mark} ({@code null}: none). */
    public Set<String> commands(String name, String mark) {
        Set<String> out = new TreeSet<>();
        for (var e : document(name).path("$defs").properties()) {
            JsonNode d = e.getValue();
            String cmd = d.path("properties").path("cmd").path("const").asString("");
            if (cmd.isEmpty()) {
                continue;
            }
            boolean web = d.path("x-web").asBoolean(false);
            boolean admin = d.path("x-admin").asBoolean(false);
            boolean match = mark == null ? !web && !admin : d.path(mark).asBoolean(false);
            if (match) {
                out.add(cmd);
            }
        }
        return Set.copyOf(out);
    }

    /** The contracts version the jar was built with. */
    public static String contractsVersion() {
        try (InputStream in = Schemas.class.getClassLoader().getResourceAsStream("contracts/VERSION")) {
            return in == null ? "unknown" : new String(in.readAllBytes(), java.nio.charset.StandardCharsets.UTF_8).strip();
        } catch (IOException e) {
            return "unknown";
        }
    }

    static String pointer(NodePath path) {
        StringBuilder b = new StringBuilder();
        for (int i = 0; i < path.getNameCount(); i++) {
            Object element = path.getElement(i);
            b.append('/').append(String.valueOf(element).replace("~", "~0").replace("/", "~1"));
        }
        return b.toString();
    }
}
