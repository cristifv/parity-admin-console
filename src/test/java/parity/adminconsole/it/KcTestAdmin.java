package parity.adminconsole.it;

import java.io.IOException;
import java.net.URI;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.json.JsonMapper;
import tools.jackson.databind.node.ObjectNode;

/**
 * The tests' own Keycloak admin (the bootstrap admin of the master realm), to set up what a test needs
 * and to plant what the console must find: never used by the console itself.
 */
public final class KcTestAdmin {

    private static final JsonMapper JSON = JsonMapper.builder().build();
    private final HttpClient http = HttpClient.newHttpClient();

    public JsonNode get(String path) {
        return send("GET", path, null);
    }

    public JsonNode post(String path, Object body) {
        return send("POST", path, body);
    }

    public JsonNode put(String path, Object body) {
        return send("PUT", path, body);
    }

    public JsonNode delete(String path) {
        return send("DELETE", path, null);
    }

    public JsonNode user(String username) {
        JsonNode list = get("/realms/parity/users?exact=true&briefRepresentation=false&username=" + enc(username));
        return list.isEmpty() ? null : list.get(0);
    }

    /** Gives a user a password and clears its required actions (so the scripted login goes straight through). */
    public void password(String userId, String password) {
        put("/realms/parity/users/" + userId + "/reset-password",
                JSON.createObjectNode().put("type", "password").put("value", password).put("temporary", false));
        ObjectNode u = (ObjectNode) get("/realms/parity/users/" + userId);
        u.putArray("requiredActions");
        put("/realms/parity/users/" + userId, u);
    }

    /** A user straight in Keycloak (planting what admin-api would never create). */
    public String createUser(String realm, String username, String password, String tenant, List<String> roles) {
        ObjectNode u = JSON.createObjectNode().put("username", username).put("enabled", true).put("firstName", "Test").put("lastName", "User")
                .put("email", username + "@example.test").put("emailVerified", true);
        if (tenant != null) {
            u.putObject("attributes").putArray("tenant_id").add(tenant);
        }
        u.putArray("credentials").addObject().put("type", "password").put("value", password).put("temporary", false);
        post("/realms/" + realm + "/users", u);
        JsonNode created = get("/realms/" + realm + "/users?exact=true&username=" + enc(username)).get(0);
        String id = created.path("id").asString();
        List<JsonNode> reps = new ArrayList<>();
        for (String r : roles) {
            reps.add(get("/realms/" + realm + "/roles/" + r));
        }
        if (!reps.isEmpty()) {
            post("/realms/" + realm + "/users/" + id + "/role-mappings/realm", reps);
        }
        return id;
    }

    public String orgId(String alias) {
        for (JsonNode o : get("/realms/parity/organizations?exact=true&search=" + enc(alias))) {
            if (alias.equals(o.path("alias").asString())) {
                return o.path("id").asString();
            }
        }
        return null;
    }

    /** Adds a user to an organization (the member endpoint takes the bare id). */
    public void addMember(String orgId, String userId) {
        raw("POST", "/realms/parity/organizations/" + orgId + "/members", userId);
    }

    private String token() {
        String form = "grant_type=password&client_id=admin-cli&username=kc-bootstrap&password=" + enc(Stack.keycloakAdminPassword());
        HttpResponse<String> r = exchange(HttpRequest.newBuilder(URI.create(Stack.keycloakUrl() + "/realms/master/protocol/openid-connect/token"))
                .header("Content-Type", "application/x-www-form-urlencoded").POST(HttpRequest.BodyPublishers.ofString(form)).build());
        return JSON.readTree(r.body()).path("access_token").asString();
    }

    private JsonNode send(String method, String path, Object body) {
        String text = body == null ? null : JSON.writeValueAsString(body);
        return parse(raw(method, path, text));
    }

    private HttpResponse<String> raw(String method, String path, String body) {
        HttpRequest.Builder b = HttpRequest.newBuilder(URI.create(Stack.keycloakUrl() + "/admin" + path))
                .header("Authorization", "Bearer " + token());
        if (body != null) {
            b.header("Content-Type", "application/json").method(method, HttpRequest.BodyPublishers.ofString(body));
        } else {
            b.method(method, HttpRequest.BodyPublishers.noBody());
        }
        HttpResponse<String> r = exchange(b.build());
        if (r.statusCode() >= 300) {
            throw new IllegalStateException("test admin " + method + " " + r.statusCode());
        }
        return r;
    }

    private HttpResponse<String> exchange(HttpRequest req) {
        try {
            return http.send(req, HttpResponse.BodyHandlers.ofString());
        } catch (IOException e) {
            throw new IllegalStateException(e);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new IllegalStateException(e);
        }
    }

    private static JsonNode parse(HttpResponse<String> r) {
        return r.body() == null || r.body().isBlank() ? JSON.missingNode() : JSON.readTree(r.body());
    }

    private static String enc(String s) {
        return URLEncoder.encode(s, StandardCharsets.UTF_8);
    }
}
