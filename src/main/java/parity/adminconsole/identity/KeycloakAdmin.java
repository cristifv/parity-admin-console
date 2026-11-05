package parity.adminconsole.identity;

import java.io.IOException;
import java.net.URI;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.time.Clock;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import parity.adminconsole.config.AdminConsoleProperties;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.json.JsonMapper;
import tools.jackson.databind.node.ArrayNode;

/**
 * The few Keycloak Admin REST API calls admin-api makes (SAML-PLAN step 4), with the service account's
 * token, plain {@link HttpClient} and Jackson 3: no Keycloak admin library (it brings RESTEasy and
 * Jackson 2, and is tied to one Keycloak release). Every call has a timeout; a connection failure or a
 * 5xx is {@link KeycloakException.Kind#UNAVAILABLE} (retried by the apply job), a 404 {@code NOT_FOUND},
 * a 409 {@code CONFLICT}, any other 4xx {@code REFUSED}. Response bodies never reach a log or an
 * exception message.
 *
 * <p>Checked against Keycloak 26.8.1 by the spike (SAML-PLAN step 1): an organization's IdP link carries
 * its membership type; email routing is set on the organization's domain.
 */
public class KeycloakAdmin {

    private static final JsonMapper JSON = JsonMapper.builder().build();

    private final String base;
    private final ServiceAccount account;
    private final HttpClient http;
    private final Duration timeout;

    public KeycloakAdmin(AdminConsoleProperties properties, Clock clock) {
        AdminConsoleProperties.Identity id = properties.identity();
        String url = id.keycloakUrl().replaceAll("/+$", "");
        this.base = url + "/admin/realms/" + enc(id.realm());
        this.timeout = id.requestTimeout();
        this.http = HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(2)).followRedirects(HttpClient.Redirect.NEVER).build();
        this.account = new ServiceAccount(url, id.realm(), properties.auth().issuer(), id.clientId(), Path.of(id.keyFile()),
                http, timeout, clock);
    }

    /** A response: the status, the body (or null) and the id from {@code Location} (or null). */
    record Response(int status, JsonNode body, String createdId) {}

    // ---------------------------------------------------------------- organizations

    public Optional<JsonNode> organizationByAlias(String alias) {
        JsonNode list = get("/organizations?exact=true&briefRepresentation=false&search=" + enc(alias));
        for (JsonNode o : list) {
            if (alias.equals(o.path("alias").asString(""))) {
                return Optional.of(o);
            }
        }
        return Optional.empty();
    }

    public List<JsonNode> organizations(int first, int max) {
        return list(get("/organizations?briefRepresentation=true&first=" + first + "&max=" + max));
    }

    /**
     * Creates an organization without domains (SAML-PLAN: domains route only after DNS verification).
     * Its name is the tenant id too: Keycloak wants names unique and its exact search matches names, not
     * aliases (Keycloak 26.8.1); the tenant's display name goes in the description.
     */
    public String createOrganization(String alias, String displayName, boolean enabled) {
        var rep = JSON.createObjectNode().put("alias", alias).put("name", alias).put("description", displayName)
                .put("enabled", enabled);
        rep.putArray("domains");
        return call("POST", "/organizations", rep).createdId();
    }

    public void updateOrganization(String id, JsonNode rep) {
        call("PUT", "/organizations/" + enc(id), rep);
    }

    public void deleteOrganization(String id) {
        call("DELETE", "/organizations/" + enc(id), null);
    }

    public List<JsonNode> members(String orgId, int first, int max) {
        return list(get("/organizations/" + enc(orgId) + "/members?first=" + first + "&max=" + max));
    }

    /** Adds an existing user as an unmanaged member (local accounts). */
    public void addMember(String orgId, String userId) {
        raw("POST", "/organizations/" + enc(orgId) + "/members", userId);
    }

    public List<JsonNode> userOrganizations(String userId) {
        return list(get("/organizations/members/" + enc(userId) + "/organizations"));
    }

    // ---------------------------------------------------------------- clients

    public Optional<JsonNode> clientByClientId(String clientId) {
        JsonNode list = get("/clients?search=false&clientId=" + enc(clientId));
        return list.isArray() && !list.isEmpty() ? Optional.of(list.get(0)) : Optional.empty();
    }

    public String createClient(JsonNode rep) {
        return call("POST", "/clients", rep).createdId();
    }

    public void deleteClient(String id) {
        call("DELETE", "/clients/" + enc(id), null);
    }

    // ---------------------------------------------------------------- users

    public String createUser(JsonNode rep) {
        return call("POST", "/users", rep).createdId();
    }

    public Optional<JsonNode> user(String id) {
        try {
            return Optional.of(get("/users/" + enc(id) + "?userProfileMetadata=false"));
        } catch (KeycloakException e) {
            if (e.kind() == KeycloakException.Kind.NOT_FOUND) {
                return Optional.empty();
            }
            throw e;
        }
    }

    public void updateUser(String id, JsonNode rep) {
        call("PUT", "/users/" + enc(id), rep);
    }

    public void deleteUser(String id) {
        call("DELETE", "/users/" + enc(id), null);
    }

    /** Ends every session of the user. */
    public void logout(String id) {
        call("POST", "/users/" + enc(id) + "/logout", null);
    }

    /** Users whose {@code tenant_id} attribute is exactly {@code tenant} (admins only can set it). */
    public List<JsonNode> usersByTenant(String tenant, int first, int max) {
        return list(get("/users?briefRepresentation=false&exact=true&first=" + first + "&max=" + max + "&q=" + enc("tenant_id:" + tenant)));
    }

    public List<JsonNode> users(int first, int max) {
        return list(get("/users?briefRepresentation=false&first=" + first + "&max=" + max));
    }

    public List<JsonNode> realmRoleMappings(String userId) {
        return list(get("/users/" + enc(userId) + "/role-mappings/realm"));
    }

    public void addRealmRoles(String userId, List<JsonNode> roles) {
        ArrayNode a = JSON.createArrayNode();
        roles.forEach(a::add);
        call("POST", "/users/" + enc(userId) + "/role-mappings/realm", a);
    }

    /** Realm roles by name (the service account reads them with {@code view-realm}: read-only). */
    public List<JsonNode> realmRoles(List<String> names) {
        List<JsonNode> out = new ArrayList<>();
        for (String n : names) {
            out.add(get("/roles/" + enc(n)));
        }
        return out;
    }

    public List<JsonNode> roleUsers(String role, int first, int max) {
        return list(get("/roles/" + enc(role) + "/users?briefRepresentation=true&first=" + first + "&max=" + max));
    }

    // ---------------------------------------------------------------- plumbing

    private JsonNode get(String path) {
        return call("GET", path, null).body();
    }

    private Response call(String method, String path, JsonNode body) {
        return send(method, path, body == null ? null : JSON.writeValueAsString(body), true);
    }

    /** A request whose body is a bare string (Keycloak's member and IdP-link endpoints). */
    private void raw(String method, String path, String body) {
        send(method, path, body, true);
    }

    private Response send(String method, String path, String body, boolean retryOn401) {
        HttpRequest.Builder b = HttpRequest.newBuilder(URI.create(base + path)).timeout(timeout)
                .header("Authorization", "Bearer " + account.token()).header("Accept", "application/json");
        if (body != null) {
            b.header("Content-Type", "application/json").method(method, HttpRequest.BodyPublishers.ofString(body));
        } else {
            b.method(method, HttpRequest.BodyPublishers.noBody());
        }
        HttpResponse<String> resp;
        try {
            resp = http.send(b.build(), HttpResponse.BodyHandlers.ofString());
        } catch (IOException e) {
            throw new KeycloakException(KeycloakException.Kind.UNAVAILABLE, e);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new KeycloakException(KeycloakException.Kind.UNAVAILABLE, e);
        }
        int s = resp.statusCode();
        if (s == 401 && retryOn401) {
            account.reset();
            return send(method, path, body, false);
        }
        if (s >= 400) {
            KeycloakException.Kind kind = s >= 500 ? KeycloakException.Kind.UNAVAILABLE : s == 404 ? KeycloakException.Kind.NOT_FOUND
                    : s == 409 ? KeycloakException.Kind.CONFLICT : KeycloakException.Kind.REFUSED;
            throw new KeycloakException(kind, s, new KeycloakException.Call(method, resource(path)));
        }
        String created = resp.headers().firstValue("Location").map(l -> l.substring(l.lastIndexOf('/') + 1)).orElse(null);
        String text = resp.body();
        JsonNode parsed = text == null || text.isBlank() ? JSON.missingNode() : JSON.readTree(text);
        return new Response(s, parsed, created);
    }

    /** The path without ids or query: "/organizations/{id}/members". */
    static String resource(String path) {
        String p = path.split("\\?", 2)[0];
        return p.replaceAll("/[0-9a-fA-F-]{36}", "/{id}").replaceAll("^(/(users|clients|organizations|roles))/(?!\\{id\\})[^/]+", "$1/{name}");
    }

    private static List<JsonNode> list(JsonNode array) {
        List<JsonNode> out = new ArrayList<>();
        if (array != null && array.isArray()) {
            array.forEach(out::add);
        }
        return out;
    }

    private static String enc(String s) {
        return URLEncoder.encode(s, StandardCharsets.UTF_8).replace("+", "%20");
    }
}
