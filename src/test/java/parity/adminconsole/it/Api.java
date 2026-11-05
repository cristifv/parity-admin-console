package parity.adminconsole.it;

import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.json.JsonMapper;

/** The console's API over HTTP, as the browser calls it (bearer token, JSON). */
public final class Api {

    private static final JsonMapper JSON = JsonMapper.builder().build();
    private static final HttpClient HTTP = HttpClient.newHttpClient();

    /** A status and a parsed body. */
    public record Answer(int status, JsonNode body) {
        public String code() {
            return body.path("code").asString("");
        }
    }

    private final int port;

    public Api(int port) {
        this.port = port;
    }

    public Answer get(String token, String path) {
        return send(token, "GET", path, null);
    }

    public Answer post(String token, String path, Object body) {
        return send(token, "POST", path, body);
    }

    public Answer put(String token, String path, Object body) {
        return send(token, "PUT", path, body);
    }

    public Answer delete(String token, String path) {
        return send(token, "DELETE", path, null);
    }

    public Answer send(String token, String method, String path, Object body) {
        HttpRequest.Builder b = HttpRequest.newBuilder(URI.create("http://localhost:" + port + path)).header("Accept", "application/json");
        if (token != null) {
            b.header("Authorization", "Bearer " + token);
        }
        if (body != null) {
            b.header("Content-Type", "application/json").method(method, HttpRequest.BodyPublishers.ofString(
                    body instanceof String s ? s : JSON.writeValueAsString(body)));
        } else {
            b.method(method, HttpRequest.BodyPublishers.noBody());
        }
        try {
            HttpResponse<String> r = HTTP.send(b.build(), HttpResponse.BodyHandlers.ofString());
            JsonNode parsed;
            try {
                parsed = r.body() == null || r.body().isBlank() ? JSON.missingNode() : JSON.readTree(r.body());
            } catch (RuntimeException e) {
                parsed = JSON.missingNode();
            }
            return new Answer(r.statusCode(), parsed);
        } catch (IOException e) {
            throw new IllegalStateException(e);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new IllegalStateException(e);
        }
    }
}
