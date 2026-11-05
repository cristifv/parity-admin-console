package parity.adminconsole.it;

import java.io.IOException;
import java.net.URI;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.json.JsonMapper;

/**
 * A scripted browser for Keycloak's login pages: the authorization-code flow with PKCE (S256), as the
 * web shell and the desktop do. It keeps its own cookie jar, follows redirects by hand, fills the
 * username and password forms (the organization's identity-first page, then the password page) and
 * stops at the redirect URI. Returns the access token, or {@link Refused} with the page's text.
 */
public final class Browser {

    private static final JsonMapper JSON = JsonMapper.builder().build();
    private static final Pattern FORM = Pattern.compile("(?is)<form\\b([^>]*)>(.*?)</form>");
    private static final Pattern INPUT = Pattern.compile("(?is)<input\\b([^>]*)>");
    private static final Pattern ATTR = Pattern.compile("(?is)\\b([a-z-]+)\\s*=\\s*\"([^\"]*)\"");

    /** The login stopped on a page (refused, an error). */
    public static final class Refused extends RuntimeException {
        private static final long serialVersionUID = 1L;
        private final String page;

        Refused(String page) {
            super("login refused: " + (page.length() > 300 ? page.substring(0, 300) : page));
            this.page = page;
        }

        public String page() {
            return page;
        }
    }

    private final HttpClient http = HttpClient.newBuilder().followRedirects(HttpClient.Redirect.NEVER).build();
    private final Map<String, String> cookies = new LinkedHashMap<>();

    public static String login(String issuer, String clientId, String redirectUri, String username, String password) {
        return new Browser().run(issuer, clientId, redirectUri, username, password);
    }

    private String run(String issuer, String clientId, String redirectUri, String username, String password) {
        byte[] v = new byte[32];
        new SecureRandom().nextBytes(v);
        String verifier = Base64.getUrlEncoder().withoutPadding().encodeToString(v);
        String challenge;
        try {
            challenge = Base64.getUrlEncoder().withoutPadding().encodeToString(
                    MessageDigest.getInstance("SHA-256").digest(verifier.getBytes(StandardCharsets.US_ASCII)));
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException(e);
        }
        String url = issuer + "/protocol/openid-connect/auth?client_id=" + enc(clientId) + "&redirect_uri=" + enc(redirectUri)
                + "&response_type=code&scope=openid&state=it&code_challenge=" + challenge + "&code_challenge_method=S256";
        String body = null;
        for (int hop = 0; hop < 30; hop++) {
            if (url.startsWith(redirectUri)) {
                Matcher m = Pattern.compile("[?&]code=([^&]+)").matcher(url);
                if (!m.find()) {
                    throw new Refused(url);
                }
                return token(issuer, clientId, redirectUri, java.net.URLDecoder.decode(m.group(1), StandardCharsets.UTF_8), verifier);
            }
            HttpResponse<String> r = send(url, body);
            body = null;
            if (r.statusCode() / 100 == 3) {
                url = URI.create(url).resolve(r.headers().firstValue("Location").orElseThrow()).toString();
                continue;
            }
            Matcher f = FORM.matcher(r.body());
            Map<String, String> fields = null;
            String action = null;
            while (f.find()) {
                Map<String, String> attrs = attrs(f.group(1));
                Map<String, String> inputs = new LinkedHashMap<>();
                Matcher in = INPUT.matcher(f.group(2));
                while (in.find()) {
                    Map<String, String> a = attrs(in.group(1));
                    if (a.containsKey("name")) {
                        inputs.put(a.get("name"), a.getOrDefault("value", ""));
                    }
                }
                if (inputs.containsKey("username") || inputs.containsKey("password")) {
                    fields = inputs;
                    action = attrs.get("action");
                    break;
                }
            }
            if (fields == null || action == null || hop > 20) {
                throw new Refused(text(r.body()));
            }
            if (fields.containsKey("username")) {
                fields.put("username", username);
            }
            if (fields.containsKey("password")) {
                fields.put("password", password);
            }
            StringBuilder form = new StringBuilder();
            for (Map.Entry<String, String> e : fields.entrySet()) {
                if (!form.isEmpty()) {
                    form.append('&');
                }
                form.append(enc(e.getKey())).append('=').append(enc(e.getValue()));
            }
            url = URI.create(url).resolve(unescape(action)).toString();
            body = form.toString();
        }
        throw new Refused("too many hops");
    }

    private String token(String issuer, String clientId, String redirectUri, String code, String verifier) {
        String form = "grant_type=authorization_code&client_id=" + enc(clientId) + "&code=" + enc(code)
                + "&redirect_uri=" + enc(redirectUri) + "&code_verifier=" + enc(verifier);
        HttpResponse<String> r = send(issuer + "/protocol/openid-connect/token", form);
        if (r.statusCode() != 200) {
            throw new Refused("token endpoint " + r.statusCode());
        }
        JsonNode t = JSON.readTree(r.body());
        return t.path("access_token").asString();
    }

    private HttpResponse<String> send(String url, String form) {
        HttpRequest.Builder b = HttpRequest.newBuilder(URI.create(url));
        if (!cookies.isEmpty()) {
            b.header("Cookie", String.join("; ", cookies.entrySet().stream().map(e -> e.getKey() + "=" + e.getValue()).toList()));
        }
        if (form != null) {
            b.header("Content-Type", "application/x-www-form-urlencoded").POST(HttpRequest.BodyPublishers.ofString(form));
        }
        try {
            HttpResponse<String> r = http.send(b.build(), HttpResponse.BodyHandlers.ofString());
            for (String c : r.headers().allValues("Set-Cookie")) {
                String pair = c.split(";", 2)[0];
                int eq = pair.indexOf('=');
                if (eq > 0) {
                    cookies.put(pair.substring(0, eq).strip(), pair.substring(eq + 1).strip());
                }
            }
            return r;
        } catch (IOException e) {
            throw new IllegalStateException("login request failed", e);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new IllegalStateException(e);
        }
    }

    private static Map<String, String> attrs(String tag) {
        Map<String, String> out = new LinkedHashMap<>();
        Matcher a = ATTR.matcher(tag);
        while (a.find()) {
            out.put(a.group(1).toLowerCase(java.util.Locale.ROOT), unescape(a.group(2)));
        }
        return out;
    }

    private static String unescape(String s) {
        return s.replace("&amp;", "&").replace("&quot;", "\"").replace("&#39;", "'").replace("&lt;", "<").replace("&gt;", ">");
    }

    static String text(String html) {
        return unescape(html.replaceAll("(?is)<script\\b.*?</script\\s*>", " ").replaceAll("<[^>]+>", " ")).replaceAll("\\s+", " ").strip();
    }

    private static String enc(String s) {
        return URLEncoder.encode(s, StandardCharsets.UTF_8);
    }

    /** The claims of a JWT, unverified (tests read their own tokens). */
    public static JsonNode claims(String jwt) {
        List<String> parts = List.of(jwt.split("\\."));
        return JSON.readTree(Base64.getUrlDecoder().decode(parts.get(1)));
    }
}
