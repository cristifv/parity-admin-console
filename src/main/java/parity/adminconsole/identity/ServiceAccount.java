package parity.adminconsole.identity;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import java.io.IOException;
import java.net.URI;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.interfaces.RSAPrivateKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.Base64;
import java.util.Date;
import java.util.UUID;
import java.util.concurrent.locks.ReentrantLock;
import parity.adminconsole.lifecycle.ConfigurationRefusedException;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.json.JsonMapper;

/**
 * admin-api's Keycloak service account (SAML-PLAN "Keycloak setup"): the client-credentials grant
 * with a client assertion, a JWT signed with the account's RSA key (RFC 7523), so there is no shared
 * secret. The key is read once from a PEM file (PKCS#8); the access token is kept until 30 s before it
 * expires.
 */
final class ServiceAccount {

    private static final JsonMapper JSON = JsonMapper.builder().build();
    private static final KeycloakException.Call TOKEN_CALL = new KeycloakException.Call("POST", "/token");

    private final URI tokenEndpoint;
    private final String audience;
    private final String clientId;
    private final RSAPrivateKey key;
    private final HttpClient http;
    private final Duration timeout;
    private final Clock clock;
    private final ReentrantLock lock = new ReentrantLock();
    private String token;
    private Instant refreshAt = Instant.EPOCH;

    ServiceAccount(String keycloakUrl, String realm, String issuer, String clientId, Path keyFile, HttpClient http,
            Duration timeout, Clock clock) {
        String base = keycloakUrl.replaceAll("/+$", "");
        this.tokenEndpoint = URI.create(base + "/realms/" + realm + "/protocol/openid-connect/token");
        // The audience is the realm's issuer, one value (RFC 7523bis; Keycloak 26.8 refuses several). The
        // console reaches Keycloak on an internal address, but the issuer is the realm's public one.
        this.audience = issuer;
        this.clientId = clientId;
        this.key = readKey(keyFile);
        this.http = http;
        this.timeout = timeout;
        this.clock = clock;
    }

    /** A valid access token for the Admin REST API. */
    String token() {
        lock.lock();
        try {
            if (token != null && clock.instant().isBefore(refreshAt)) {
                return token;
            }
            String body = "grant_type=client_credentials&client_id=" + enc(clientId)
                    + "&client_assertion_type=" + enc("urn:ietf:params:oauth:client-assertion-type:jwt-bearer")
                    + "&client_assertion=" + enc(assertion());
            HttpRequest req = HttpRequest.newBuilder(tokenEndpoint).timeout(timeout)
                    .header("Content-Type", "application/x-www-form-urlencoded")
                    .POST(HttpRequest.BodyPublishers.ofString(body)).build();
            HttpResponse<String> resp;
            try {
                resp = http.send(req, HttpResponse.BodyHandlers.ofString());
            } catch (IOException e) {
                throw new KeycloakException(KeycloakException.Kind.UNAVAILABLE, e);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                throw new KeycloakException(KeycloakException.Kind.UNAVAILABLE, e);
            }
            if (resp.statusCode() >= 500) {
                throw new KeycloakException(KeycloakException.Kind.UNAVAILABLE, resp.statusCode(), TOKEN_CALL);
            }
            if (resp.statusCode() != 200) {
                // The OAuth error code is a fixed vocabulary (invalid_client, unauthorized_client...): safe to log.
                String error = "unknown";
                try {
                    error = JSON.readTree(resp.body()).path("error").asString("unknown").replaceAll("[^a-z_]", "");
                } catch (RuntimeException ignored) {
                    // not JSON: "unknown"
                }
                throw new KeycloakException(KeycloakException.Kind.REFUSED, resp.statusCode(),
                        new KeycloakException.Call("POST", "/token (" + error + ")"));
            }
            JsonNode t = JSON.readTree(resp.body());
            token = t.path("access_token").asString();
            long expires = t.path("expires_in").asLong(60);
            refreshAt = clock.instant().plusSeconds(Math.max(5, expires - 30));
            return token;
        } finally {
            lock.unlock();
        }
    }

    /** Forget the token (a 401 from the API: it was revoked or the key rotated). */
    void reset() {
        lock.lock();
        try {
            token = null;
        } finally {
            lock.unlock();
        }
    }

    private String assertion() {
        Instant now = clock.instant();
        JWTClaimsSet claims = new JWTClaimsSet.Builder().issuer(clientId).subject(clientId).audience(audience)
                .jwtID(UUID.randomUUID().toString()).issueTime(Date.from(now)).expirationTime(Date.from(now.plusSeconds(60)))
                .build();
        SignedJWT jwt = new SignedJWT(new JWSHeader(JWSAlgorithm.RS256), claims);
        try {
            jwt.sign(new RSASSASigner(key));
        } catch (JOSEException e) {
            throw new IllegalStateException("can't sign the client assertion", e);
        }
        return jwt.serialize();
    }

    private static RSAPrivateKey readKey(Path file) {
        try {
            String pem = Files.readString(file, StandardCharsets.US_ASCII);
            int start = pem.indexOf("-----BEGIN PRIVATE KEY-----");
            int end = pem.indexOf("-----END PRIVATE KEY-----");
            if (start < 0 || end < start) {
                throw new ConfigurationRefusedException("parity-admin-console.identity.key-file is not a PKCS#8 PEM key");
            }
            byte[] der = Base64.getMimeDecoder().decode(pem.substring(start + 27, end));
            return (RSAPrivateKey) KeyFactory.getInstance("RSA").generatePrivate(new PKCS8EncodedKeySpec(der));
        } catch (IOException | GeneralSecurityException | ClassCastException | IllegalArgumentException e) {
            throw new ConfigurationRefusedException("parity-admin-console.identity.key-file can't be read as an RSA key");
        }
    }

    private static String enc(String s) {
        return URLEncoder.encode(s, StandardCharsets.UTF_8);
    }
}
