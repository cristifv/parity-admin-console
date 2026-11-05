package parity.adminconsole.web;

import java.util.LinkedHashMap;
import java.util.Map;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;
import parity.adminconsole.config.AdminConsoleProperties;
import parity.adminconsole.security.Caller;

/**
 * {@code GET /api/me}: who the token says the caller is (the web shell's role-aware navigation), and
 * {@code GET /api/config}: what the shell needs to sign in (public: the issuer and the client id).
 */
@RestController
public class MeController {

    private final AdminConsoleProperties.Auth auth;

    public MeController(AdminConsoleProperties properties) {
        this.auth = properties.auth();
    }

    @GetMapping("/api/me")
    public Map<String, Object> me(@AuthenticationPrincipal Caller caller) {
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("subject", caller.subject());
        m.put("username", caller.username());
        m.put("tenant_id", caller.tenantId());
        m.put("roles", caller.roleNames());
        return m;
    }

    @GetMapping("/api/config")
    public Map<String, Object> config() {
        return Map.of("issuer", auth.browserIssuer(), "client_id", auth.browserClientId());
    }
}
