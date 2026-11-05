package parity.adminconsole.security;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.servlet.HandlerInterceptor;
import org.springframework.web.servlet.config.annotation.InterceptorRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;
import parity.adminconsole.identity.TenantIdentities;
import parity.adminconsole.web.ApiException;

/**
 * Suspension cuts console access at once (decision 2026-10-31, review AC-007): every {@code /api}
 * request reads its caller's tenant's identity state, so a token issued before a suspension (it lives
 * up to 5 minutes) is refused from the next request on. A suspended tenant answers 403
 * {@code tenant_suspended}, a deleted one 403 {@code tenant_deleted}. Every caller is gated: there is no
 * staff caller here (user decision D2, 2026-11-03). A tenant without an identity row is no tenant this
 * console made (every tenant gets its row before its organization exists): 403, fail closed.
 * Sub-tenants a parent acts on are gated in {@link TenantScope}.
 */
@Configuration
public class TenantStateGate implements HandlerInterceptor, WebMvcConfigurer {

    private final TenantIdentities identities;

    public TenantStateGate(TenantIdentities identities) {
        this.identities = identities;
    }

    @Override
    public void addInterceptors(InterceptorRegistry registry) {
        registry.addInterceptor(this).addPathPatterns("/api/**").excludePathPatterns("/api/config");
    }

    @Override
    public boolean preHandle(HttpServletRequest request, HttpServletResponse response, Object handler) {
        Authentication a = SecurityContextHolder.getContext().getAuthentication();
        if (a instanceof CallerAuthentication ca) {
            TenantIdentities.Row row = identities.get(ca.getPrincipal().tenantId()).orElseThrow(ForbiddenException::new);
            switch (row.state()) {
                case ACTIVE -> { }
                case SUSPENDED -> throw ApiException.of(ApiException.Code.SUSPENDED_TENANT_ACCESS);
                case DELETED -> throw ApiException.of(ApiException.Code.DELETED_TENANT_ACCESS);
            }
        }
        return true;
    }
}
