package parity.adminconsole.web;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;
import parity.adminconsole.lifecycle.LifecycleFiles;

/** Once the drain started, new API requests get 503 with {@code Retry-After: 1} (PLAN.md "Startup and graceful shutdown"). */
@Component
@Order(Ordered.HIGHEST_PRECEDENCE)
public class DrainFilter extends OncePerRequestFilter {

    private final LifecycleFiles files;

    public DrainFilter(LifecycleFiles files) {
        this.files = files;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
            throws ServletException, IOException {
        if (files.draining() && request.getRequestURI().startsWith("/api/")) {
            response.setStatus(503);
            response.setHeader("Retry-After", "1");
            response.setContentType("application/problem+json");
            response.getWriter().write("{\"type\":\"about:blank\",\"title\":\"Service Unavailable\",\"status\":503,\"code\":\"draining\"}");
            return;
        }
        chain.doFilter(request, response);
    }
}
