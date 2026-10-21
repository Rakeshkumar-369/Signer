package in.signer.server.web;

import in.signer.core.util.Json;
import in.signer.server.config.SignerProperties;
import in.signer.server.service.TenantService;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.Map;

/** Security headers, request size limit and CORS for browser-callable API endpoints. */
public final class HttpFilters {

    private HttpFilters() {
    }

    @Component
    @Order(Ordered.HIGHEST_PRECEDENCE)
    public static class SecurityHeaders extends OncePerRequestFilter {

        private final SignerProperties props;

        public SecurityHeaders(SignerProperties props) {
            this.props = props;
        }

        @Override
        protected void doFilterInternal(HttpServletRequest req, HttpServletResponse res, FilterChain chain)
                throws ServletException, IOException {
            res.setHeader("X-Content-Type-Options", "nosniff");
            res.setHeader("Referrer-Policy", "no-referrer");
            String path = req.getRequestURI();
            if (path.startsWith("/admin") || path.startsWith("/demo")) {
                res.setHeader("X-Frame-Options", "DENY");
                res.setHeader("Content-Security-Policy", "default-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data: blob:; frame-src 'self' blob:; "
                        + "object-src 'self' blob:; connect-src 'self' http://127.0.0.1:* http://localhost:*; frame-ancestors 'none'");
            }
            if (path.startsWith("/api/")) {
                res.setHeader("Cache-Control", "no-store");
            }
            long max = props.getMaxRequestMb() * 1024L * 1024L;
            if (req.getContentLengthLong() > max) {
                res.setStatus(413);
                res.setContentType("application/json");
                res.getWriter().write(Json.MAPPER.writeValueAsString(Map.of("ok", false,
                        "error", Map.of("code", "PAYLOAD_TOO_LARGE", "message", "Request exceeds " + props.getMaxRequestMb() + " MB"))));
                return;
            }
            chain.doFilter(req, res);
        }
    }

    /**
     * Allows browsers on registered tenant origins to call the signing endpoints with a transaction token.
     * The token-issuing endpoint is deliberately excluded: API keys must stay on the integrator's server.
     */
    @Component
    @Order(Ordered.HIGHEST_PRECEDENCE + 1)
    public static class Cors extends OncePerRequestFilter {

        private final TenantService tenants;

        public Cors(TenantService tenants) {
            this.tenants = tenants;
        }

        @Override
        protected boolean shouldNotFilter(HttpServletRequest req) {
            String p = req.getRequestURI();
            return !p.startsWith("/api/v1/") || p.startsWith("/api/v1/tokens");
        }

        @Override
        protected void doFilterInternal(HttpServletRequest req, HttpServletResponse res, FilterChain chain)
                throws ServletException, IOException {
            String origin = req.getHeader("Origin");
            boolean allowed = origin != null && tenants.activeOrigins().contains(TenantService.normalizeOrigin(origin));
            if (allowed) {
                res.setHeader("Access-Control-Allow-Origin", origin);
                res.setHeader("Vary", "Origin");
                res.setHeader("Access-Control-Allow-Methods", "GET, POST, OPTIONS");
                res.setHeader("Access-Control-Allow-Headers", "Content-Type, Authorization");
                res.setHeader("Access-Control-Max-Age", "600");
            }
            if ("OPTIONS".equalsIgnoreCase(req.getMethod()) && req.getHeader("Access-Control-Request-Method") != null) {
                res.setStatus(allowed ? 204 : 403);
                return;
            }
            chain.doFilter(req, res);
        }
    }
}
