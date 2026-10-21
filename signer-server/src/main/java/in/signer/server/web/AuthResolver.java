package in.signer.server.web;

import in.signer.core.ErrorCode;
import in.signer.core.SignerException;
import in.signer.core.token.TransactionToken;
import in.signer.server.repo.Tenant;
import in.signer.server.service.AdminAuthService;
import in.signer.server.service.ApiKeyService;
import in.signer.server.service.TenantService;
import in.signer.server.service.TransactionService;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.stereotype.Component;

/** Resolves the caller: tenant API key, browser transaction token, or administrator session. */
@Component
public class AuthResolver {

    /** Tenant identity; {@code token} is set when the browser authenticated with a transaction token. */
    public record TenantAuth(Tenant tenant, TransactionToken token) {
        public String txn() {
            return token == null ? null : token.txn();
        }

        public String actor() {
            return token == null ? "api-key:" + tenant.code() : "token:" + tenant.code();
        }
    }

    private final ApiKeyService apiKeys;
    private final TransactionService transactions;
    private final TenantService tenants;
    private final AdminAuthService admins;

    public AuthResolver(ApiKeyService apiKeys, TransactionService transactions, TenantService tenants, AdminAuthService admins) {
        this.apiKeys = apiKeys;
        this.transactions = transactions;
        this.tenants = tenants;
        this.admins = admins;
    }

    public Tenant apiKey(HttpServletRequest req) {
        return apiKeys.authenticate(req.getHeader("X-API-Key"));
    }

    /** Accepts either an API key (server-to-server) or a transaction token (browser) permitting {@code operation}. */
    public TenantAuth tenantOrToken(HttpServletRequest req, String operation) {
        if (req.getHeader("X-API-Key") != null) {
            return new TenantAuth(apiKey(req), null);
        }
        String bearer = bearer(req);
        if (bearer == null) {
            throw new SignerException(ErrorCode.UNAUTHORIZED, "Provide an X-API-Key header or a transaction token (Authorization: Bearer)");
        }
        TransactionToken t = transactions.verifyBearer(bearer);
        if (operation != null && !t.allows(operation)) {
            throw new SignerException(ErrorCode.FORBIDDEN, "The transaction token does not permit '" + operation + "'");
        }
        String origin = req.getHeader("Origin");
        if (origin != null && !TenantService.normalizeOrigin(origin).equals(TenantService.normalizeOrigin(t.origin()))) {
            throw new SignerException(ErrorCode.ORIGIN_NOT_ALLOWED, "The transaction token was issued for a different website");
        }
        return new TenantAuth(tenants.get(t.tenantId()), t);
    }

    public AdminAuthService.Principal admin(HttpServletRequest req) {
        return admins.authenticate(bearer(req));
    }

    public AdminAuthService.Principal adminWrite(HttpServletRequest req) {
        AdminAuthService.Principal p = admin(req);
        if (!p.isAdmin()) {
            throw new SignerException(ErrorCode.FORBIDDEN, "Administrator role required");
        }
        return p;
    }

    static String bearer(HttpServletRequest req) {
        String h = req.getHeader("Authorization");
        if (h != null && h.regionMatches(true, 0, "Bearer ", 0, 7)) {
            return h.substring(7).strip();
        }
        return null;
    }

    public static String clientIp(HttpServletRequest req) {
        return req.getRemoteAddr();
    }
}
