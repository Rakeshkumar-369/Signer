package in.signer.agent.security;

import in.signer.agent.config.AgentConfig;
import in.signer.core.ErrorCode;
import in.signer.core.SignerException;
import in.signer.core.token.TokenVerifier;
import in.signer.core.token.TransactionToken;

import java.util.List;
import java.util.Locale;

/**
 * Authorises every agent request: origin allow-list, transaction token signature/expiry/origin binding,
 * permitted operations and single-use enforcement.
 */
public final class RequestGuard {

    public static final String NATIVE_ORIGIN = "native";

    private final boolean tokenMode;
    private final List<String> allowedOrigins;
    private final boolean allowNative;
    private final KeyRing keyRing;
    private final ReplayCache replay = new ReplayCache();

    public RequestGuard(AgentConfig cfg, KeyRing keyRing) {
        this(cfg.tokenMode(), cfg.allowedOrigins(), cfg.getBool("security.allowNativeClients", false), keyRing);
    }

    public RequestGuard(boolean tokenMode, List<String> allowedOrigins, boolean allowNative, KeyRing keyRing) {
        this.tokenMode = tokenMode;
        this.allowedOrigins = allowedOrigins;
        this.allowNative = allowNative;
        this.keyRing = keyRing;
    }

    public static String normalizeOrigin(String origin) {
        if (origin == null || origin.isBlank() || "null".equals(origin)) {
            return null;
        }
        return origin.strip().toLowerCase(Locale.ROOT).replaceAll("/+$", "");
    }

    /** Whether CORS headers may be sent for this origin (actual authorisation happens in {@link #authorize}). */
    public boolean corsAllowed(String origin) {
        String o = normalizeOrigin(origin);
        if (o == null) {
            return false;
        }
        if (!allowedOrigins.isEmpty()) {
            return allowedOrigins.contains(o);
        }
        return tokenMode;
    }

    public boolean tokenMode() {
        return tokenMode;
    }

    public RequestContext authorize(String originHeader, String token, String operation, int documents) {
        String origin = normalizeOrigin(originHeader);
        if (origin == null) {
            if (!allowNative) {
                throw new SignerException(ErrorCode.ORIGIN_NOT_ALLOWED, "Requests must come from a web page (Origin header missing)");
            }
            origin = NATIVE_ORIGIN;
        }
        if (!allowedOrigins.isEmpty() && !NATIVE_ORIGIN.equals(origin) && !allowedOrigins.contains(origin)) {
            throw new SignerException(ErrorCode.ORIGIN_NOT_ALLOWED, "This website (" + origin + ") is not allowed to use the signing agent");
        }
        if (!tokenMode) {
            if (allowedOrigins.isEmpty() && !NATIVE_ORIGIN.equals(origin)) {
                throw new SignerException(ErrorCode.ORIGIN_NOT_ALLOWED,
                        "The signing agent has no allowed websites configured (security.allowedOrigins)");
            }
            return new RequestContext(origin, null);
        }
        if (token == null || token.isBlank()) {
            throw new SignerException(ErrorCode.UNAUTHORIZED, "A transaction token is required");
        }
        TransactionToken t;
        try {
            t = new TokenVerifier(keyRing.keys()).verify(token);
        } catch (SignerException e) {
            if (e.code() == ErrorCode.TOKEN_INVALID && e.getMessage().contains("unknown key") && keyRing.refresh(false)) {
                t = new TokenVerifier(keyRing.keys()).verify(token);
            } else {
                throw e;
            }
        }
        if (!origin.equals(normalizeOrigin(t.origin()))) {
            throw new SignerException(ErrorCode.ORIGIN_NOT_ALLOWED, "The transaction token was issued for a different website");
        }
        if (!t.allows(operation)) {
            throw new SignerException(ErrorCode.FORBIDDEN, "The transaction token does not permit '" + operation + "'");
        }
        if (TransactionToken.OP_SIGN.equals(operation)) {
            replay.consume(t.txn(), documents, t.maxDocuments(), t.expiresAt());
        }
        return new RequestContext(origin, t);
    }

    /** Gives back the document allowance when a transaction failed before producing signatures. */
    public void refund(RequestContext ctx, int documents) {
        if (ctx.token() != null) {
            replay.refund(ctx.txn(), documents);
        }
    }
}
