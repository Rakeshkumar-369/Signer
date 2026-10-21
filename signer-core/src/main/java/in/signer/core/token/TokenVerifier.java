package in.signer.core.token;

import in.signer.core.ErrorCode;
import in.signer.core.SignerException;
import tools.jackson.databind.JsonNode;

import java.security.PublicKey;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.Map;

/** Verifies transaction tokens offline using the server's published Ed25519 keys. */
public final class TokenVerifier {

    private final Map<String, PublicKey> keys;
    private final Duration skew;
    private final Clock clock;

    public TokenVerifier(Map<String, PublicKey> keys, Duration skew, Clock clock) {
        this.keys = Map.copyOf(keys);
        this.skew = skew;
        this.clock = clock;
    }

    public TokenVerifier(Map<String, PublicKey> keys) {
        this(keys, Duration.ofSeconds(120), Clock.systemUTC());
    }

    public boolean hasKeys() {
        return !keys.isEmpty();
    }

    public TransactionToken verify(String token) {
        JsonNode claims = Jws.verify(token, TransactionToken.TYPE, keys);
        if (!TransactionToken.AUDIENCE.equals(claims.path("aud").asString(""))) {
            throw new SignerException(ErrorCode.TOKEN_INVALID, "Token is not intended for the signing agent");
        }
        TransactionToken t = TransactionToken.fromClaims(claims);
        if (t.txn() == null || t.txn().isBlank()) {
            throw new SignerException(ErrorCode.TOKEN_INVALID, "Token has no transaction id");
        }
        Instant now = clock.instant();
        if (now.isAfter(t.expiresAt().plus(skew))) {
            throw new SignerException(ErrorCode.TOKEN_EXPIRED, "Transaction token has expired; request a new one");
        }
        if (now.isBefore(t.issuedAt().minus(skew))) {
            throw new SignerException(ErrorCode.TOKEN_INVALID, "Token is not yet valid; check the computer clock");
        }
        return t;
    }
}
