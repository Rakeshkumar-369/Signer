package in.signer.core.token;

import in.signer.core.ErrorCode;
import in.signer.core.SignerException;
import in.signer.core.util.Bytes;
import in.signer.core.util.Json;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.node.ObjectNode;

import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.util.Map;

/** Compact JWS (RFC 7515) with the EdDSA / Ed25519 algorithm only. */
public final class Jws {

    private Jws() {
    }

    public static String sign(ObjectNode payload, String type, String keyId, PrivateKey key) {
        ObjectNode header = Json.MAPPER.createObjectNode();
        header.put("alg", "EdDSA");
        header.put("typ", type);
        header.put("kid", keyId);
        String signingInput = Bytes.b64url(Json.MAPPER.writeValueAsBytes(header)) + "."
                + Bytes.b64url(Json.MAPPER.writeValueAsBytes(payload));
        try {
            Signature s = Signature.getInstance("Ed25519");
            s.initSign(key);
            s.update(signingInput.getBytes(StandardCharsets.US_ASCII));
            return signingInput + "." + Bytes.b64url(s.sign());
        } catch (GeneralSecurityException e) {
            throw new SignerException(ErrorCode.INTERNAL_ERROR, "Unable to sign token", e);
        }
    }

    /** Verifies the signature against the key named by "kid" and returns the payload. */
    public static JsonNode verify(String token, String expectedType, Map<String, PublicKey> keys) {
        if (token == null || token.isBlank()) {
            throw new SignerException(ErrorCode.UNAUTHORIZED, "Missing token");
        }
        String[] parts = token.strip().split("\\.");
        if (parts.length != 3) {
            throw new SignerException(ErrorCode.TOKEN_INVALID, "Malformed token");
        }
        JsonNode header;
        JsonNode payload;
        try {
            header = Json.MAPPER.readTree(Bytes.fromB64url(parts[0]));
            payload = Json.MAPPER.readTree(Bytes.fromB64url(parts[1]));
        } catch (RuntimeException e) {
            throw new SignerException(ErrorCode.TOKEN_INVALID, "Malformed token");
        }
        if (!"EdDSA".equals(header.path("alg").asString(""))) {
            throw new SignerException(ErrorCode.TOKEN_INVALID, "Unsupported token algorithm");
        }
        if (expectedType != null && !expectedType.equals(header.path("typ").asString(""))) {
            throw new SignerException(ErrorCode.TOKEN_INVALID, "Unexpected token type");
        }
        PublicKey key = keys.get(header.path("kid").asString(""));
        if (key == null) {
            throw new SignerException(ErrorCode.TOKEN_INVALID, "Token was issued by an unknown key");
        }
        try {
            Signature s = Signature.getInstance("Ed25519");
            s.initVerify(key);
            s.update((parts[0] + "." + parts[1]).getBytes(StandardCharsets.US_ASCII));
            if (!s.verify(Bytes.fromB64url(parts[2]))) {
                throw new SignerException(ErrorCode.TOKEN_INVALID, "Token signature is invalid");
            }
        } catch (GeneralSecurityException e) {
            throw new SignerException(ErrorCode.TOKEN_INVALID, "Token signature is invalid");
        }
        return payload;
    }
}
