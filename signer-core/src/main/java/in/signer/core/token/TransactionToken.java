package in.signer.core.token;

import in.signer.core.util.Json;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.node.ArrayNode;
import tools.jackson.databind.node.ObjectNode;

import java.time.Instant;
import java.util.ArrayList;
import java.util.List;

/**
 * Short-lived, single-transaction authorisation issued by the Signer server and verified offline by the
 * desktop agent. It binds a tenant, a browser origin, the allowed operations and a transaction id.
 *
 * @param txn          unique transaction id (JWS "jti")
 * @param tenantId     licensed customer ("sub")
 * @param tenantName   display name shown in the consent dialog
 * @param origin       web origin allowed to use the token, e.g. https://eoffice.ap.gov.in
 * @param operations   subset of {@code certificates}, {@code sign}
 * @param maxDocuments maximum documents that may be signed with this token
 * @param reference    free-text reference supplied by the integrating application (file number etc.)
 */
public record TransactionToken(
        String txn,
        String issuer,
        String tenantId,
        String tenantName,
        String origin,
        List<String> operations,
        int maxDocuments,
        String reference,
        Instant issuedAt,
        Instant expiresAt) {

    public static final String TYPE = "signer-txn+jwt";
    public static final String AUDIENCE = "signer-agent";
    public static final String OP_CERTIFICATES = "certificates";
    public static final String OP_SIGN = "sign";

    public boolean allows(String operation) {
        return operations.contains(operation);
    }

    public ObjectNode toClaims() {
        ObjectNode n = Json.MAPPER.createObjectNode();
        n.put("jti", txn);
        n.put("iss", issuer);
        n.put("sub", tenantId);
        n.put("aud", AUDIENCE);
        n.put("tnm", tenantName);
        n.put("origin", origin);
        ArrayNode ops = n.putArray("ops");
        operations.forEach(ops::add);
        n.put("max", maxDocuments);
        if (reference != null) {
            n.put("ref", reference);
        }
        n.put("iat", issuedAt.getEpochSecond());
        n.put("exp", expiresAt.getEpochSecond());
        return n;
    }

    public static TransactionToken fromClaims(JsonNode n) {
        List<String> ops = new ArrayList<>();
        n.path("ops").forEach(o -> ops.add(o.asString()));
        return new TransactionToken(
                n.path("jti").asString(null),
                n.path("iss").asString(null),
                n.path("sub").asString(null),
                n.path("tnm").asString(null),
                n.path("origin").asString(null),
                List.copyOf(ops),
                n.path("max").asInt(1),
                n.hasNonNull("ref") ? n.path("ref").asString() : null,
                Instant.ofEpochSecond(n.path("iat").asLong(0)),
                Instant.ofEpochSecond(n.path("exp").asLong(0)));
    }
}
