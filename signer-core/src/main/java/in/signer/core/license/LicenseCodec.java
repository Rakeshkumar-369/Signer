package in.signer.core.license;

import in.signer.core.ErrorCode;
import in.signer.core.SignerException;
import in.signer.core.token.Ed25519Keys;
import in.signer.core.token.Jws;
import in.signer.core.util.Json;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.node.ObjectNode;

import java.security.PrivateKey;
import java.security.PublicKey;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

/** Issues and verifies licence files (an Ed25519 JWS signed with the vendor's licensing key). */
public final class LicenseCodec {

    public static final String TYPE = "signer-license";

    private LicenseCodec() {
    }

    public static String issue(LicenseInfo l, PrivateKey vendorKey) {
        ObjectNode n = Json.MAPPER.createObjectNode();
        n.put("lid", l.licenseId());
        n.put("licensee", l.licensee());
        n.put("edition", l.edition());
        n.put("iat", l.issuedAt().getEpochSecond());
        if (l.expiresAt() != null) {
            n.put("exp", l.expiresAt().getEpochSecond());
        }
        n.put("maxTenants", l.maxTenants());
        n.put("maxSignaturesPerMonth", l.maxSignaturesPerMonth());
        var f = n.putArray("features");
        l.features().forEach(f::add);
        PublicKey pub = Ed25519Keys.publicFromPrivate(vendorKey);
        return Jws.sign(n, TYPE, Ed25519Keys.keyId(pub), vendorKey);
    }

    public static LicenseInfo verify(String licenseText, PublicKey vendorKey) {
        try {
            JsonNode n = Jws.verify(licenseText.strip(), TYPE, Map.of(Ed25519Keys.keyId(vendorKey), vendorKey));
            List<String> features = new ArrayList<>();
            n.path("features").forEach(x -> features.add(x.asString()));
            return new LicenseInfo(
                    n.path("lid").asString(null),
                    n.path("licensee").asString(null),
                    n.path("edition").asString("standard"),
                    Instant.ofEpochSecond(n.path("iat").asLong(0)),
                    n.hasNonNull("exp") ? Instant.ofEpochSecond(n.path("exp").asLong()) : null,
                    n.path("maxTenants").asInt(0),
                    n.path("maxSignaturesPerMonth").asLong(0),
                    List.copyOf(features));
        } catch (SignerException e) {
            throw new SignerException(ErrorCode.LICENSE_INVALID, "Licence file is not valid: " + e.getMessage());
        }
    }
}
