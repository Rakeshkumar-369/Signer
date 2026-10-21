package in.signer.agent.http;

import in.signer.core.SignerException;
import in.signer.core.cert.CertificateFilter;
import in.signer.core.pdf.PdfSignOptions;
import in.signer.core.util.Json;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.node.ObjectNode;

/** JSON request parsing helpers. */
final class Requests {

    private Requests() {
    }

    static String text(JsonNode n, String field) {
        JsonNode v = n.get(field);
        return v == null || v.isNull() ? null : v.asString();
    }

    static CertificateFilter filter(JsonNode n) {
        JsonNode f = n.path("certificate");
        if (f.isMissingNode() || f.isNull()) {
            f = n.path("filter");
        }
        if (f.isString()) {
            return new CertificateFilter(f.asString(), null, null, null, null, null, null, null, null, null, null);
        }
        if (!f.isObject()) {
            return CertificateFilter.ANY;
        }
        return new CertificateFilter(
                text(f, "id"), text(f, "commonName"), text(f, "serialNumber"), text(f, "issuer"),
                text(f, "organization"), text(f, "organizationalUnit"), text(f, "title"), text(f, "email"),
                f.has("validOnly") ? f.get("validOnly").asBoolean() : null,
                f.has("signingOnly") ? f.get("signingOnly").asBoolean() : null,
                text(f, "certificateClass"));
    }

    /** Merges per-document options over request-level options into a {@link PdfSignOptions}. */
    static PdfSignOptions options(JsonNode common, JsonNode perDoc) {
        ObjectNode merged = Json.MAPPER.createObjectNode();
        if (common != null && common.isObject()) {
            merged.setAll((ObjectNode) common);
        }
        if (perDoc != null && perDoc.isObject()) {
            merged.setAll((ObjectNode) perDoc);
        }
        try {
            return Json.MAPPER.treeToValue(merged, PdfSignOptions.class);
        } catch (RuntimeException e) {
            throw SignerException.badRequest("Invalid signature options: " + e.getMessage());
        }
    }
}
