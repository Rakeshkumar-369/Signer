package in.signer.agent.http;

import in.signer.agent.security.RequestContext;
import in.signer.agent.security.RequestGuard;
import in.signer.agent.service.SigningService;
import in.signer.agent.token.TokenManager;
import in.signer.core.ErrorCode;
import in.signer.core.SignerException;
import in.signer.core.cert.CertificateFilter;
import in.signer.core.cert.CertificateInfo;
import in.signer.core.pdf.PdfSignOptions;
import in.signer.core.token.TransactionToken;
import in.signer.core.util.Bytes;
import in.signer.core.util.Json;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.node.ArrayNode;
import tools.jackson.databind.node.ObjectNode;

import java.nio.file.Path;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;

/** Implementation of the agent's JSON API (see docs/AGENT-API.md). */
public final class AgentApi {

    private final RequestGuard guard;
    private final SigningService signing;
    private final String version;
    private final long maxDocumentBytes;
    private final int maxBatch;
    private final boolean legacyEnabled;
    private final boolean tsaConfigured;
    private final int port;
    private final List<Path> configSources;

    public AgentApi(RequestGuard guard, SigningService signing, String version, long maxDocumentBytes, int maxBatch,
                    boolean legacyEnabled, boolean tsaConfigured, int port, List<Path> configSources) {
        this.guard = guard;
        this.signing = signing;
        this.version = version;
        this.maxDocumentBytes = maxDocumentBytes;
        this.maxBatch = maxBatch;
        this.legacyEnabled = legacyEnabled;
        this.tsaConfigured = tsaConfigured;
        this.port = port;
        this.configSources = configSources;
    }

    // ---------------------------------------------------------------- status

    public ObjectNode status() {
        ObjectNode n = ok();
        n.put("product", "Signer Agent");
        n.put("version", version);
        n.put("mode", guard.tokenMode() ? "token" : "allowlist");
        n.put("timestampAuthority", tsaConfigured);
        n.put("legacyApi", legacyEnabled);
        n.put("maxDocumentBytes", maxDocumentBytes);
        n.put("maxBatch", maxBatch);
        ArrayNode providers = n.putArray("tokens");
        int certs = 0;
        for (TokenManager.ProviderStatus s : signing.tokens().status()) {
            ObjectNode p = providers.addObject();
            p.put("name", s.name());
            p.put("certificates", s.certificates());
            p.put("pinPromptByAgent", s.requiresPin());
            if (s.error() != null && s.certificates() == 0) {
                p.put("error", s.error());
            }
            certs += s.certificates();
        }
        n.put("tokenPresent", certs > 0);
        return n;
    }

    // ---------------------------------------------------------- certificates

    public ObjectNode certificates(String origin, String token, JsonNode body) {
        RequestContext ctx = guard.authorize(origin, token, TransactionToken.OP_CERTIFICATES, 0);
        List<CertificateInfo> list = signing.certificates(Requests.filter(body));
        ObjectNode n = ok();
        n.put("txn", ctx.txn());
        n.set("certificates", Json.MAPPER.valueToTree(list));
        return n;
    }

    // -------------------------------------------------------------- sign/pdf

    public ObjectNode signPdf(String origin, String token, JsonNode body) {
        JsonNode common = body.get("options");
        List<SigningService.PdfJob> jobs = new ArrayList<>();
        if (body.has("documents")) {
            int i = 0;
            for (JsonNode d : body.get("documents")) {
                i++;
                String name = Requests.text(d, "name");
                jobs.add(new SigningService.PdfJob(name == null ? "document-" + i + ".pdf" : name,
                        decodePdf(Requests.text(d, "data"), "documents[" + (i - 1) + "].data"),
                        Requests.options(common, d.get("options"))));
            }
        } else {
            String name = Requests.text(body, "name");
            jobs.add(new SigningService.PdfJob(name == null ? "document.pdf" : name,
                    decodePdf(Requests.text(body, "pdf") != null ? Requests.text(body, "pdf") : Requests.text(body, "data"), "pdf"),
                    Requests.options(common, null)));
        }
        checkBatch(jobs.size());
        RequestContext ctx = guard.authorize(origin, token, TransactionToken.OP_SIGN, jobs.size());
        try {
            SigningService.Result<SigningService.PdfOutcome> r = signing.signPdfs(ctx, jobs, Requests.filter(body));
            ObjectNode n = ok();
            n.put("txn", ctx.txn());
            n.put("signedAt", Instant.now().toString());
            n.set("certificate", Json.MAPPER.valueToTree(r.certificate()));
            n.set("chain", Json.MAPPER.valueToTree(r.chain()));
            ArrayNode docs = n.putArray("documents");
            for (SigningService.PdfOutcome o : r.items()) {
                ObjectNode d = docs.addObject();
                d.put("name", o.name());
                d.put("size", o.signedPdf().length);
                d.put("sha256", Bytes.hex(Bytes.sha256(o.signedPdf())));
                d.put("data", Bytes.b64(o.signedPdf()));
            }
            return n;
        } catch (RuntimeException e) {
            guard.refund(ctx, jobs.size());
            throw e;
        }
    }

    // ------------------------------------------------------------- sign/hash

    public ObjectNode signHash(String origin, String token, JsonNode body) {
        List<SigningService.HashJob> jobs = new ArrayList<>();
        if (body.has("hashes")) {
            int i = 0;
            for (JsonNode h : body.get("hashes")) {
                String id = Requests.text(h, "id");
                jobs.add(new SigningService.HashJob(id == null ? "hash-" + i : id, digest(Requests.text(h, "digest"), "hashes[" + i + "].digest")));
                i++;
            }
        } else {
            jobs.add(new SigningService.HashJob("hash-0", digest(Requests.text(body, "digest"), "digest")));
        }
        checkBatch(jobs.size());
        String alg = Requests.text(body, "digestAlgorithm");
        if (alg != null && !alg.replace("-", "").equalsIgnoreCase("SHA256")) {
            throw SignerException.badRequest("Only SHA-256 digests are supported");
        }
        List<String> names = new ArrayList<>();
        body.path("documentNames").forEach(x -> names.add(x.asString()));
        RequestContext ctx = guard.authorize(origin, token, TransactionToken.OP_SIGN, jobs.size());
        try {
            SigningService.Result<SigningService.HashOutcome> r = signing.signHashes(ctx, jobs, Requests.filter(body),
                    Requests.text(body, "format"), body.path("timestamp").asBoolean(false), names);
            ObjectNode n = ok();
            n.put("txn", ctx.txn());
            n.put("format", Requests.text(body, "format") == null ? "cms" : Requests.text(body, "format").toLowerCase(Locale.ROOT));
            n.set("certificate", Json.MAPPER.valueToTree(r.certificate()));
            n.set("chain", Json.MAPPER.valueToTree(r.chain()));
            ArrayNode sigs = n.putArray("signatures");
            for (SigningService.HashOutcome o : r.items()) {
                ObjectNode s = sigs.addObject();
                s.put("id", o.id());
                s.put("signature", Bytes.b64(o.signature()));
            }
            return n;
        } catch (RuntimeException e) {
            guard.refund(ctx, jobs.size());
            throw e;
        }
    }

    // --------------------------------------------------------- legacy (APTS)

    /**
     * Command style API compatible with the APTS "Browser Signing Solution" request format:
     * {@code {"request":{"command":"pkiNetworkCertExt"|"pkinetworksign", ...}}}.
     */
    public ObjectNode legacy(String origin, String token, JsonNode body) {
        ObjectNode response = Json.MAPPER.createObjectNode();
        ObjectNode r = response.putObject("response");
        JsonNode req = body.path("request");
        String command = req.path("command").asString("");
        r.put("command", command);
        r.put("txn", req.path("txn").asString(null));
        r.put("ts", Instant.now().toString());
        try {
            if (!legacyEnabled) {
                throw new ApiException(404, "NOT_FOUND", "Legacy command API is disabled");
            }
            CertificateFilter filter = legacyFilter(req.path("certificate").path("attribute"));
            switch (command.toLowerCase(Locale.ROOT)) {
                case "pkinetworkcertext" -> {
                    ObjectNode certs = certificates(origin, token, Json.MAPPER.createObjectNode().set("certificate", toFilterNode(filter)));
                    ArrayNode out = r.putArray("certificates");
                    for (JsonNode c : certs.get("certificates")) {
                        out.add(legacyCert(c));
                    }
                    r.put("status", "success");
                    r.put("code", "0");
                    r.put("message", out.isEmpty() ? "No certificate found" : out.size() + " certificate(s) found");
                }
                case "pkinetworksign" -> {
                    JsonNode pdf = req.path("pdf");
                    ObjectNode options = legacyOptions(pdf);
                    ArrayNode warnings = r.putArray("warnings");
                    if (options.path("timestamp").asBoolean(false) && !tsaConfigured) {
                        options.put("timestamp", false);
                        warnings.add("Timestamp skipped: no timestamp authority configured on this computer");
                    }
                    ObjectNode modern = Json.MAPPER.createObjectNode();
                    modern.put("pdf", req.path("data").asString(null));
                    modern.set("options", options);
                    modern.set("certificate", toFilterNode(filter));
                    ObjectNode signed = signPdf(origin, token, modern);
                    JsonNode doc = signed.get("documents").get(0);
                    r.put("status", "success");
                    r.put("code", "0");
                    r.put("message", "Document signed successfully");
                    r.put("data", doc.get("data").asString());
                    r.set("certificate", legacyCert(signed.get("certificate")));
                }
                default -> throw SignerException.badRequest("Unknown command '" + command + "'");
            }
            response.put("ok", true);
        } catch (SignerException e) {
            fail(response, r, e.code().name(), e.getMessage());
        } catch (ApiException e) {
            fail(response, r, e.code, e.getMessage());
        }
        return response;
    }

    private static void fail(ObjectNode response, ObjectNode r, String code, String message) {
        response.put("ok", false);
        r.put("status", "failed");
        r.put("code", code);
        r.put("message", message);
    }

    static CertificateFilter legacyFilter(JsonNode attributes) {
        String cn = null, sn = null, o = null, ou = null, t = null, e = null, ca = null;
        for (JsonNode a : attributes) {
            String s = a.asString("");
            int eq = s.indexOf('=');
            if (eq <= 0 || eq == s.length() - 1) {
                continue;
            }
            String key = s.substring(0, eq).strip().toUpperCase(Locale.ROOT);
            String val = s.substring(eq + 1).strip();
            switch (key) {
                case "CN" -> cn = val;
                case "SN" -> sn = val;
                case "O" -> o = val;
                case "OU" -> ou = val;
                case "T" -> t = val;
                case "E" -> e = val;
                case "CA" -> ca = val;
                default -> { /* AP, TC and other vendor flags carry no filter meaning here */ }
            }
        }
        return new CertificateFilter(null, cn, sn, ca, o, ou, t, e, null, null, null);
    }

    private static ObjectNode toFilterNode(CertificateFilter f) {
        return Json.MAPPER.valueToTree(f);
    }

    private static ObjectNode legacyCert(JsonNode c) {
        ObjectNode n = Json.MAPPER.createObjectNode();
        n.put("CN", c.path("commonName").asString(""));
        n.put("O", c.path("organization").asString(""));
        n.put("OU", c.path("organizationalUnit").asString(""));
        n.put("T", c.path("title").asString(""));
        n.put("E", c.path("email").asString(""));
        n.put("SN", c.path("serialNumber").asString(""));
        n.put("CA", c.path("issuerCommonName").asString(""));
        n.put("validFrom", c.path("notBefore").asString(""));
        n.put("validTo", c.path("notAfter").asString(""));
        n.put("thumbprint", c.path("id").asString(""));
        n.put("class", c.path("certificateClass").asString(""));
        n.put("certificate", c.path("certificate").asString(""));
        return n;
    }

    static ObjectNode legacyOptions(JsonNode pdf) {
        ObjectNode o = Json.MAPPER.createObjectNode();
        float[] xy = pair(pdf.path("cood").asString(null), 10, 10);
        float[] wh = pair(pdf.path("size").asString(null), 200, 100);
        o.put("x", xy[0]);
        o.put("y", xy[1]);
        o.put("width", wh[0]);
        o.put("height", wh[1]);
        o.put("page", pdf.path("page").asString("1"));
        o.put("greenTick", yes(pdf.path("isgreentick")));
        o.put("ltv", yes(pdf.path("enableltv")));
        o.put("timestamp", yes(pdf.path("enabletimestamp")));
        if (pdf.hasNonNull("location")) {
            o.put("location", pdf.get("location").asString());
        }
        if (pdf.hasNonNull("reason")) {
            o.put("reason", pdf.get("reason").asString());
        }
        if (pdf.hasNonNull("dateformat") && !pdf.get("dateformat").asString().isBlank()) {
            o.put("dateFormat", pdf.get("dateformat").asString());
        }
        if (pdf.hasNonNull("customtext") && !pdf.get("customtext").asString().isBlank()) {
            o.put("customText", pdf.get("customtext").asString());
        }
        if (pdf.hasNonNull("password")) {
            o.put("pdfPassword", pdf.get("password").asString());
        }
        return o;
    }

    private static boolean yes(JsonNode n) {
        String v = n.asString("no").strip().toLowerCase(Locale.ROOT);
        return v.equals("yes") || v.equals("true") || v.equals("1") || v.equals("y");
    }

    private static float[] pair(String s, float d1, float d2) {
        if (s == null || s.isBlank()) {
            return new float[]{d1, d2};
        }
        String[] p = s.split("[,x ]+");
        try {
            return new float[]{Float.parseFloat(p[0].strip()), Float.parseFloat(p[1].strip())};
        } catch (RuntimeException e) {
            throw SignerException.badRequest("Invalid coordinate pair '" + s + "'");
        }
    }

    // ---------------------------------------------------------------- helpers

    private byte[] decodePdf(String b64, String field) {
        byte[] pdf = Bytes.fromB64(b64, field);
        if (pdf.length > maxDocumentBytes) {
            throw new SignerException(ErrorCode.PAYLOAD_TOO_LARGE,
                    "Document exceeds the " + maxDocumentBytes / 1024 / 1024 + " MB limit");
        }
        if (pdf.length < 5 || !new String(pdf, 0, Math.min(pdf.length, 1024), java.nio.charset.StandardCharsets.ISO_8859_1).contains("%PDF")) {
            throw new SignerException(ErrorCode.PDF_INVALID, "Field '" + field + "' is not a PDF document");
        }
        return pdf;
    }

    private static byte[] digest(String b64, String field) {
        byte[] d = Bytes.fromB64(b64, field);
        if (d.length != 32) {
            throw SignerException.badRequest("Field '" + field + "' must be a Base64 SHA-256 digest (32 bytes)");
        }
        return d;
    }

    private void checkBatch(int n) {
        if (n == 0) {
            throw SignerException.badRequest("Nothing to sign");
        }
        if (n > maxBatch) {
            throw SignerException.badRequest("At most " + maxBatch + " documents can be signed in one transaction");
        }
    }

    private static ObjectNode ok() {
        ObjectNode n = Json.MAPPER.createObjectNode();
        n.put("ok", true);
        return n;
    }

    // ------------------------------------------------------------ diagnostics

    public String diagnosticsHtml() {
        StringBuilder sb = new StringBuilder();
        sb.append("<!doctype html><html><head><meta charset=\"utf-8\"><title>Signer Agent</title><style>")
                .append("body{font-family:Segoe UI,Arial,sans-serif;margin:24px;color:#1a1a1a;background:#fff}")
                .append("h1{color:#0b4f8a;font-size:22px}h2{font-size:16px;margin-top:28px}")
                .append("table{border-collapse:collapse;width:100%;font-size:13px}td,th{border:1px solid #ddd;padding:6px 8px;text-align:left}")
                .append("th{background:#f3f6f9}.ok{color:#1e7e34;font-weight:600}.bad{color:#b02020;font-weight:600}code{background:#f3f3f3;padding:1px 4px}")
                .append("</style></head><body>");
        sb.append("<h1>Signer Agent ").append(esc(version)).append("</h1>");
        sb.append("<p class=\"ok\">The signing agent is running on port ").append(port).append(".</p>");
        sb.append("<p>Mode: <b>").append(guard.tokenMode() ? "token (licensed)" : "allow-list").append("</b> &middot; Timestamp authority: <b>")
                .append(tsaConfigured ? "configured" : "not configured").append("</b></p>");
        sb.append("<h2>Token connections</h2><table><tr><th>Source</th><th>Certificates</th><th>Status</th></tr>");
        for (TokenManager.ProviderStatus s : signing.tokens().status()) {
            sb.append("<tr><td>").append(esc(s.name())).append("</td><td>").append(s.certificates()).append("</td><td>")
                    .append(s.certificates() > 0 ? "<span class=\"ok\">Ready</span>" : esc(s.error() == null ? "No token" : s.error()))
                    .append("</td></tr>");
        }
        sb.append("</table><h2>Signing certificates</h2>");
        List<CertificateInfo> certs = signing.certificates(CertificateFilter.ANY);
        if (certs.isEmpty()) {
            sb.append("<p class=\"bad\">No signing certificate found. Insert your DSC USB token and refresh this page.</p>");
        } else {
            sb.append("<table><tr><th>Name</th><th>Issued by</th><th>Class</th><th>Valid till</th><th>Serial</th><th>Source</th></tr>");
            for (CertificateInfo c : certs) {
                sb.append("<tr><td>").append(esc(c.commonName())).append("</td><td>").append(esc(c.issuerCommonName()))
                        .append("</td><td>").append(esc(c.certificateClass())).append("</td><td>").append(esc(String.valueOf(c.notAfter())))
                        .append("</td><td>").append(esc(c.serialNumber())).append("</td><td>").append(esc(c.source())).append("</td></tr>");
            }
            sb.append("</table>");
        }
        sb.append("<h2>Configuration files</h2><ul>");
        for (Path p : configSources) {
            sb.append("<li><code>").append(esc(p.toString())).append("</code></li>");
        }
        if (configSources.isEmpty()) {
            sb.append("<li>Built-in defaults only</li>");
        }
        sb.append("</ul></body></html>");
        return sb.toString();
    }

    private static String esc(String s) {
        if (s == null) {
            return "";
        }
        return s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace("\"", "&quot;");
    }
}
