package in.signer.agent;

import in.signer.agent.config.AgentConfig;
import in.signer.core.cert.TrustAnchors;
import in.signer.core.pdf.PdfVerifier;
import in.signer.core.pdf.VerificationReport;
import in.signer.core.testing.TestPki;
import in.signer.core.token.Ed25519Keys;
import in.signer.core.token.Jws;
import in.signer.core.token.TransactionToken;
import in.signer.core.util.Bytes;
import in.signer.core.util.Json;
import org.bouncycastle.cms.CMSProcessableByteArray;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.jcajce.JcaSimpleSignerInfoVerifierBuilder;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.node.ObjectNode;

import java.io.InputStream;
import java.io.OutputStream;
import java.net.Socket;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyPair;
import java.security.Signature;
import java.time.Instant;
import java.util.List;
import java.util.Properties;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.*;

class AgentHttpTest {

    static final String ORIGIN = "https://eoffice.example.gov.in";
    static TestPki pki;
    static KeyPair serverKey;
    static AgentMain.Agent agent;
    static String base;
    static HttpClient http = HttpClient.newBuilder().proxy(HttpClient.Builder.NO_PROXY).build();

    @BeforeAll
    static void start() throws Exception {
        pki = new TestPki();
        Path dir = Files.createTempDirectory("agent");
        Path p12 = pki.writePkcs12(dir.resolve("signer.p12"), "secret".toCharArray());
        serverKey = Ed25519Keys.generate();

        Properties p = new Properties();
        p.setProperty("agent.port", "0");
        p.setProperty("security.mode", "token");
        p.setProperty("security.trustedKeys", Ed25519Keys.keyId(serverKey.getPublic()) + "=" + Ed25519Keys.publicKeyToString(serverKey.getPublic()));
        p.setProperty("consent.mode", "auto");
        p.setProperty("token.providers", "pkcs12");
        p.setProperty("pkcs12.file", p12.toString());
        p.setProperty("pkcs12.password", "secret");
        p.setProperty("tsa.url", pki.tsaUrl());
        p.setProperty("network.fetchIssuers", "true");
        p.setProperty("autostart", "false");
        agent = AgentMain.start(AgentConfig.of(p), true);
        base = "http://127.0.0.1:" + agent.server().port();
    }

    @AfterAll
    static void stop() {
        agent.stop();
        pki.close();
    }

    static String token(String origin, List<String> ops, int max) {
        Instant now = Instant.now();
        TransactionToken t = new TransactionToken(UUID.randomUUID().toString(), "test", "tenant-1", "General Administration Dept",
                origin, ops, max, "FILE-2026-001", now, now.plusSeconds(300));
        return Jws.sign(t.toClaims(), TransactionToken.TYPE, Ed25519Keys.keyId(serverKey.getPublic()), serverKey.getPrivate());
    }

    static HttpResponse<String> post(String path, String origin, String token, Object body) throws Exception {
        HttpRequest.Builder b = HttpRequest.newBuilder(URI.create(base + path))
                .header("Content-Type", "application/json")
                .POST(HttpRequest.BodyPublishers.ofString(Json.MAPPER.writeValueAsString(body)));
        if (origin != null) {
            b.header("Origin", origin);
        }
        if (token != null) {
            b.header("Authorization", "Bearer " + token);
        }
        return http.send(b.build(), HttpResponse.BodyHandlers.ofString());
    }

    static JsonNode json(HttpResponse<String> r) {
        return Json.MAPPER.readTree(r.body());
    }

    @Test
    void statusIsPublic() throws Exception {
        var r = http.send(HttpRequest.newBuilder(URI.create(base + "/api/v1/status")).build(), HttpResponse.BodyHandlers.ofString());
        assertEquals(200, r.statusCode());
        JsonNode n = json(r);
        assertTrue(n.get("ok").asBoolean());
        assertTrue(n.get("tokenPresent").asBoolean());
        assertEquals("token", n.get("mode").asString());
        var html = http.send(HttpRequest.newBuilder(URI.create(base + "/")).build(), HttpResponse.BodyHandlers.ofString());
        assertTrue(html.body().contains("RAVI KUMAR"));
    }

    @Test
    void rejectsForeignHostHeader() throws Exception {
        try (Socket s = new Socket("127.0.0.1", agent.server().port())) {
            OutputStream os = s.getOutputStream();
            os.write(("GET /api/v1/status HTTP/1.1\r\nHost: attacker.example:" + agent.server().port() + "\r\nConnection: close\r\n\r\n")
                    .getBytes(StandardCharsets.US_ASCII));
            os.flush();
            InputStream in = s.getInputStream();
            String resp = new String(in.readAllBytes(), StandardCharsets.US_ASCII);
            assertTrue(resp.startsWith("HTTP/1.1 403"), resp);
        }
    }

    @Test
    void preflightAllowsPrivateNetworkAccess() throws Exception {
        var r = http.send(HttpRequest.newBuilder(URI.create(base + "/api/v1/sign/pdf"))
                .method("OPTIONS", HttpRequest.BodyPublishers.noBody())
                .header("Origin", ORIGIN)
                .header("Access-Control-Request-Method", "POST")
                .header("Access-Control-Request-Private-Network", "true")
                .build(), HttpResponse.BodyHandlers.ofString());
        assertEquals(204, r.statusCode());
        assertEquals(ORIGIN, r.headers().firstValue("Access-Control-Allow-Origin").orElse(null));
        assertEquals("true", r.headers().firstValue("Access-Control-Allow-Private-Network").orElse(null));
    }

    @Test
    void certificatesRequireValidTokenForThisOrigin() throws Exception {
        assertEquals("UNAUTHORIZED", json(post("/api/v1/certificates", ORIGIN, null, Json.MAPPER.createObjectNode()))
                .path("error").path("code").asString());
        var wrongOrigin = post("/api/v1/certificates", "https://evil.example", token(ORIGIN, List.of("certificates"), 1), Json.MAPPER.createObjectNode());
        assertEquals(403, wrongOrigin.statusCode());
        assertEquals("ORIGIN_NOT_ALLOWED", json(wrongOrigin).path("error").path("code").asString());

        var ok = post("/api/v1/certificates", ORIGIN, token(ORIGIN, List.of("certificates"), 1), Json.MAPPER.createObjectNode());
        assertEquals(200, ok.statusCode(), ok.body());
        JsonNode certs = json(ok).get("certificates");
        assertEquals(1, certs.size());
        assertEquals("RAVI KUMAR", certs.get(0).get("commonName").asString());
        assertEquals("Class 3", certs.get(0).get("certificateClass").asString());
    }

    @Test
    void signPdfEndToEnd() throws Exception {
        ObjectNode body = Json.MAPPER.createObjectNode();
        body.put("name", "note-file.pdf");
        body.put("pdf", Bytes.b64(TestPki.samplePdf(1, 0)));
        ObjectNode opts = body.putObject("options");
        opts.put("reason", "Approved");
        opts.put("location", "Amaravati");
        opts.put("timestamp", true);
        opts.put("page", "1");
        String tok = token(ORIGIN, List.of("sign"), 1);
        var r = post("/api/v1/sign/pdf", ORIGIN, tok, body);
        assertEquals(200, r.statusCode(), r.body());
        JsonNode n = json(r);
        byte[] signed = Bytes.fromB64(n.get("documents").get(0).get("data").asString(), "data");
        VerificationReport rep = new PdfVerifier(TrustAnchors.empty().addAll(List.of(pki.root)), null, false).verify(signed, null);
        assertEquals(VerificationReport.Status.VALID, rep.signatures().get(0).status(), rep.toString());
        assertTrue(rep.signatures().get(0).timestamped());
        assertEquals(List.of("RAVI KUMAR", "Test Sub CA 2026", "Test Root CA 2026"),
                Json.MAPPER.convertValue(n.get("chain"), List.class));

        // the same token cannot be used again
        var again = post("/api/v1/sign/pdf", ORIGIN, tok, body);
        assertEquals("TOKEN_REPLAYED", json(again).path("error").path("code").asString());
    }

    @Test
    void batchLimitedByToken() throws Exception {
        ObjectNode body = Json.MAPPER.createObjectNode();
        var docs = body.putArray("documents");
        for (int i = 0; i < 3; i++) {
            ObjectNode d = docs.addObject();
            d.put("name", "doc" + i + ".pdf");
            d.put("data", Bytes.b64(TestPki.samplePdf(1, 0)));
        }
        var tooMany = post("/api/v1/sign/pdf", ORIGIN, token(ORIGIN, List.of("sign"), 2), body);
        assertEquals("TOKEN_REPLAYED", json(tooMany).path("error").path("code").asString());
        var ok = post("/api/v1/sign/pdf", ORIGIN, token(ORIGIN, List.of("sign"), 3), body);
        assertEquals(3, json(ok).get("documents").size(), ok.body());
    }

    @Test
    void failedSigningRefundsToken() throws Exception {
        ObjectNode bad = Json.MAPPER.createObjectNode();
        bad.put("pdf", Bytes.b64(TestPki.samplePdf(1, 0)));
        bad.putObject("options").put("x", 9999);
        String tok = token(ORIGIN, List.of("sign"), 1);
        assertEquals("BAD_REQUEST", json(post("/api/v1/sign/pdf", ORIGIN, tok, bad)).path("error").path("code").asString());
        ObjectNode good = Json.MAPPER.createObjectNode();
        good.put("pdf", Bytes.b64(TestPki.samplePdf(1, 0)));
        assertEquals(200, post("/api/v1/sign/pdf", ORIGIN, tok, good).statusCode());
    }

    @Test
    void signHashCmsAndRaw() throws Exception {
        byte[] content = "server prepared byte range".getBytes(StandardCharsets.UTF_8);
        byte[] digest = Bytes.sha256(content);
        ObjectNode body = Json.MAPPER.createObjectNode();
        body.put("digest", Bytes.b64(digest));
        body.put("format", "pades");
        var r = post("/api/v1/sign/hash", ORIGIN, token(ORIGIN, List.of("sign"), 1), body);
        assertEquals(200, r.statusCode(), r.body());
        byte[] cms = Bytes.fromB64(json(r).get("signatures").get(0).get("signature").asString(), "sig");
        var si = new CMSSignedData(new CMSProcessableByteArray(content), cms).getSignerInfos().getSigners().iterator().next();
        assertTrue(si.verify(new JcaSimpleSignerInfoVerifierBuilder().build(pki.signer)));

        body.put("format", "raw");
        var raw = post("/api/v1/sign/hash", ORIGIN, token(ORIGIN, List.of("sign"), 1), body);
        byte[] sig = Bytes.fromB64(json(raw).get("signatures").get(0).get("signature").asString(), "sig");
        Signature v = Signature.getInstance("SHA256withRSA");
        v.initVerify(pki.signer.getPublicKey());
        v.update(content);
        assertTrue(v.verify(sig));
    }

    @Test
    void legacyCommandsCompatibleWithAptsFormat() throws Exception {
        ObjectNode certReq = (ObjectNode) Json.MAPPER.readTree("""
                {"request":{"command":"pkiNetworkCertExt","ts":"2026-01-02T13:54:59.245Z","txn":"T1",
                 "certificate":{"attribute":["AP=1","CN=","SN=","TC=SG"]},"file":{"attribute":[]}}}""");
        ((ObjectNode) certReq.get("request")).put("token", token(ORIGIN, List.of("certificates", "sign"), 1));
        JsonNode certs = json(post("/", ORIGIN, null, certReq));
        assertEquals("success", certs.path("response").path("status").asString(), certs.toString());
        assertEquals("RAVI KUMAR", certs.path("response").path("certificates").get(0).path("CN").asString());

        ObjectNode signReq = (ObjectNode) Json.MAPPER.readTree("""
                {"request":{"command":"pkinetworksign","ts":"2026-01-02T13:55:57.454Z","txn":"T2",
                 "certificate":{"attribute":["CN=RAVI","O=","OU=","T=","E=","SN=","CA=","TC=SG","AP=1"]},
                 "file":{"attribute":["type=pdf"]},
                 "pdf":{"cood":"10,10","page":"1","size":"200,100","isgreentick":"yes","location":"Amaravati",
                        "enableltv":"no","enabletimestamp":"yes","reason":"Sign by RAVI KUMAR",
                        "dateformat":"dd-MMM-yyyy hh:mm tt","customtext":""}}}""");
        ObjectNode req = (ObjectNode) signReq.get("request");
        req.put("token", token(ORIGIN, List.of("sign"), 1));
        req.put("data", Bytes.b64(TestPki.samplePdf(1, 0)));
        JsonNode resp = json(post("/", ORIGIN, null, signReq));
        assertEquals("success", resp.path("response").path("status").asString(), resp.toString());
        byte[] signed = Bytes.fromB64(resp.path("response").path("data").asString(), "data");
        var rep = new PdfVerifier(TrustAnchors.empty().addAll(List.of(pki.root)), null, false).verify(signed, null);
        assertEquals("Sign by RAVI KUMAR", rep.signatures().get(0).reason());
        assertTrue(rep.signatures().get(0).integrityValid());

        ObjectNode noMatch = signReq.deepCopy();
        ((ObjectNode) noMatch.get("request")).put("token", token(ORIGIN, List.of("sign"), 1));
        ((ObjectNode) noMatch.get("request").get("certificate")).putArray("attribute").add("CN=SOMEONE ELSE");
        JsonNode fail = json(post("/", ORIGIN, null, noMatch));
        assertEquals("failed", fail.path("response").path("status").asString());
        assertEquals("CERTIFICATE_NOT_FOUND", fail.path("response").path("code").asString());
    }

    @Test
    void invalidRequestsAreRejectedCleanly() throws Exception {
        String tok = token(ORIGIN, List.of("sign"), 1);
        var notPdf = post("/api/v1/sign/pdf", ORIGIN, tok, Json.MAPPER.createObjectNode().put("pdf", Bytes.b64("hello".getBytes())));
        assertEquals("PDF_INVALID", json(notPdf).path("error").path("code").asString());
        var badHash = post("/api/v1/sign/hash", ORIGIN, tok, Json.MAPPER.createObjectNode().put("digest", "AAAA"));
        assertEquals("BAD_REQUEST", json(badHash).path("error").path("code").asString());
        var raw = http.send(HttpRequest.newBuilder(URI.create(base + "/api/v1/sign/pdf")).header("Origin", ORIGIN)
                .POST(HttpRequest.BodyPublishers.ofString("{not json")).build(), HttpResponse.BodyHandlers.ofString());
        assertEquals(400, raw.statusCode());
    }
}
