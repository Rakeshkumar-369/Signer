package in.signer.server;

import in.signer.agent.AgentMain;
import in.signer.agent.config.AgentConfig;
import in.signer.core.testing.TestPki;
import in.signer.core.util.Bytes;
import in.signer.core.util.Json;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.node.ObjectNode;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Properties;

import static org.junit.jupiter.api.Assertions.*;

@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
class EndToEndTest {

    static final String ORIGIN = "https://eoffice.example.gov.in";
    static final String ADMIN_PASSWORD = "Admin12345pass";
    static TestPki pki;
    static Path dataDir;

    @LocalServerPort
    int port;

    final HttpClient http = HttpClient.newBuilder().proxy(HttpClient.Builder.NO_PROXY).build();
    AgentMain.Agent agent;
    String server;
    String agentUrl;
    String adminToken;
    String tenantId;
    String apiKey;

    @DynamicPropertySource
    static void props(DynamicPropertyRegistry r) throws Exception {
        pki = new TestPki();
        dataDir = Files.createTempDirectory("signer-server");
        Files.createDirectories(dataDir.resolve("trust"));
        Files.write(dataDir.resolve("trust/root.cer"), pki.root.getEncoded());
        r.add("signer.data-dir", dataDir::toString);
        // -De2e.jdbcUrl=jdbc:postgresql://... runs the suite against a real PostgreSQL/MySQL
        r.add("spring.datasource.url", () -> System.getProperty("e2e.jdbcUrl", "jdbc:h2:mem:e2e;DB_CLOSE_DELAY=-1"));
        r.add("signer.admin.initial-password", () -> ADMIN_PASSWORD);
        r.add("signer.tsa.url", pki::tsaUrl);
        r.add("signer.demo.enabled", () -> "true");
    }

    @BeforeAll
    void setUp() throws Exception {
        server = "http://127.0.0.1:" + port;
        Path p12 = pki.writePkcs12(dataDir.resolve("user.p12"), "pw".toCharArray());
        Properties p = new Properties();
        p.setProperty("agent.port", "0");
        p.setProperty("security.mode", "token");
        p.setProperty("security.serverUrl", server);
        p.setProperty("consent.mode", "auto");
        p.setProperty("token.providers", "pkcs12");
        p.setProperty("pkcs12.file", p12.toString());
        p.setProperty("pkcs12.password", "pw");
        p.setProperty("autostart", "false");
        agent = AgentMain.start(AgentConfig.of(p), true);
        assertTrue(agent.keyRing().refresh(true), "agent should download the server keys");
        agentUrl = "http://127.0.0.1:" + agent.server().port();

        JsonNode login = call("POST", server + "/api/admin/login", null, null, Json.MAPPER.createObjectNode()
                .put("username", "admin").put("password", ADMIN_PASSWORD), 200);
        assertTrue(login.get("mustChangePassword").asBoolean());
        adminToken = login.get("token").asString();

        ObjectNode t = Json.MAPPER.createObjectNode();
        t.put("code", "gad");
        t.put("name", "General Administration Department");
        t.put("plan", "enterprise");
        t.put("monthlyQuota", 5);
        t.putArray("allowedOrigins").add(ORIGIN).add("http://10.0.0.5:8080");
        tenantId = call("POST", server + "/api/admin/tenants", "Bearer " + adminToken, null, t, 200).get("tenant").get("id").asString();
        apiKey = call("POST", server + "/api/admin/tenants/" + tenantId + "/keys", "Bearer " + adminToken, null,
                Json.MAPPER.createObjectNode().put("label", "eoffice-prod"), 200).get("secret").asString();
    }

    @AfterAll
    void tearDown() {
        if (agent != null) {
            agent.stop();
        }
        pki.close();
    }

    JsonNode call(String method, String url, String auth, String origin, Object body, int expected) throws Exception {
        HttpRequest.Builder b = HttpRequest.newBuilder(URI.create(url)).header("Content-Type", "application/json")
                .method(method, body == null ? HttpRequest.BodyPublishers.noBody()
                        : HttpRequest.BodyPublishers.ofString(Json.MAPPER.writeValueAsString(body)));
        if (auth != null) {
            if (auth.startsWith("sk_")) {
                b.header("X-API-Key", auth);
            } else {
                b.header("Authorization", auth);
            }
        }
        if (origin != null) {
            b.header("Origin", origin);
        }
        HttpResponse<String> r = http.send(b.build(), HttpResponse.BodyHandlers.ofString());
        assertEquals(expected, r.statusCode(), method + " " + url + " -> " + r.body());
        return r.body().isEmpty() ? Json.MAPPER.createObjectNode() : Json.MAPPER.readTree(r.body());
    }

    String issueToken(int maxDocuments) throws Exception {
        ObjectNode req = Json.MAPPER.createObjectNode().put("origin", ORIGIN).put("maxDocuments", maxDocuments).put("reference", "FILE/42");
        return call("POST", server + "/api/v1/tokens", apiKey, null, req, 200).get("token").asString();
    }

    @Test
    void publishesKeysForAgents() throws Exception {
        JsonNode jwks = call("GET", server + "/.well-known/signer-keys", null, null, null, 200);
        assertEquals("Ed25519", jwks.get("keys").get(0).get("crv").asString());
    }

    @Test
    void agentSignsWholePdfWithServerIssuedToken() throws Exception {
        String token = issueToken(1);
        ObjectNode sign = Json.MAPPER.createObjectNode();
        sign.put("pdf", Bytes.b64(TestPki.samplePdf(1, 0)));
        sign.putObject("options").put("reason", "Approved").put("page", "1");
        JsonNode signed = call("POST", agentUrl + "/api/v1/sign/pdf", "Bearer " + token, ORIGIN, sign, 200);
        String pdf = signed.get("documents").get(0).get("data").asString();

        JsonNode report = call("POST", server + "/api/v1/pdf/verify", apiKey, null, Json.MAPPER.createObjectNode().put("pdf", pdf), 200)
                .get("report");
        assertEquals("VALID", report.get("signatures").get(0).get("status").asString(), report.toString());
        assertTrue(report.get("allValid").asBoolean());
    }

    @Test
    void serverPreparedHashSigningFromTheBrowser() throws Exception {
        String token = issueToken(1);
        // 1. browser asks the agent for the certificate
        JsonNode certs = call("POST", agentUrl + "/api/v1/certificates", "Bearer " + token, ORIGIN, Json.MAPPER.createObjectNode(), 200);
        String cert = certs.get("certificates").get(0).get("certificate").asString();
        // 2. server prepares the PDF (only the digest leaves the server)
        ObjectNode prep = Json.MAPPER.createObjectNode();
        prep.put("pdf", Bytes.b64(TestPki.samplePdf(2, 90)));
        prep.put("name", "note.pdf");
        prep.put("certificate", cert);
        prep.putObject("options").put("timestamp", true).put("subFilter", "ETSI.CAdES.detached").put("page", "2");
        JsonNode prepared = call("POST", server + "/api/v1/pdf/prepare", "Bearer " + token, ORIGIN, prep, 200);
        assertEquals("pades", prepared.get("format").asString());
        // 3. agent signs the digest on the token
        ObjectNode hash = Json.MAPPER.createObjectNode().put("digest", prepared.get("digest").asString()).put("format", "pades");
        JsonNode sig = call("POST", agentUrl + "/api/v1/sign/hash", "Bearer " + token, ORIGIN, hash, 200);
        // 4. server embeds signature + timestamp
        ObjectNode complete = Json.MAPPER.createObjectNode().put("sessionId", prepared.get("sessionId").asString())
                .put("signature", sig.get("signatures").get(0).get("signature").asString());
        JsonNode done = call("POST", server + "/api/v1/pdf/complete", "Bearer " + token, ORIGIN, complete, 200);
        assertTrue(done.get("timestamped").asBoolean());

        JsonNode report = call("POST", server + "/api/v1/pdf/verify", apiKey, null,
                Json.MAPPER.createObjectNode().put("pdf", done.get("pdf").asString()), 200).get("report");
        JsonNode s0 = report.get("signatures").get(0);
        assertEquals("VALID", s0.get("status").asString(), report.toString());
        assertTrue(s0.get("timestamped").asBoolean());

        // completing twice is rejected; transaction is recorded as completed
        call("POST", server + "/api/v1/pdf/complete", "Bearer " + token, ORIGIN, complete, 409);
        String txn = certs.get("txn").asString();
        JsonNode t = call("GET", server + "/api/v1/transactions/" + txn, apiKey, null, null, 200).get("transaction");
        assertEquals("COMPLETED", t.get("status").asString());
        assertEquals("RAVI KUMAR", t.get("signerName").asString());
    }

    @Test
    void foreignSignatureCannotCompleteSession() throws Exception {
        String token = issueToken(2);
        ObjectNode prep = Json.MAPPER.createObjectNode().put("pdf", Bytes.b64(TestPki.samplePdf(1, 0)));
        JsonNode prepared = call("POST", server + "/api/v1/pdf/prepare", apiKey, null, prep, 200);
        // sign a different digest
        ObjectNode hash = Json.MAPPER.createObjectNode().put("digest", Bytes.b64(Bytes.sha256("other".getBytes())));
        JsonNode sig = call("POST", agentUrl + "/api/v1/sign/hash", "Bearer " + token, ORIGIN, hash, 200);
        ObjectNode complete = Json.MAPPER.createObjectNode().put("sessionId", prepared.get("sessionId").asString())
                .put("signature", sig.get("signatures").get(0).get("signature").asString());
        JsonNode err = call("POST", server + "/api/v1/pdf/complete", apiKey, null, complete, 400);
        assertTrue(err.get("error").get("message").asString().contains("does not belong"));
    }

    @Test
    void tokenRulesAndCors() throws Exception {
        // unregistered origin
        call("POST", server + "/api/v1/tokens", apiKey, null, Json.MAPPER.createObjectNode().put("origin", "https://evil.example"), 403);
        // bad key
        call("POST", server + "/api/v1/tokens", "sk_invalid", null, Json.MAPPER.createObjectNode().put("origin", ORIGIN), 401);
        // token used from a different origin at the server
        String token = issueToken(1);
        call("POST", server + "/api/v1/pdf/prepare", "Bearer " + token, "http://10.0.0.5:8080",
                Json.MAPPER.createObjectNode().put("pdf", Bytes.b64(TestPki.samplePdf(1, 0))), 403);
        // CORS: allowed for tenant origins on signing endpoints, never for the token endpoint
        HttpResponse<String> pre = http.send(HttpRequest.newBuilder(URI.create(server + "/api/v1/pdf/prepare"))
                .method("OPTIONS", HttpRequest.BodyPublishers.noBody()).header("Origin", ORIGIN)
                .header("Access-Control-Request-Method", "POST").build(), HttpResponse.BodyHandlers.ofString());
        assertEquals(204, pre.statusCode());
        assertEquals(ORIGIN, pre.headers().firstValue("Access-Control-Allow-Origin").orElse(null));
        HttpResponse<String> preTok = http.send(HttpRequest.newBuilder(URI.create(server + "/api/v1/tokens"))
                .method("OPTIONS", HttpRequest.BodyPublishers.noBody()).header("Origin", ORIGIN)
                .header("Access-Control-Request-Method", "POST").build(), HttpResponse.BodyHandlers.ofString());
        assertTrue(preTok.headers().firstValue("Access-Control-Allow-Origin").isEmpty());
    }

    @Test
    void quotaSuspensionAndRevocation() throws Exception {
        ObjectNode t = Json.MAPPER.createObjectNode();
        t.put("code", "small");
        t.put("name", "Small Office");
        t.put("monthlyQuota", 1);
        t.putArray("allowedOrigins").add(ORIGIN);
        String id = call("POST", server + "/api/admin/tenants", "Bearer " + adminToken, null, t, 200).get("tenant").get("id").asString();
        JsonNode key = call("POST", server + "/api/admin/tenants/" + id + "/keys", "Bearer " + adminToken, null, null, 200);
        String secret = key.get("secret").asString();
        ObjectNode req = Json.MAPPER.createObjectNode().put("origin", ORIGIN);
        call("POST", server + "/api/v1/tokens", secret, null, req, 200);
        assertEquals("QUOTA_EXCEEDED", call("POST", server + "/api/v1/tokens", secret, null, req, 429).get("error").get("code").asString());

        call("POST", server + "/api/admin/tenants/" + id + "/status", "Bearer " + adminToken, null,
                Json.MAPPER.createObjectNode().put("status", "SUSPENDED"), 200);
        call("POST", server + "/api/v1/tokens", secret, null, req, 403);

        call("DELETE", server + "/api/admin/keys/" + key.get("apiKey").get("id").asString(), "Bearer " + adminToken, null, null, 200);
        call("POST", server + "/api/v1/tokens", secret, null, req, 401);
    }

    @Test
    void adminConsoleApis() throws Exception {
        String auth = "Bearer " + adminToken;
        JsonNode overview = call("GET", server + "/api/admin/overview", auth, null, null, 200);
        assertTrue(overview.get("license").get("evaluation").asBoolean());
        assertTrue(overview.get("agentConfig").asString().contains("security.serverUrl=" + "http://localhost:8080"));
        call("GET", server + "/api/admin/tenants", auth, null, null, 200);
        issueToken(1);
        JsonNode tx = call("GET", server + "/api/admin/transactions?tenantId=" + tenantId, auth, null, null, 200);
        assertTrue(tx.get("total").asLong() >= 1);
        HttpResponse<String> csv = http.send(HttpRequest.newBuilder(URI.create(server + "/api/admin/usage.csv"))
                .header("Authorization", auth).build(), HttpResponse.BodyHandlers.ofString());
        assertTrue(csv.body().contains("gad,General Administration Department"), csv.body());
        assertTrue(call("GET", server + "/api/admin/audit", auth, null, null, 200).get("total").asLong() > 0);
        call("GET", server + "/api/admin/overview", null, null, null, 401);
        call("GET", server + "/api/admin/overview", "Bearer forged.token.value", null, null, 401);

        // viewer accounts cannot change anything
        call("POST", server + "/api/admin/users", auth, null, Json.MAPPER.createObjectNode()
                .put("username", "auditor").put("password", "Viewer12345x").put("role", "VIEWER"), 200);
        String viewer = call("POST", server + "/api/admin/login", null, null, Json.MAPPER.createObjectNode()
                .put("username", "auditor").put("password", "Viewer12345x"), 200).get("token").asString();
        call("GET", server + "/api/admin/overview", "Bearer " + viewer, null, null, 200);
        call("POST", server + "/api/admin/tenants", "Bearer " + viewer, null, Json.MAPPER.createObjectNode(), 403);
    }

    @Test
    void loginLockout() throws Exception {
        ObjectNode bad = Json.MAPPER.createObjectNode().put("username", "nobody").put("password", "wrong");
        for (int i = 0; i < 5; i++) {
            call("POST", server + "/api/admin/login", null, null, bad, 401);
        }
        call("POST", server + "/api/admin/login", null, null, bad, 429);
    }

    @Test
    void demoPageAndSdkAreServed() throws Exception {
        HttpResponse<String> demo = http.send(HttpRequest.newBuilder(URI.create(server + "/demo/")).build(), HttpResponse.BodyHandlers.ofString());
        assertEquals(200, demo.statusCode());
        HttpResponse<String> sdk = http.send(HttpRequest.newBuilder(URI.create(server + "/sdk/signer.js")).build(), HttpResponse.BodyHandlers.ofString());
        assertEquals(200, sdk.statusCode());
        assertTrue(sdk.body().contains("class SignerClient"));
        JsonNode tok = call("POST", server + "/demo/api/token", null, "http://localhost:8080", Json.MAPPER.createObjectNode(), 200);
        assertNotNull(tok.get("token"));
    }
}
