package in.signer.agent.http;

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;
import in.signer.agent.security.RequestGuard;
import in.signer.core.ErrorCode;
import in.signer.core.SignerException;
import in.signer.core.util.Json;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.node.ObjectNode;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.util.Locale;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

/**
 * Loopback-only HTTP server. Handles CORS (incl. Private/Local Network Access preflights), DNS-rebinding
 * protection via Host header validation, request size limits and uniform JSON error responses.
 */
public final class AgentHttpServer {

    private static final Logger log = LoggerFactory.getLogger(AgentHttpServer.class);

    private final HttpServer server;
    private final ExecutorService executor;
    private final int port;
    private final RequestGuard guard;
    private volatile AgentApi api;
    private final long maxBody;

    public AgentHttpServer(int port, RequestGuard guard, long maxBodyBytes) throws IOException {
        this.server = HttpServer.create(new InetSocketAddress(InetAddress.getLoopbackAddress(), port), 32);
        this.port = server.getAddress().getPort();
        this.guard = guard;
        this.maxBody = maxBodyBytes;
        this.executor = Executors.newFixedThreadPool(6, r -> {
            Thread t = new Thread(r, "agent-http");
            t.setDaemon(true);
            return t;
        });
        server.setExecutor(executor);
        server.createContext("/", this::handle);
    }

    public int port() {
        return port;
    }

    public void start(AgentApi api) {
        this.api = api;
        server.start();
        log.info("Signer agent listening on http://127.0.0.1:{}", port);
    }

    public void stop() {
        server.stop(0);
        executor.shutdownNow();
    }

    private void handle(HttpExchange ex) throws IOException {
        String origin = ex.getRequestHeaders().getFirst("Origin");
        try {
            if (!hostAllowed(ex.getRequestHeaders().getFirst("Host"))) {
                throw new ApiException(403, "HOST_NOT_ALLOWED", "Invalid Host header");
            }
            addCors(ex, origin);
            String method = ex.getRequestMethod().toUpperCase(Locale.ROOT);
            String path = ex.getRequestURI().getPath().replaceAll("/+$", "");
            if ("OPTIONS".equals(method)) {
                ex.sendResponseHeaders(204, -1);
                return;
            }
            if ("GET".equals(method) && (path.isEmpty() || path.equals("/index.html"))) {
                byte[] html = api.diagnosticsHtml().getBytes(StandardCharsets.UTF_8);
                ex.getResponseHeaders().set("Content-Type", "text/html; charset=utf-8");
                ex.getResponseHeaders().set("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'");
                send(ex, 200, html);
                return;
            }
            if ("GET".equals(method) && path.equals("/api/v1/status")) {
                sendJson(ex, 200, api.status());
                return;
            }
            if (!"POST".equals(method)) {
                throw new ApiException(405, "METHOD_NOT_ALLOWED", "Use POST");
            }
            JsonNode body = readJson(ex);
            String token = token(ex, body);
            ObjectNode result = switch (path) {
                case "/api/v1/certificates" -> api.certificates(origin, token, body);
                case "/api/v1/sign/pdf" -> api.signPdf(origin, token, body);
                case "/api/v1/sign/hash" -> api.signHash(origin, token, body);
                case "" -> api.legacy(origin, token, body);
                default -> throw new ApiException(404, "NOT_FOUND", "Unknown endpoint " + path);
            };
            sendJson(ex, 200, result);
        } catch (SignerException e) {
            sendError(ex, e.code().httpStatus(), e.code().name(), e.getMessage());
        } catch (ApiException e) {
            sendError(ex, e.status, e.code, e.getMessage());
        } catch (Exception e) {
            log.error("Unexpected error", e);
            sendError(ex, 500, ErrorCode.INTERNAL_ERROR.name(), "Unexpected error: " + e.getMessage());
        } finally {
            ex.close();
        }
    }

    private boolean hostAllowed(String host) {
        if (host == null) {
            return false;
        }
        String h = host.toLowerCase(Locale.ROOT);
        return h.equals("127.0.0.1:" + port) || h.equals("localhost:" + port) || h.equals("[::1]:" + port);
    }

    private void addCors(HttpExchange ex, String origin) {
        var h = ex.getResponseHeaders();
        h.set("Cache-Control", "no-store");
        h.set("X-Content-Type-Options", "nosniff");
        if (origin != null && guard.corsAllowed(origin)) {
            h.set("Access-Control-Allow-Origin", origin);
            h.set("Vary", "Origin");
            h.set("Access-Control-Allow-Methods", "GET, POST, OPTIONS");
            h.set("Access-Control-Allow-Headers", "Content-Type, Authorization, X-Signer-Token");
            h.set("Access-Control-Max-Age", "600");
            // Chrome Private Network Access / Local Network Access preflight
            if ("true".equalsIgnoreCase(ex.getRequestHeaders().getFirst("Access-Control-Request-Private-Network"))
                    || ex.getRequestHeaders().containsKey("Access-Control-Request-Local-Network")) {
                h.set("Access-Control-Allow-Private-Network", "true");
                h.set("Access-Control-Allow-Local-Network", "true");
            }
        }
    }

    private static String token(HttpExchange ex, JsonNode body) {
        String auth = ex.getRequestHeaders().getFirst("Authorization");
        if (auth != null && auth.regionMatches(true, 0, "Bearer ", 0, 7)) {
            return auth.substring(7).strip();
        }
        String hdr = ex.getRequestHeaders().getFirst("X-Signer-Token");
        if (hdr != null && !hdr.isBlank()) {
            return hdr.strip();
        }
        JsonNode t = body.path("token");
        if (t.isMissingNode()) {
            t = body.path("request").path("token");
        }
        return t.isString() ? t.asString() : null;
    }

    private JsonNode readJson(HttpExchange ex) throws IOException {
        String len = ex.getRequestHeaders().getFirst("Content-Length");
        if (len != null && Long.parseLong(len) > maxBody) {
            throw new SignerException(ErrorCode.PAYLOAD_TOO_LARGE, "Request exceeds " + (maxBody / 1024 / 1024) + " MB");
        }
        ByteArrayOutputStream buf = new ByteArrayOutputStream();
        try (InputStream in = ex.getRequestBody()) {
            byte[] chunk = new byte[64 * 1024];
            int n;
            long total = 0;
            while ((n = in.read(chunk)) > 0) {
                total += n;
                if (total > maxBody) {
                    throw new SignerException(ErrorCode.PAYLOAD_TOO_LARGE, "Request exceeds " + (maxBody / 1024 / 1024) + " MB");
                }
                buf.write(chunk, 0, n);
            }
        }
        if (buf.size() == 0) {
            return Json.MAPPER.createObjectNode();
        }
        try {
            JsonNode n = Json.MAPPER.readTree(buf.toByteArray());
            if (!n.isObject()) {
                throw SignerException.badRequest("Request body must be a JSON object");
            }
            return n;
        } catch (SignerException e) {
            throw e;
        } catch (RuntimeException e) {
            throw SignerException.badRequest("Request body is not valid JSON");
        }
    }

    private static void sendJson(HttpExchange ex, int status, ObjectNode body) throws IOException {
        ex.getResponseHeaders().set("Content-Type", "application/json; charset=utf-8");
        send(ex, status, Json.MAPPER.writeValueAsBytes(body));
    }

    private static void sendError(HttpExchange ex, int status, String code, String message) throws IOException {
        ObjectNode n = Json.MAPPER.createObjectNode();
        n.put("ok", false);
        ObjectNode err = n.putObject("error");
        err.put("code", code);
        err.put("message", message);
        try {
            sendJson(ex, status, n);
        } catch (IOException ignored) {
            // client went away
        }
    }

    private static void send(HttpExchange ex, int status, byte[] body) throws IOException {
        ex.sendResponseHeaders(status, body.length);
        try (OutputStream os = ex.getResponseBody()) {
            os.write(body);
        }
    }
}
