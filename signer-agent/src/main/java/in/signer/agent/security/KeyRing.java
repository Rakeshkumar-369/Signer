package in.signer.agent.security;

import in.signer.agent.config.AgentConfig;
import in.signer.core.token.Ed25519Keys;
import in.signer.core.util.Http;
import in.signer.core.util.Json;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import tools.jackson.databind.JsonNode;

import java.nio.file.Files;
import java.nio.file.Path;
import java.security.PublicKey;
import java.time.Duration;
import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Public keys of the Signer server(s) trusted to issue transaction tokens. Keys come from static configuration
 * and/or from {@code <serverUrl>/.well-known/signer-keys}, cached on disk so the agent works offline.
 */
public final class KeyRing {

    private static final Logger log = LoggerFactory.getLogger(KeyRing.class);
    private static final Duration REFRESH = Duration.ofHours(6);
    private static final Duration MIN_RETRY = Duration.ofMinutes(1);

    private final Map<String, PublicKey> staticKeys = new LinkedHashMap<>();
    private volatile Map<String, PublicKey> fetchedKeys = Map.of();
    private final String serverUrl;
    private final Path cacheFile;
    private volatile Instant lastFetch = Instant.EPOCH;
    private volatile Instant lastAttempt = Instant.EPOCH;

    public KeyRing(AgentConfig cfg) {
        this(cfg.get("security.trustedKeys"), cfg.get("security.serverUrl"), AgentConfig.userDataDir().resolve("server-keys.json"));
    }

    public KeyRing(String staticKeySpec, String serverUrl, Path cacheFile) {
        if (staticKeySpec != null) {
            for (String entry : staticKeySpec.split(",")) {
                String e = entry.strip();
                if (e.isEmpty()) {
                    continue;
                }
                int eq = e.indexOf('=');
                PublicKey key = Ed25519Keys.publicKeyFromString(eq > 0 ? e.substring(eq + 1) : e);
                staticKeys.put(eq > 0 ? e.substring(0, eq).strip() : Ed25519Keys.keyId(key), key);
            }
        }
        this.serverUrl = serverUrl == null || serverUrl.isBlank() ? null : serverUrl.strip().replaceAll("/+$", "");
        this.cacheFile = cacheFile;
        loadCache();
    }

    public Map<String, PublicKey> keys() {
        if (serverUrl != null && Duration.between(lastFetch, Instant.now()).compareTo(REFRESH) > 0) {
            refresh(false);
        }
        Map<String, PublicKey> all = new LinkedHashMap<>(fetchedKeys);
        all.putAll(staticKeys);
        return all;
    }

    public boolean isEmpty() {
        return keys().isEmpty();
    }

    /** Re-downloads the key set; used when a token names an unknown key (server key rotation). */
    public synchronized boolean refresh(boolean force) {
        if (serverUrl == null) {
            return false;
        }
        if (!force && Duration.between(lastAttempt, Instant.now()).compareTo(MIN_RETRY) < 0) {
            return false;
        }
        lastAttempt = Instant.now();
        try {
            byte[] body = Http.get(serverUrl + "/.well-known/signer-keys", Duration.ofSeconds(10));
            Map<String, PublicKey> keys = parse(Json.MAPPER.readTree(body));
            if (!keys.isEmpty()) {
                fetchedKeys = keys;
                lastFetch = Instant.now();
                Files.createDirectories(cacheFile.getParent());
                Files.write(cacheFile, body);
                log.info("Loaded {} signing key(s) from {}", keys.size(), serverUrl);
                return true;
            }
        } catch (Exception e) {
            log.warn("Could not refresh server keys from {}: {}", serverUrl, e.getMessage());
        }
        return false;
    }

    private void loadCache() {
        try {
            if (cacheFile != null && Files.isRegularFile(cacheFile)) {
                fetchedKeys = parse(Json.MAPPER.readTree(Files.readAllBytes(cacheFile)));
            }
        } catch (Exception e) {
            log.warn("Ignoring unreadable key cache {}: {}", cacheFile, e.getMessage());
        }
    }

    static Map<String, PublicKey> parse(JsonNode doc) {
        Map<String, PublicKey> out = new LinkedHashMap<>();
        for (JsonNode k : doc.path("keys")) {
            if ("OKP".equals(k.path("kty").asString("")) && "Ed25519".equals(k.path("crv").asString(""))) {
                PublicKey key = Ed25519Keys.publicKeyFromString(k.path("x").asString());
                out.put(k.path("kid").asString(Ed25519Keys.keyId(key)), key);
            }
        }
        return out;
    }
}
