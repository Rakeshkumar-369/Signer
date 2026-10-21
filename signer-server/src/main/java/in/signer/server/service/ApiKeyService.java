package in.signer.server.service;

import in.signer.core.ErrorCode;
import in.signer.core.SignerException;
import in.signer.core.util.Bytes;
import in.signer.server.repo.ApiKey;
import in.signer.server.repo.ApiKeyRepository;
import in.signer.server.repo.Tenant;
import in.signer.server.repo.TenantRepository;
import org.springframework.stereotype.Service;

import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/** Creates, authenticates and revokes tenant API keys ("sk_..." secrets, stored as SHA-256 hashes). */
@Service
public class ApiKeyService {

    private static final SecureRandom RANDOM = new SecureRandom();

    public record Created(ApiKey key, String secret) {
    }

    private final ApiKeyRepository keys;
    private final TenantRepository tenants;
    private final Map<String, Long> lastTouch = new ConcurrentHashMap<>();

    public ApiKeyService(ApiKeyRepository keys, TenantRepository tenants) {
        this.keys = keys;
        this.tenants = tenants;
    }

    public Created create(String tenantId, String label) {
        tenants.findById(tenantId).orElseThrow(() -> new SignerException(ErrorCode.NOT_FOUND, "Tenant not found"));
        byte[] raw = new byte[32];
        RANDOM.nextBytes(raw);
        String secret = "sk_" + Bytes.b64url(raw);
        ApiKey k = keys.insert(tenantId, label == null || label.isBlank() ? "default" : label.strip(), secret.substring(0, 10), hash(secret));
        return new Created(k, secret);
    }

    public List<ApiKey> list(String tenantId) {
        return keys.findByTenant(tenantId);
    }

    public ApiKey revoke(String id) {
        ApiKey k = keys.findById(id).orElseThrow(() -> new SignerException(ErrorCode.NOT_FOUND, "API key not found"));
        keys.revoke(id);
        return k;
    }

    /** Resolves the tenant of an API key; the tenant must be active and within its validity period. */
    public Tenant authenticate(String secret) {
        if (secret == null || secret.isBlank()) {
            throw new SignerException(ErrorCode.UNAUTHORIZED, "Missing API key (X-API-Key header)");
        }
        ApiKey k = keys.findActiveByHash(hash(secret.strip()))
                .orElseThrow(() -> new SignerException(ErrorCode.UNAUTHORIZED, "Invalid or revoked API key"));
        Tenant t = tenants.findById(k.tenantId()).orElseThrow(() -> new SignerException(ErrorCode.UNAUTHORIZED, "Unknown tenant"));
        if (!t.active(Instant.now())) {
            throw new SignerException(ErrorCode.FORBIDDEN, "Tenant '" + t.code() + "' is suspended or its subscription has ended");
        }
        long now = System.currentTimeMillis();
        Long prev = lastTouch.get(k.id());
        if (prev == null || now - prev > 60_000) {
            lastTouch.put(k.id(), now);
            keys.touch(k.id());
        }
        return t;
    }

    static String hash(String secret) {
        return Bytes.hex(Bytes.sha256(secret.getBytes(StandardCharsets.UTF_8)));
    }
}
