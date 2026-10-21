package in.signer.server.repo;

import java.time.Instant;

/** Server-to-server credential of a tenant. Only the SHA-256 hash of the secret is stored. */
public record ApiKey(String id, String tenantId, String label, String prefix, Instant createdAt, Instant lastUsedAt, Instant revokedAt) {
}
