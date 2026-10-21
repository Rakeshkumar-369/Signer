package in.signer.server.repo;

import java.time.Instant;

public record AuditEntry(String id, Instant occurredAt, String actor, String action, String target, String detail, String ip) {
}
