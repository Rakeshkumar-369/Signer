package in.signer.server.repo;

import java.time.Instant;

/** One signing transaction (one issued transaction token). This is the billable unit. */
public record Txn(
        String id,
        String tenantId,
        String origin,
        String operations,
        int maxDocuments,
        String reference,
        String status,
        Instant issuedAt,
        Instant expiresAt,
        Instant completedAt,
        int documents,
        String signerName,
        String signerSerial,
        String documentHash,
        String clientIp,
        String error) {

    public static final String ISSUED = "ISSUED";
    public static final String COMPLETED = "COMPLETED";
    public static final String FAILED = "FAILED";
}
