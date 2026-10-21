package in.signer.server.repo;

import java.time.Instant;

/** A server-prepared PDF waiting for the CMS signature produced on the user's token. */
public record SigningSession(
        String id,
        String tenantId,
        String txn,
        String status,
        String documentName,
        String digestHex,
        String certificate,
        boolean timestamp,
        boolean ltv,
        Instant createdAt,
        Instant expiresAt) {

    public static final String PREPARED = "PREPARED";
    public static final String COMPLETED = "COMPLETED";
}
