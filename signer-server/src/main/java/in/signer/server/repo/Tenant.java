package in.signer.server.repo;

import java.time.Instant;
import java.util.List;

/** A licensed customer organisation (department, company) that integrates the signer. */
public record Tenant(
        String id,
        String code,
        String name,
        String contactEmail,
        String status,
        String plan,
        long monthlyQuota,
        Instant validUntil,
        List<String> allowedOrigins,
        Instant createdAt,
        Instant updatedAt) {

    public static final String ACTIVE = "ACTIVE";
    public static final String SUSPENDED = "SUSPENDED";

    public boolean active(Instant now) {
        return ACTIVE.equals(status) && (validUntil == null || now.isBefore(validUntil));
    }
}
