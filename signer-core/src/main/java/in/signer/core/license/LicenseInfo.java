package in.signer.core.license;

import java.time.Instant;
import java.util.List;

/**
 * Commercial licence for an on-premise Signer server installation.
 *
 * @param maxTenants            number of customer organisations (tenants) that may be configured; 0 = unlimited
 * @param maxSignaturesPerMonth server-wide monthly transaction cap; 0 = unlimited
 * @param features              enabled feature flags, e.g. "server-signing", "ltv", "verification"
 */
public record LicenseInfo(
        String licenseId,
        String licensee,
        String edition,
        Instant issuedAt,
        Instant expiresAt,
        int maxTenants,
        long maxSignaturesPerMonth,
        List<String> features) {

    public boolean expired(Instant now) {
        return expiresAt != null && now.isAfter(expiresAt);
    }

    public boolean hasFeature(String feature) {
        return features != null && (features.contains(feature) || features.contains("*"));
    }
}
