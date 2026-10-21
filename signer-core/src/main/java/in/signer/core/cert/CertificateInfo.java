package in.signer.core.cert;

import java.time.Instant;
import java.util.List;

/**
 * Description of a signing certificate, safe to return to a browser.
 *
 * @param id               stable identifier (SHA-1 thumbprint, upper-case hex, same as Windows "Thumbprint")
 * @param certificateClass Indian CCA class derived from the policy OIDs (e.g. "Class 3"), or null
 */
public record CertificateInfo(
        String id,
        String commonName,
        String subject,
        String organization,
        String organizationalUnit,
        String title,
        String email,
        String serialNumber,
        String issuer,
        String issuerCommonName,
        Instant notBefore,
        Instant notAfter,
        boolean currentlyValid,
        List<String> keyUsage,
        String keyAlgorithm,
        int keySize,
        String certificateClass,
        List<String> policies,
        String source,
        String certificate) {
}
