package in.signer.core.pdf;

import in.signer.core.cert.CertificateInfo;

import java.time.Instant;
import java.util.List;

/** Result of verifying all signatures in a PDF. */
public record VerificationReport(int signatureCount, boolean allValid, boolean hasDss, List<SignatureResult> signatures) {

    /** Overall verdict of a single signature. */
    public enum Status {
        /** Integrity, certificate validity and trust chain all verified. */
        VALID,
        /** The document is intact but trust or revocation could not be fully established. */
        VALID_UNTRUSTED,
        /** The document was altered after signing, or the signature itself is broken or revoked. */
        INVALID
    }

    public record SignatureResult(
            String fieldName,
            Status status,
            String signerName,
            CertificateInfo certificate,
            List<String> chain,
            Instant signingTime,
            boolean timestamped,
            Instant timestampTime,
            String timestampAuthority,
            String reason,
            String location,
            String subFilter,
            boolean integrityValid,
            boolean coversWholeDocument,
            boolean certificateValidAtSigningTime,
            boolean chainTrusted,
            String revocation,
            int certificationLevel,
            List<String> notes) {
    }
}
