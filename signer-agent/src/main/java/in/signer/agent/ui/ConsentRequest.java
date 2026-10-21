package in.signer.agent.ui;

import in.signer.core.cert.CertificateInfo;

import java.util.List;
import java.util.Set;

/**
 * What the user is asked to approve.
 *
 * @param pinRequiredFor ids of certificates for which the agent itself must collect the PIN (PKCS#11)
 * @param errorMessage   shown when re-asking, e.g. after an incorrect PIN
 */
public record ConsentRequest(
        String origin,
        String organisation,
        String reference,
        String action,
        List<String> documents,
        List<CertificateInfo> certificates,
        String preselectedId,
        Set<String> pinRequiredFor,
        String errorMessage) {

    public ConsentRequest withError(String message) {
        return new ConsentRequest(origin, organisation, reference, action, documents, certificates, preselectedId, pinRequiredFor, message);
    }
}
