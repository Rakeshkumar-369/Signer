package in.signer.agent.token;

import in.signer.core.cert.CertificateInfo;

import java.security.cert.X509Certificate;
import java.util.List;

/** A certificate found on a token, together with where it came from. */
public record TokenCertificate(X509Certificate certificate, List<X509Certificate> chain, String alias,
                               TokenProvider provider, CertificateInfo info) {

    public String id() {
        return info.id();
    }
}
