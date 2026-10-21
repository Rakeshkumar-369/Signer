package in.signer.core.pdf;

import in.signer.core.crypto.RawSigner;

import java.security.cert.X509Certificate;
import java.util.List;

/** A certificate, its chain (may be just the certificate) and the token-backed signer for its private key. */
public record SigningKey(X509Certificate certificate, List<X509Certificate> chain, RawSigner signer) {
}
