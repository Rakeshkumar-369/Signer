package in.signer.agent.token;

import in.signer.core.cert.Certificates;

import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;

/** Shared helpers for providers backed by a JCA {@link KeyStore}. */
final class KeyStoreTokenSupport {

    private KeyStoreTokenSupport() {
    }

    /** End-entity signing certificates in the key store (key entries, or certificate entries when keys are hidden until login). */
    static List<TokenCertificate> list(KeyStore ks, TokenProvider provider, String source, boolean includeCertificateEntries)
            throws KeyStoreException {
        List<TokenCertificate> out = new ArrayList<>();
        for (String alias : Collections.list(ks.aliases())) {
            boolean key = ks.isKeyEntry(alias);
            if (!key && !(includeCertificateEntries && ks.isCertificateEntry(alias))) {
                continue;
            }
            Certificate c = ks.getCertificate(alias);
            if (!(c instanceof X509Certificate x) || x.getBasicConstraints() >= 0) {
                continue;
            }
            List<X509Certificate> chain = new ArrayList<>();
            Certificate[] cc = key ? ks.getCertificateChain(alias) : null;
            if (cc != null) {
                Arrays.stream(cc).filter(X509Certificate.class::isInstance).map(X509Certificate.class::cast).forEach(chain::add);
            }
            if (chain.isEmpty()) {
                chain.add(x);
            }
            out.add(new TokenCertificate(x, chain, alias, provider, Certificates.describe(x, source)));
        }
        return out;
    }

    /** Finds the key-entry alias whose certificate equals {@code cert}. */
    static String aliasFor(KeyStore ks, X509Certificate cert) throws KeyStoreException {
        for (String alias : Collections.list(ks.aliases())) {
            if (ks.isKeyEntry(alias) && cert.equals(ks.getCertificate(alias))) {
                return alias;
            }
        }
        return null;
    }
}
