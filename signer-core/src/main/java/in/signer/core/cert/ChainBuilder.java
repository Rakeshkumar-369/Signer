package in.signer.core.cert;

import in.signer.core.util.Http;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.security.cert.X509Certificate;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Collection;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;

/**
 * Builds a certificate path from a signer certificate up to a root, using the certificates already
 * known (token chain, trust anchors) and, optionally, downloading missing issuers from AIA URLs.
 */
public final class ChainBuilder {

    private static final Logger log = LoggerFactory.getLogger(ChainBuilder.class);
    private static final int MAX_DEPTH = 8;

    private final Set<X509Certificate> pool = new LinkedHashSet<>();
    private final boolean fetchMissing;

    public ChainBuilder(TrustAnchors anchors, boolean fetchMissing) {
        if (anchors != null) {
            pool.addAll(anchors.roots());
            pool.addAll(anchors.intermediates());
        }
        this.fetchMissing = fetchMissing;
    }

    public ChainBuilder withCertificates(Collection<X509Certificate> certs) {
        if (certs != null) {
            pool.addAll(certs);
        }
        return this;
    }

    /** Returns the path starting with {@code leaf}; it ends at a self-signed root when one could be found. */
    public List<X509Certificate> build(X509Certificate leaf) {
        List<X509Certificate> chain = new ArrayList<>();
        chain.add(leaf);
        X509Certificate current = leaf;
        for (int depth = 0; depth < MAX_DEPTH && !Certificates.isSelfSigned(current); depth++) {
            X509Certificate issuer = findIssuer(current, pool);
            if (issuer == null && fetchMissing) {
                issuer = fetchIssuer(current);
            }
            if (issuer == null || chain.contains(issuer)) {
                break;
            }
            chain.add(issuer);
            current = issuer;
        }
        return chain;
    }

    public static X509Certificate findIssuer(X509Certificate cert, Collection<X509Certificate> candidates) {
        for (X509Certificate c : candidates) {
            if (c.getSubjectX500Principal().equals(cert.getIssuerX500Principal()) && !c.equals(cert)) {
                try {
                    cert.verify(c.getPublicKey());
                    return c;
                } catch (Exception ignored) {
                    // same name, different key
                }
            }
        }
        return null;
    }

    private X509Certificate fetchIssuer(X509Certificate cert) {
        for (String url : Certificates.caIssuerUrls(cert)) {
            if (!url.startsWith("http")) {
                continue;
            }
            try {
                List<X509Certificate> fetched = Certificates.parseAll(Http.get(url, Duration.ofSeconds(15)));
                pool.addAll(fetched);
                X509Certificate issuer = findIssuer(cert, fetched);
                if (issuer != null) {
                    return issuer;
                }
            } catch (Exception e) {
                log.warn("Could not download issuer certificate from {}: {}", url, e.getMessage());
            }
        }
        return null;
    }
}
