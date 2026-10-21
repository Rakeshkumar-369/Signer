package in.signer.core.cert;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.stream.Stream;

/**
 * Set of trusted root (and optional intermediate) certificates, loaded from a directory of
 * {@code .cer/.crt/.pem/.der/.p7b} files. For Indian DSCs put the CCA India root certificates here.
 */
public final class TrustAnchors {

    private static final Logger log = LoggerFactory.getLogger(TrustAnchors.class);

    private final List<X509Certificate> roots = new ArrayList<>();
    private final List<X509Certificate> intermediates = new ArrayList<>();

    public static TrustAnchors empty() {
        return new TrustAnchors();
    }

    public static TrustAnchors fromDirectory(Path dir) {
        TrustAnchors t = new TrustAnchors();
        if (dir == null || !Files.isDirectory(dir)) {
            return t;
        }
        try (Stream<Path> files = Files.list(dir)) {
            files.filter(Files::isRegularFile)
                    .filter(f -> f.getFileName().toString().toLowerCase().matches(".*\\.(cer|crt|pem|der|p7b|p7c)$"))
                    .forEach(f -> {
                        try {
                            t.addAll(Certificates.parseAll(Files.readAllBytes(f)));
                        } catch (IOException | RuntimeException e) {
                            log.warn("Skipping unreadable trust anchor {}: {}", f, e.getMessage());
                        }
                    });
        } catch (IOException e) {
            log.warn("Cannot read trust anchor directory {}: {}", dir, e.getMessage());
        }
        log.info("Loaded {} root and {} intermediate certificates from {}", t.roots.size(), t.intermediates.size(), dir);
        return t;
    }

    public TrustAnchors addAll(Collection<X509Certificate> certs) {
        for (X509Certificate c : certs) {
            if (Certificates.isSelfSigned(c)) {
                roots.add(c);
            } else {
                intermediates.add(c);
            }
        }
        return this;
    }

    public List<X509Certificate> roots() {
        return roots;
    }

    public List<X509Certificate> intermediates() {
        return intermediates;
    }

    public boolean isEmpty() {
        return roots.isEmpty();
    }

    public boolean isTrustedRoot(X509Certificate cert) {
        for (X509Certificate r : roots) {
            if (r.equals(cert)) {
                return true;
            }
        }
        return false;
    }
}
