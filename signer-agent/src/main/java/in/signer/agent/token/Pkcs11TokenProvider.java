package in.signer.agent.token;

import in.signer.core.ErrorCode;
import in.signer.core.SignerException;
import in.signer.core.crypto.KeyRawSigner;
import in.signer.core.pdf.SigningKey;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.security.auth.login.LoginException;
import java.nio.file.Path;
import java.security.AuthProvider;
import java.security.Key;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.Security;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

/** Token accessed through the vendor's PKCS#11 library via the JDK SunPKCS11 provider. */
public final class Pkcs11TokenProvider implements TokenProvider {

    private static final Logger log = LoggerFactory.getLogger(Pkcs11TokenProvider.class);

    private final Path library;
    private final int slotIndex;
    private Provider provider;
    private String lastError;

    public Pkcs11TokenProvider(Path library, int slotIndex) {
        this.library = library;
        this.slotIndex = slotIndex;
    }

    @Override
    public String name() {
        return "pkcs11:" + library.getFileName() + "#" + slotIndex;
    }

    @Override
    public boolean requiresPin() {
        return true;
    }

    @Override
    public String lastError() {
        return lastError;
    }

    private synchronized Provider provider() {
        if (provider == null) {
            String lib = library.toAbsolutePath().toString().replace('\\', '/');
            String cfg = "--name=Signer-" + library.getFileName().toString().replaceAll("[^A-Za-z0-9]", "") + "-" + slotIndex + "\n"
                    + "library=" + lib + "\n"
                    + "slotListIndex=" + slotIndex + "\n";
            Provider base = Security.getProvider("SunPKCS11");
            if (base == null) {
                throw new SignerException(ErrorCode.INTERNAL_ERROR, "SunPKCS11 provider is not available in this Java runtime");
            }
            provider = base.configure(cfg);
        }
        return provider;
    }

    private synchronized void reset() {
        provider = null;
    }

    @Override
    public synchronized List<TokenCertificate> certificates() {
        try {
            KeyStore ks = KeyStore.getInstance("PKCS11", provider());
            ks.load(null, null);
            lastError = null;
            return KeyStoreTokenSupport.list(ks, this, name(), true);
        } catch (Exception e) {
            // No token in this slot, or token removed: forget the provider so it is re-created on the next call.
            lastError = TokenErrors.rootMessage(e);
            log.debug("{}: {}", name(), lastError);
            reset();
            return List.of();
        }
    }

    @Override
    public synchronized SigningKey unlock(TokenCertificate cert, char[] pin) {
        if (pin == null || pin.length == 0) {
            throw new SignerException(ErrorCode.PIN_INCORRECT, "Token PIN is required");
        }
        try {
            Provider p = provider();
            logout(p);
            KeyStore ks = KeyStore.getInstance("PKCS11", p);
            ks.load(null, pin);
            String alias = KeyStoreTokenSupport.aliasFor(ks, cert.certificate());
            if (alias == null) {
                throw new SignerException(ErrorCode.CERTIFICATE_NOT_FOUND,
                        "The private key for the selected certificate was not found on the token");
            }
            Key key = ks.getKey(alias, null);
            if (!(key instanceof PrivateKey pk)) {
                throw new SignerException(ErrorCode.CERTIFICATE_NOT_FOUND, "Selected certificate has no private key");
            }
            List<X509Certificate> chain = new ArrayList<>();
            Certificate[] cc = ks.getCertificateChain(alias);
            if (cc != null) {
                Arrays.stream(cc).map(X509Certificate.class::cast).forEach(chain::add);
            }
            if (chain.isEmpty()) {
                chain.add(cert.certificate());
            }
            return new SigningKey(cert.certificate(), chain, new KeyRawSigner(pk, p));
        } catch (Exception e) {
            SignerException se = TokenErrors.translate(e, "Opening the token");
            if (se.code() == ErrorCode.TOKEN_NOT_PRESENT) {
                reset();
            }
            throw se;
        } finally {
            Arrays.fill(pin, '\0');
        }
    }

    @Override
    public synchronized void release() {
        if (provider != null) {
            logout(provider);
        }
    }

    private static void logout(Provider p) {
        if (p instanceof AuthProvider ap) {
            try {
                ap.logout();
            } catch (LoginException | RuntimeException ignored) {
                // not logged in
            }
        }
    }
}
