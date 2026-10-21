package in.signer.agent.token;

import in.signer.core.crypto.KeyRawSigner;
import in.signer.core.pdf.SigningKey;
import in.signer.core.ErrorCode;
import in.signer.core.SignerException;

import java.security.Key;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.util.List;

/**
 * Certificates in the current user's Windows "Personal" store (SunMSCAPI). USB tokens that ship a smart-card
 * minidriver or CSP (ePass2003, ProxKey, mToken, eToken, ...) appear here; the token driver shows its own PIN prompt.
 */
public final class WindowsStoreTokenProvider implements TokenProvider {

    private String lastError;

    @Override
    public String name() {
        return "windows:CurrentUser\\My";
    }

    @Override
    public boolean requiresPin() {
        return false;
    }

    @Override
    public String lastError() {
        return lastError;
    }

    private static KeyStore open() throws Exception {
        KeyStore ks = KeyStore.getInstance("Windows-MY");
        ks.load(null, null);
        return ks;
    }

    @Override
    public synchronized List<TokenCertificate> certificates() {
        try {
            List<TokenCertificate> list = KeyStoreTokenSupport.list(open(), this, name(), false);
            lastError = null;
            return list;
        } catch (Exception e) {
            lastError = TokenErrors.rootMessage(e);
            return List.of();
        }
    }

    @Override
    public synchronized SigningKey unlock(TokenCertificate cert, char[] pin) {
        try {
            KeyStore ks = open();
            String alias = KeyStoreTokenSupport.aliasFor(ks, cert.certificate());
            if (alias == null) {
                throw new SignerException(ErrorCode.CERTIFICATE_NOT_FOUND, "Certificate is no longer in the Windows certificate store");
            }
            Key key = ks.getKey(alias, null);
            if (!(key instanceof PrivateKey pk)) {
                throw new SignerException(ErrorCode.CERTIFICATE_NOT_FOUND, "Selected certificate has no private key");
            }
            return new SigningKey(cert.certificate(), cert.chain(), new KeyRawSigner(pk, ks.getProvider()));
        } catch (Exception e) {
            throw TokenErrors.translate(e, "Opening the certificate");
        }
    }

    @Override
    public void release() {
        // The Windows key handle is released by the driver; nothing to do.
    }
}
