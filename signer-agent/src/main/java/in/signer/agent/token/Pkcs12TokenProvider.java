package in.signer.agent.token;

import in.signer.core.ErrorCode;
import in.signer.core.SignerException;
import in.signer.core.crypto.KeyRawSigner;
import in.signer.core.pdf.SigningKey;

import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.util.List;

/** Software certificate in a PKCS#12 file. Intended for development and testing only. */
public final class Pkcs12TokenProvider implements TokenProvider {

    private final Path file;
    private final char[] password;
    private String lastError;

    public Pkcs12TokenProvider(Path file, String password) {
        this.file = file;
        this.password = password == null ? new char[0] : password.toCharArray();
    }

    @Override
    public String name() {
        return "pkcs12:" + file.getFileName();
    }

    @Override
    public boolean requiresPin() {
        return false;
    }

    @Override
    public String lastError() {
        return lastError;
    }

    private KeyStore open() throws Exception {
        KeyStore ks = KeyStore.getInstance("PKCS12");
        try (InputStream in = Files.newInputStream(file)) {
            ks.load(in, password);
        }
        return ks;
    }

    @Override
    public List<TokenCertificate> certificates() {
        try {
            lastError = null;
            return KeyStoreTokenSupport.list(open(), this, name(), false);
        } catch (Exception e) {
            lastError = TokenErrors.rootMessage(e);
            return List.of();
        }
    }

    @Override
    public SigningKey unlock(TokenCertificate cert, char[] pin) {
        try {
            KeyStore ks = open();
            String alias = KeyStoreTokenSupport.aliasFor(ks, cert.certificate());
            if (alias == null) {
                throw new SignerException(ErrorCode.CERTIFICATE_NOT_FOUND, "Certificate not found in " + file);
            }
            PrivateKey key = (PrivateKey) ks.getKey(alias, password);
            return new SigningKey(cert.certificate(), cert.chain(), new KeyRawSigner(key, null));
        } catch (Exception e) {
            throw TokenErrors.translate(e, "Opening the PKCS#12 file");
        }
    }

    @Override
    public void release() {
    }
}
