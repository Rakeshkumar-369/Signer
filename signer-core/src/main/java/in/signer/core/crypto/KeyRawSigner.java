package in.signer.core.crypto;

import in.signer.core.ErrorCode;
import in.signer.core.SignerException;

import java.security.GeneralSecurityException;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.Signature;

/** {@link RawSigner} backed by a JCA {@link PrivateKey} (PKCS#11, Windows CNG/CAPI or software). */
public final class KeyRawSigner implements RawSigner {

    private final PrivateKey key;
    private final Provider provider;
    private final String algorithm;

    public KeyRawSigner(PrivateKey key, Provider provider) {
        this(key, provider, defaultAlgorithm(key));
    }

    public KeyRawSigner(PrivateKey key, Provider provider, String algorithm) {
        this.key = key;
        this.provider = provider;
        this.algorithm = algorithm;
    }

    public static String defaultAlgorithm(PrivateKey key) {
        String alg = key.getAlgorithm();
        if ("EC".equalsIgnoreCase(alg) || "ECDSA".equalsIgnoreCase(alg)) {
            return "SHA256withECDSA";
        }
        return "SHA256withRSA";
    }

    @Override
    public String algorithm() {
        return algorithm;
    }

    @Override
    public byte[] sign(byte[] toBeSigned) {
        try {
            Signature s = provider == null ? Signature.getInstance(algorithm) : Signature.getInstance(algorithm, provider);
            s.initSign(key);
            s.update(toBeSigned);
            return s.sign();
        } catch (GeneralSecurityException | RuntimeException e) {
            throw new SignerException(ErrorCode.SIGNING_FAILED, "Token could not create the signature: " + rootMessage(e), e);
        }
    }

    /**
     * Signs an externally computed SHA-256 digest (PKCS#1 v1.5 DigestInfo for RSA, plain digest for ECDSA).
     * Used by integrators that assemble their own CMS / XML signature.
     */
    public byte[] signDigest(byte[] sha256) {
        if (sha256 == null || sha256.length != 32) {
            throw SignerException.badRequest("Digest must be a 32-byte SHA-256 value");
        }
        boolean ec = algorithm.endsWith("ECDSA");
        byte[] input = ec ? sha256 : concat(SHA256_DIGEST_INFO_PREFIX, sha256);
        try {
            String alg = ec ? "NONEwithECDSA" : "NONEwithRSA";
            Signature s = provider == null ? Signature.getInstance(alg) : Signature.getInstance(alg, provider);
            s.initSign(key);
            s.update(input);
            return s.sign();
        } catch (GeneralSecurityException | RuntimeException e) {
            throw new SignerException(ErrorCode.SIGNING_FAILED, "Token could not sign the digest: " + rootMessage(e), e);
        }
    }

    private static final byte[] SHA256_DIGEST_INFO_PREFIX = {
            0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, (byte) 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05, 0x00, 0x04, 0x20};

    private static byte[] concat(byte[] a, byte[] b) {
        byte[] out = java.util.Arrays.copyOf(a, a.length + b.length);
        System.arraycopy(b, 0, out, a.length, b.length);
        return out;
    }

    static String rootMessage(Throwable t) {
        Throwable c = t;
        while (c.getCause() != null && c.getCause() != c) {
            c = c.getCause();
        }
        return c.getMessage() == null ? c.getClass().getSimpleName() : c.getMessage();
    }
}
