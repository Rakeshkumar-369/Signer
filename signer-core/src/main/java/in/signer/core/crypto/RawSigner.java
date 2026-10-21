package in.signer.core.crypto;

/**
 * Produces a raw signature value over the given bytes using a private key that may live
 * on a hardware token. Implementations hash the input themselves (e.g. SHA256withRSA).
 */
public interface RawSigner {

    /** JCA signature algorithm name, e.g. {@code SHA256withRSA}. */
    String algorithm();

    byte[] sign(byte[] toBeSigned);
}
