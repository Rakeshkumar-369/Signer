package in.signer.core.pdf;

/**
 * A PDF containing an empty signature placeholder, ready for a detached CMS signature.
 *
 * @param pdf       the PDF bytes, with the /Contents placeholder filled with zeros
 * @param byteRange the /ByteRange of the placeholder signature
 * @param digest    SHA-256 of the signed byte ranges (the value the CMS must sign)
 */
public record PreparedPdf(byte[] pdf, long[] byteRange, byte[] digest) {

    /** Number of bytes available for the DER encoded CMS signature. */
    public int capacity() {
        return (int) ((byteRange[2] - byteRange[1] - 2) / 2);
    }
}
