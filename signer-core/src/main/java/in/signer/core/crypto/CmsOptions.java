package in.signer.core.crypto;

import java.util.Date;

/**
 * Options for building a detached CMS (PKCS#7) signature.
 *
 * @param pades          true for ETSI.CAdES.detached (PAdES baseline): adds signing-certificate-v2 and omits signing-time
 * @param signingTime    claimed signing time (used when {@code pades} is false); null means "now"
 */
public record CmsOptions(boolean pades, Date signingTime) {

    public static CmsOptions forPkcs7() {
        return new CmsOptions(false, null);
    }

    public static CmsOptions forPades() {
        return new CmsOptions(true, null);
    }
}
