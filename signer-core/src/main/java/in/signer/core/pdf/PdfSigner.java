package in.signer.core.pdf;

import in.signer.core.ErrorCode;
import in.signer.core.SignerException;
import in.signer.core.cert.RevocationClient;
import in.signer.core.crypto.CmsBuilder;
import in.signer.core.crypto.CmsOptions;
import in.signer.core.crypto.CmsTimestamper;
import in.signer.core.crypto.TimestampClient;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.SignerInformation;
import org.bouncycastle.tsp.TimeStampToken;

import java.security.cert.X509Certificate;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Date;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;

/**
 * High level PDF signing: prepare, sign the digest on the token, optionally timestamp, inject, optionally add LTV data.
 * Instances are thread-safe; the TSA and revocation client are optional.
 */
public final class PdfSigner {

    private final TimestampClient tsa;
    private final RevocationClient revocation;

    public PdfSigner(TimestampClient tsa, RevocationClient revocation) {
        this.tsa = tsa;
        this.revocation = revocation;
    }

    public byte[] sign(byte[] pdf, PdfSignOptions options, SigningKey key) {
        PdfSignOptions o = options == null ? new PdfSignOptions() : options;
        Instant now = Instant.now();
        PreparedPdf prepared = PdfPreparer.prepare(pdf, o, key.certificate(), now);
        byte[] cms = CmsBuilder.build(prepared.digest(), key.certificate(), key.chain(), key.signer(),
                new CmsOptions(o.isPades(), Date.from(now)));
        return complete(prepared.pdf(), cms, o.timestamp, o.ltv, key.chain());
    }

    /**
     * Finishes a prepared PDF with a CMS signature produced elsewhere (e.g. by the desktop agent),
     * optionally adding a signature timestamp and LTV information.
     */
    public byte[] complete(byte[] preparedPdf, byte[] cms, boolean timestamp, boolean ltv, List<X509Certificate> extraCerts) {
        byte[] finalCms = cms;
        if (timestamp) {
            if (tsa == null) {
                throw new SignerException(ErrorCode.TIMESTAMP_FAILED, "Timestamp requested but no timestamp authority (TSA) is configured");
            }
            finalCms = CmsTimestamper.addSignatureTimestamp(cms, tsa);
        }
        byte[] signed = PdfPreparer.inject(preparedPdf, finalCms);
        if (ltv) {
            if (revocation == null) {
                throw new SignerException(ErrorCode.REVOCATION_FETCH_FAILED, "LTV requested but revocation checking is disabled");
            }
            signed = PdfLtv.addValidationData(signed, certificatesFor(finalCms, extraCerts), revocation);
        }
        return signed;
    }

    public boolean hasTsa() {
        return tsa != null;
    }

    /** Signer chain plus timestamp authority certificates contained in the CMS. */
    static List<X509Certificate> certificatesFor(byte[] cms, List<X509Certificate> extra) {
        Set<X509Certificate> out = new LinkedHashSet<>();
        if (extra != null) {
            out.addAll(extra);
        }
        try {
            JcaX509CertificateConverter conv = new JcaX509CertificateConverter();
            CMSSignedData sd = new CMSSignedData(cms);
            for (X509CertificateHolder h : sd.getCertificates().getMatches(null)) {
                out.add(conv.getCertificate(h));
            }
            for (SignerInformation si : sd.getSignerInfos().getSigners()) {
                var attrs = si.getUnsignedAttributes();
                if (attrs == null) {
                    continue;
                }
                var tsAttr = attrs.get(org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers.id_aa_signatureTimeStampToken);
                if (tsAttr != null) {
                    TimeStampToken token = new TimeStampToken(new CMSSignedData(tsAttr.getAttrValues().getObjectAt(0).toASN1Primitive().getEncoded()));
                    for (X509CertificateHolder h : token.getCertificates().getMatches(null)) {
                        out.add(conv.getCertificate(h));
                    }
                }
            }
        } catch (Exception e) {
            throw new SignerException(ErrorCode.SIGNING_FAILED, "Unreadable CMS signature: " + e.getMessage(), e);
        }
        return new ArrayList<>(out);
    }
}
