package in.signer.core.crypto;

import in.signer.core.ErrorCode;
import in.signer.core.SignerException;
import in.signer.core.util.Bytes;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.DERSet;
import org.bouncycastle.asn1.cms.Attribute;
import org.bouncycastle.asn1.cms.AttributeTable;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.SignerInformation;
import org.bouncycastle.cms.SignerInformationStore;
import org.bouncycastle.tsp.TimeStampToken;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

/** Adds an RFC 3161 signature timestamp (id-aa-signatureTimeStampToken) to every signer of a CMS structure. */
public final class CmsTimestamper {

    private CmsTimestamper() {
    }

    public static byte[] addSignatureTimestamp(byte[] cms, TimestampClient tsa) {
        try {
            CMSSignedData signedData = new CMSSignedData(cms);
            List<SignerInformation> updated = new ArrayList<>();
            for (SignerInformation signer : signedData.getSignerInfos().getSigners()) {
                TimeStampToken token = tsa.timestamp(Bytes.sha256(signer.getSignature()));
                AttributeTable unsigned = signer.getUnsignedAttributes();
                Attribute tsAttr = new Attribute(PKCSObjectIdentifiers.id_aa_signatureTimeStampToken,
                        new DERSet(ASN1Primitive.fromByteArray(token.getEncoded())));
                unsigned = unsigned == null
                        ? new AttributeTable(tsAttr)
                        : unsigned.remove(PKCSObjectIdentifiers.id_aa_signatureTimeStampToken)
                                .add(PKCSObjectIdentifiers.id_aa_signatureTimeStampToken, tsAttr.getAttrValues().getObjectAt(0));
                updated.add(SignerInformation.replaceUnsignedAttributes(signer, unsigned));
            }
            CMSSignedData result = CMSSignedData.replaceSigners(signedData, new SignerInformationStore(updated));
            return result.getEncoded("DER");
        } catch (CMSException | IOException e) {
            throw new SignerException(ErrorCode.TIMESTAMP_FAILED, "Unable to embed timestamp: " + e.getMessage(), e);
        }
    }
}
