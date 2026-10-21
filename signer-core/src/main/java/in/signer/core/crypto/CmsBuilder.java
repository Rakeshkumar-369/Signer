package in.signer.core.crypto;

import in.signer.core.ErrorCode;
import in.signer.core.SignerException;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.DERSet;
import org.bouncycastle.asn1.cms.Attribute;
import org.bouncycastle.asn1.cms.AttributeTable;
import org.bouncycastle.asn1.cms.CMSAttributes;
import org.bouncycastle.asn1.cms.Time;
import org.bouncycastle.asn1.ess.ESSCertIDv2;
import org.bouncycastle.asn1.ess.SigningCertificateV2;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.asn1.x509.IssuerSerial;
import org.bouncycastle.cert.jcajce.JcaCertStore;
import org.bouncycastle.cert.jcajce.JcaX509CertificateHolder;
import org.bouncycastle.cms.CMSAbsentContent;
import org.bouncycastle.cms.CMSAttributeTableGenerator;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.CMSSignedDataGenerator;
import org.bouncycastle.cms.DefaultSignedAttributeTableGenerator;
import org.bouncycastle.cms.SignerInfoGenerator;
import org.bouncycastle.cms.SignerInfoGeneratorBuilder;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.DefaultDigestAlgorithmIdentifierFinder;
import org.bouncycastle.operator.DefaultSignatureAlgorithmIdentifierFinder;
import org.bouncycastle.operator.DigestCalculator;
import org.bouncycastle.operator.DigestCalculatorProvider;

import java.io.ByteArrayOutputStream;
import java.io.OutputStream;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.Date;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * Builds a detached CMS SignedData structure from a pre-computed content digest.
 * Only the DER encoding of the signed attributes is sent to the token, so documents of any
 * size are signed with a single, fast token operation.
 */
public final class CmsBuilder {

    private CmsBuilder() {
    }

    public static byte[] build(byte[] contentDigest,
                               X509Certificate signerCert,
                               List<X509Certificate> chain,
                               RawSigner rawSigner,
                               CmsOptions options) {
        if (contentDigest == null || contentDigest.length != 32) {
            throw SignerException.badRequest("Content digest must be a 32-byte SHA-256 value");
        }
        try {
            AlgorithmIdentifier digestAlgId = new DefaultDigestAlgorithmIdentifierFinder().find("SHA-256");
            DigestCalculatorProvider digests = alg -> new PrecomputedDigest(digestAlgId, contentDigest);

            AttributeTable extra = options.pades()
                    ? new AttributeTable(signingCertificateV2(signerCert))
                    : new AttributeTable(new ASN1EncodableVector());
            CMSAttributeTableGenerator signedAttrs = new SignedAttributes(extra, !options.pades(), options.signingTime());

            SignerInfoGenerator sig = new SignerInfoGeneratorBuilder(digests)
                    .setSignedAttributeGenerator(signedAttrs)
                    .build(new TokenContentSigner(rawSigner), new JcaX509CertificateHolder(signerCert));

            Set<X509Certificate> certs = new LinkedHashSet<>();
            certs.add(signerCert);
            if (chain != null) {
                certs.addAll(chain);
            }
            CMSSignedDataGenerator gen = new CMSSignedDataGenerator();
            gen.addSignerInfoGenerator(sig);
            gen.addCertificates(new JcaCertStore(certs));
            CMSSignedData signed = gen.generate(new CMSAbsentContent(), false);
            return signed.getEncoded("DER");
        } catch (SignerException e) {
            throw e;
        } catch (Exception e) {
            if (e.getCause() instanceof SignerException se) {
                throw se;
            }
            throw new SignerException(ErrorCode.SIGNING_FAILED, "Unable to build CMS signature: " + e.getMessage(), e);
        }
    }

    private static Attribute signingCertificateV2(X509Certificate cert) throws CertificateEncodingException {
        byte[] hash = in.signer.core.util.Bytes.sha256(cert.getEncoded());
        X500Name issuer = new JcaX509CertificateHolder(cert).getIssuer();
        IssuerSerial issuerSerial = new IssuerSerial(new GeneralNames(new GeneralName(issuer)), cert.getSerialNumber());
        // SHA-256 is the default hash algorithm for ESSCertIDv2, so it is omitted per RFC 5035.
        ESSCertIDv2 id = new ESSCertIDv2(hash, issuerSerial);
        SigningCertificateV2 scv2 = new SigningCertificateV2(new ESSCertIDv2[]{id});
        return new Attribute(PKCSObjectIdentifiers.id_aa_signingCertificateV2, new DERSet(scv2));
    }

    /** Digest calculator that ignores its input and returns a digest computed elsewhere. */
    private record PrecomputedDigest(AlgorithmIdentifier alg, byte[] digest) implements DigestCalculator {
        @Override
        public AlgorithmIdentifier getAlgorithmIdentifier() {
            return alg;
        }

        @Override
        public OutputStream getOutputStream() {
            return OutputStream.nullOutputStream();
        }

        @Override
        public byte[] getDigest() {
            return digest.clone();
        }
    }

    /** Adds content-type and message-digest (and optionally signing-time) to the caller's attributes. */
    private static final class SignedAttributes implements CMSAttributeTableGenerator {
        private final DefaultSignedAttributeTableGenerator delegate;
        private final boolean includeSigningTime;
        private final Date signingTime;

        SignedAttributes(AttributeTable extra, boolean includeSigningTime, Date signingTime) {
            this.delegate = new DefaultSignedAttributeTableGenerator(extra);
            this.includeSigningTime = includeSigningTime;
            this.signingTime = signingTime;
        }

        @Override
        @SuppressWarnings({"rawtypes", "unchecked"})
        public AttributeTable getAttributes(Map params) {
            AttributeTable table = delegate.getAttributes(params);
            table = table.remove(CMSAttributes.signingTime);
            if (includeSigningTime) {
                Date t = signingTime == null ? new Date() : signingTime;
                table = table.add(CMSAttributes.signingTime, new Time(t));
            }
            return table;
        }
    }

    /** Bridges a BouncyCastle {@link ContentSigner} to a {@link RawSigner}. */
    private static final class TokenContentSigner implements ContentSigner {
        private final RawSigner raw;
        private final AlgorithmIdentifier algId;
        private final ByteArrayOutputStream buffer = new ByteArrayOutputStream();

        TokenContentSigner(RawSigner raw) {
            this.raw = raw;
            // BouncyCastle records RSA PKCS#1 v1.5 as rsaEncryption in the SignerInfo, which all PDF validators accept.
            this.algId = new DefaultSignatureAlgorithmIdentifierFinder().find(raw.algorithm());
        }

        @Override
        public AlgorithmIdentifier getAlgorithmIdentifier() {
            return algId;
        }

        @Override
        public OutputStream getOutputStream() {
            return buffer;
        }

        @Override
        public byte[] getSignature() {
            return raw.sign(buffer.toByteArray());
        }
    }
}
