package in.signer.core.pdf;

import in.signer.core.ErrorCode;
import in.signer.core.SignerException;
import in.signer.core.cert.CertificateInfo;
import in.signer.core.cert.Certificates;
import in.signer.core.cert.ChainBuilder;
import in.signer.core.cert.RevocationClient;
import in.signer.core.cert.TrustAnchors;
import in.signer.core.util.Bytes;
import org.apache.pdfbox.cos.COSArray;
import org.apache.pdfbox.cos.COSBase;
import org.apache.pdfbox.cos.COSDictionary;
import org.apache.pdfbox.cos.COSName;
import org.apache.pdfbox.pdmodel.PDDocument;
import org.apache.pdfbox.pdmodel.interactive.digitalsignature.PDSignature;
import org.apache.pdfbox.pdmodel.interactive.form.PDAcroForm;
import org.apache.pdfbox.pdmodel.interactive.form.PDField;
import org.apache.pdfbox.pdmodel.interactive.form.PDSignatureField;
import org.bouncycastle.asn1.cms.Attribute;
import org.bouncycastle.asn1.cms.AttributeTable;
import org.bouncycastle.asn1.cms.CMSAttributes;
import org.bouncycastle.asn1.cms.Time;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cms.CMSProcessableByteArray;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.SignerInformation;
import org.bouncycastle.cms.jcajce.JcaSimpleSignerInfoVerifierBuilder;
import org.bouncycastle.tsp.TimeStampToken;

import java.security.cert.X509Certificate;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/** Verifies every signature in a PDF: integrity, timestamp, certificate validity, chain trust and (optionally) revocation. */
public final class PdfVerifier {

    private final TrustAnchors anchors;
    private final RevocationClient revocation;
    private final boolean fetchIssuers;

    public PdfVerifier(TrustAnchors anchors, RevocationClient revocation, boolean fetchIssuers) {
        this.anchors = anchors == null ? TrustAnchors.empty() : anchors;
        this.revocation = revocation;
        this.fetchIssuers = fetchIssuers;
    }

    public VerificationReport verify(byte[] pdf, String password) {
        try (PDDocument doc = PdfPreparer.load(pdf, password)) {
            Map<COSDictionary, String> names = fieldNames(doc);
            List<PDSignature> sigs = doc.getSignatureDictionaries();
            List<VerificationReport.SignatureResult> results = new ArrayList<>();
            int mdp = PdfPreparer.docMdpPermission(doc);
            for (PDSignature sig : sigs) {
                results.add(verifyOne(pdf, sig, names.get(sig.getCOSObject()), mdp));
            }
            boolean allValid = !results.isEmpty()
                    && results.stream().allMatch(r -> r.status() == VerificationReport.Status.VALID);
            return new VerificationReport(results.size(), allValid, PdfLtv.hasDss(doc), results);
        } catch (SignerException e) {
            throw e;
        } catch (Exception e) {
            throw new SignerException(ErrorCode.PDF_INVALID, "Unable to read PDF: " + e.getMessage(), e);
        }
    }

    private VerificationReport.SignatureResult verifyOne(byte[] pdf, PDSignature sig, String fieldName, int mdp) {
        List<String> notes = new ArrayList<>();
        String subFilter = sig.getSubFilter();
        int[] br = sig.getByteRange();
        boolean wholeDoc = br != null && br.length == 4 && br[0] == 0 && (long) br[2] + br[3] == pdf.length;
        if (!wholeDoc) {
            notes.add("The document was updated after this signature (e.g. later signatures or form changes)");
        }
        boolean isCertification = isCertificationSignature(sig);
        try {
            byte[] contents = derTrim(sig.getContents(pdf));
            byte[] signedContent = sig.getSignedContent(pdf);
            if (!PdfSignOptions.SUBFILTER_PKCS7.equals(subFilter) && !PdfSignOptions.SUBFILTER_PADES.equals(subFilter)) {
                notes.add("Unsupported signature sub-filter " + subFilter);
                return result(fieldName, VerificationReport.Status.INVALID, sig.getName(), null, List.of(), sigTime(sig, null),
                        false, null, null, sig, subFilter, false, wholeDoc, false, false, "UNKNOWN", isCertification ? mdp : 0, notes);
            }
            CMSSignedData cms = new CMSSignedData(new CMSProcessableByteArray(signedContent), contents);
            SignerInformation signer = cms.getSignerInfos().getSigners().iterator().next();
            JcaX509CertificateConverter conv = new JcaX509CertificateConverter();
            List<X509Certificate> cmsCerts = new ArrayList<>();
            for (X509CertificateHolder h : cms.getCertificates().getMatches(null)) {
                cmsCerts.add(conv.getCertificate(h));
            }
            @SuppressWarnings("unchecked")
            Collection<X509CertificateHolder> matches = cms.getCertificates().getMatches(signer.getSID());
            if (matches.isEmpty()) {
                notes.add("Signer certificate is not embedded in the signature");
                return result(fieldName, VerificationReport.Status.INVALID, sig.getName(), null, List.of(), sigTime(sig, null),
                        false, null, null, sig, subFilter, false, wholeDoc, false, false, "UNKNOWN", isCertification ? mdp : 0, notes);
            }
            X509Certificate cert = conv.getCertificate(matches.iterator().next());

            boolean integrity;
            try {
                integrity = signer.verify(new JcaSimpleSignerInfoVerifierBuilder().build(cert.getPublicKey()));
            } catch (Exception e) {
                integrity = false;
                notes.add("Integrity check failed: " + e.getMessage());
            }

            // Timestamp
            TimeStampToken tst = timestampToken(signer);
            Instant tsTime = null;
            String tsa = null;
            if (tst != null) {
                try {
                    byte[] imprint = tst.getTimeStampInfo().getMessageImprintDigest();
                    if (!Arrays.equals(imprint, Bytes.sha256(signer.getSignature()))) {
                        notes.add("Timestamp does not match the signature value");
                    } else {
                        @SuppressWarnings("unchecked")
                        Collection<X509CertificateHolder> tsCerts = tst.getCertificates().getMatches(tst.getSID());
                        if (!tsCerts.isEmpty()) {
                            X509CertificateHolder tsCert = tsCerts.iterator().next();
                            tst.validate(new JcaSimpleSignerInfoVerifierBuilder().build(tsCert));
                            tsa = Certificates.commonName(conv.getCertificate(tsCert));
                        }
                        tsTime = tst.getTimeStampInfo().getGenTime().toInstant();
                    }
                } catch (Exception e) {
                    notes.add("Timestamp could not be validated: " + e.getMessage());
                    tsTime = null;
                }
            }
            Instant signingTime = sigTime(sig, signer);
            Instant effective = tsTime != null ? tsTime : signingTime;
            if (tsTime == null) {
                notes.add("Signing time is taken from the signer's computer clock (no trusted timestamp)");
            }

            boolean certValid = effective != null && Certificates.isValidAt(cert, Date.from(effective));
            if (!certValid) {
                notes.add("Signer certificate was not valid at the time of signing");
            }
            if (!Certificates.isSigningCertificate(cert)) {
                notes.add("Certificate key usage does not permit document signing");
            }

            List<X509Certificate> chain = new ChainBuilder(anchors, fetchIssuers).withCertificates(cmsCerts).build(cert);
            X509Certificate top = chain.get(chain.size() - 1);
            boolean trusted = !anchors.isEmpty() && anchors.isTrustedRoot(top);
            if (anchors.isEmpty()) {
                notes.add("No trust anchors configured; certificate chain was not checked against a trusted root");
            } else if (!trusted) {
                notes.add("Certificate chain does not end at a configured trusted root (e.g. CCA India)");
            }

            String revStatus = "NOT_CHECKED";
            if (revocation != null) {
                X509Certificate issuer = chain.size() > 1 ? chain.get(1) : null;
                RevocationClient.Result r = revocation.check(cert, issuer);
                revStatus = r.status().name();
                if (r.status() == RevocationClient.Status.REVOKED) {
                    notes.add("Certificate revoked: " + r.detail());
                }
            }

            VerificationReport.Status status;
            if (!integrity || "REVOKED".equals(revStatus)) {
                status = VerificationReport.Status.INVALID;
            } else if (certValid && trusted && !"UNKNOWN".equals(revStatus)) {
                status = VerificationReport.Status.VALID;
            } else {
                status = VerificationReport.Status.VALID_UNTRUSTED;
            }
            List<String> chainNames = chain.stream().map(Certificates::commonName).toList();
            return result(fieldName, status, Certificates.commonName(cert), Certificates.describe(cert, "document"), chainNames,
                    signingTime, tst != null, tsTime, tsa, sig, subFilter, integrity, wholeDoc, certValid, trusted, revStatus,
                    isCertification ? mdp : 0, notes);
        } catch (Exception e) {
            notes.add("Signature could not be parsed: " + e.getMessage());
            return result(fieldName, VerificationReport.Status.INVALID, sig.getName(), null, List.of(), sigTime(sig, null),
                    false, null, null, sig, subFilter, false, wholeDoc, false, false, "UNKNOWN", isCertification ? mdp : 0, notes);
        }
    }

    private static VerificationReport.SignatureResult result(String field, VerificationReport.Status status, String name,
                                                            CertificateInfo info, List<String> chain, Instant signingTime,
                                                            boolean timestamped, Instant tsTime, String tsa, PDSignature sig,
                                                            String subFilter, boolean integrity, boolean whole, boolean certValid,
                                                            boolean trusted, String revocation, int mdp, List<String> notes) {
        return new VerificationReport.SignatureResult(field, status, name, info, chain, signingTime, timestamped, tsTime, tsa,
                sig.getReason(), sig.getLocation(), subFilter, integrity, whole, certValid, trusted, revocation, mdp, notes);
    }

    private static Instant sigTime(PDSignature sig, SignerInformation signer) {
        if (signer != null && signer.getSignedAttributes() != null) {
            Attribute st = signer.getSignedAttributes().get(CMSAttributes.signingTime);
            if (st != null) {
                return Time.getInstance(st.getAttrValues().getObjectAt(0)).getDate().toInstant();
            }
        }
        return sig.getSignDate() == null ? null : sig.getSignDate().toInstant();
    }

    private static TimeStampToken timestampToken(SignerInformation signer) {
        AttributeTable unsigned = signer.getUnsignedAttributes();
        if (unsigned == null) {
            return null;
        }
        Attribute a = unsigned.get(PKCSObjectIdentifiers.id_aa_signatureTimeStampToken);
        if (a == null) {
            return null;
        }
        try {
            return new TimeStampToken(new CMSSignedData(a.getAttrValues().getObjectAt(0).toASN1Primitive().getEncoded()));
        } catch (Exception e) {
            return null;
        }
    }

    /** Removes the zero padding that follows the DER encoded CMS inside /Contents. */
    static byte[] derTrim(byte[] contents) throws java.io.IOException {
        try (org.bouncycastle.asn1.ASN1InputStream in = new org.bouncycastle.asn1.ASN1InputStream(contents)) {
            return in.readObject().getEncoded();
        }
    }

    private static boolean isCertificationSignature(PDSignature sig) {
        COSArray refs = sig.getCOSObject().getCOSArray(COSName.getPDFName("Reference"));
        if (refs == null) {
            return false;
        }
        for (COSBase b : refs) {
            if (b.getCOSObject() instanceof COSDictionary d
                    && COSName.DOCMDP.equals(d.getCOSName(COSName.getPDFName("TransformMethod")))) {
                return true;
            }
        }
        return false;
    }

    private static Map<COSDictionary, String> fieldNames(PDDocument doc) {
        Map<COSDictionary, String> names = new HashMap<>();
        PDAcroForm form = doc.getDocumentCatalog().getAcroForm(null);
        if (form == null) {
            return names;
        }
        for (PDField f : form.getFieldTree()) {
            if (f instanceof PDSignatureField sf && sf.getSignature() != null) {
                names.put(sf.getSignature().getCOSObject(), sf.getFullyQualifiedName());
            }
        }
        return names;
    }
}
