package in.signer.core.pdf;

import in.signer.core.ErrorCode;
import in.signer.core.SignerException;
import in.signer.core.cert.ChainBuilder;
import in.signer.core.cert.Certificates;
import in.signer.core.cert.RevocationClient;
import org.apache.pdfbox.cos.COSArray;
import org.apache.pdfbox.cos.COSDictionary;
import org.apache.pdfbox.cos.COSName;
import org.apache.pdfbox.cos.COSStream;
import org.apache.pdfbox.pdmodel.PDDocument;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

/**
 * Adds a Document Security Store (PAdES-LTV / ISO 32000-2 §12.8.4.3) holding the certificate chain and
 * OCSP responses / CRLs, so the signature can be validated after the certificate expires or the CA goes offline.
 */
public final class PdfLtv {

    private static final Logger log = LoggerFactory.getLogger(PdfLtv.class);
    private static final COSName DSS = COSName.getPDFName("DSS");
    private static final COSName CERTS = COSName.getPDFName("Certs");
    private static final COSName OCSPS = COSName.getPDFName("OCSPs");
    private static final COSName CRLS = COSName.getPDFName("CRLs");

    private PdfLtv() {
    }

    /** Fetches revocation data for every non-root certificate and embeds everything in the DSS. */
    public static byte[] addValidationData(byte[] pdf, List<X509Certificate> certs, RevocationClient revocation) {
        List<byte[]> ocsps = new ArrayList<>();
        List<byte[]> crls = new ArrayList<>();
        int missing = 0;
        for (X509Certificate cert : certs) {
            if (Certificates.isSelfSigned(cert)) {
                continue;
            }
            X509Certificate issuer = ChainBuilder.findIssuer(cert, certs);
            byte[] ocsp = issuer == null ? null : revocation.fetchOcsp(cert, issuer);
            if (ocsp != null) {
                ocsps.add(ocsp);
                continue;
            }
            byte[] crl = revocation.fetchCrl(cert);
            if (crl != null) {
                crls.add(crl);
            } else {
                missing++;
                log.warn("No revocation information available for {}", cert.getSubjectX500Principal());
            }
        }
        if (missing > 0 && ocsps.isEmpty() && crls.isEmpty()) {
            throw new SignerException(ErrorCode.REVOCATION_FETCH_FAILED,
                    "Could not download OCSP/CRL data for LTV; check network access to the CA");
        }
        List<byte[]> der = certs.stream().map(Certificates::encoded).toList();
        return addValidationData(pdf, der, ocsps, crls);
    }

    public static byte[] addValidationData(byte[] pdf, List<byte[]> certs, List<byte[]> ocsps, List<byte[]> crls) {
        try (PDDocument doc = PdfPreparer.load(pdf, null)) {
            COSDictionary catalog = doc.getDocumentCatalog().getCOSObject();
            COSDictionary dss = catalog.getCOSDictionary(DSS);
            if (dss == null) {
                dss = new COSDictionary();
                catalog.setItem(DSS, dss);
            }
            append(doc, dss, CERTS, certs);
            append(doc, dss, OCSPS, ocsps);
            append(doc, dss, CRLS, crls);
            dss.setNeedToBeUpdated(true);
            catalog.setNeedToBeUpdated(true);
            ByteArrayOutputStream out = new ByteArrayOutputStream(pdf.length + 64_000);
            doc.saveIncremental(out);
            return out.toByteArray();
        } catch (IOException e) {
            throw new SignerException(ErrorCode.PDF_INVALID, "Unable to add LTV data: " + e.getMessage(), e);
        }
    }

    private static void append(PDDocument doc, COSDictionary dss, COSName key, List<byte[]> items) throws IOException {
        if (items == null || items.isEmpty()) {
            return;
        }
        COSArray array = dss.getCOSArray(key);
        if (array == null) {
            array = new COSArray();
            dss.setItem(key, array);
        }
        List<byte[]> seen = new ArrayList<>();
        for (byte[] item : items) {
            if (seen.stream().anyMatch(s -> Arrays.equals(s, item))) {
                continue;
            }
            seen.add(item);
            COSStream stream = doc.getDocument().createCOSStream();
            try (OutputStream os = stream.createOutputStream(COSName.FLATE_DECODE)) {
                os.write(item);
            }
            array.add(stream);
        }
        array.setNeedToBeUpdated(true);
    }

    /** True when the document carries a DSS dictionary. */
    public static boolean hasDss(PDDocument doc) {
        return doc.getDocumentCatalog().getCOSObject().getCOSDictionary(DSS) != null;
    }
}
