package in.signer.core.pdf;

import in.signer.core.ErrorCode;
import in.signer.core.SignerException;
import in.signer.core.cert.Certificates;
import in.signer.core.util.Bytes;
import org.apache.pdfbox.Loader;
import org.apache.pdfbox.cos.COSArray;
import org.apache.pdfbox.cos.COSBase;
import org.apache.pdfbox.cos.COSDictionary;
import org.apache.pdfbox.cos.COSName;
import org.apache.pdfbox.pdmodel.PDDocument;
import org.apache.pdfbox.pdmodel.PDPage;
import org.apache.pdfbox.pdmodel.common.PDRectangle;
import org.apache.pdfbox.pdmodel.encryption.InvalidPasswordException;
import org.apache.pdfbox.pdmodel.interactive.digitalsignature.ExternalSigningSupport;
import org.apache.pdfbox.pdmodel.interactive.digitalsignature.PDSignature;
import org.apache.pdfbox.pdmodel.interactive.digitalsignature.SignatureOptions;
import org.apache.pdfbox.pdmodel.interactive.form.PDAcroForm;
import org.apache.pdfbox.pdmodel.interactive.form.PDField;
import org.apache.pdfbox.pdmodel.interactive.form.PDSignatureField;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.time.ZoneId;
import java.time.ZonedDateTime;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Calendar;
import java.util.GregorianCalendar;
import java.util.List;
import java.util.Locale;
import java.util.TimeZone;

/**
 * Two-phase PDF signing:
 * <ol>
 *   <li>{@link #prepare} adds a signature field (visible or invisible) with an empty /Contents placeholder
 *       using an incremental update, and returns the SHA-256 digest that has to be signed;</li>
 *   <li>{@link #inject} writes the detached CMS signature into the placeholder.</li>
 * </ol>
 * The same code path is used for desktop signing (whole PDF on the agent) and for server-side preparation
 * where only the 32-byte digest travels to the USB token.
 */
public final class PdfPreparer {

    /** Bytes reserved for the CMS structure: enough for a 4096-bit chain of 5 certificates plus a timestamp. */
    public static final int RESERVED_SIGNATURE_BYTES = 32 * 1024;

    private static final byte[] BYTE_RANGE = "/ByteRange".getBytes(StandardCharsets.US_ASCII);

    private PdfPreparer() {
    }

    public static PreparedPdf prepare(byte[] pdf, PdfSignOptions options, X509Certificate signerCert, Instant signingTime) {
        PdfSignOptions o = options == null ? new PdfSignOptions() : options;
        Instant when = signingTime == null ? Instant.now() : signingTime;
        try (PDDocument doc = load(pdf, o.pdfPassword)) {
            int mdp = docMdpPermission(doc);
            if (mdp == 1) {
                throw new SignerException(ErrorCode.PDF_SIGNING_NOT_ALLOWED,
                        "The document is certified with 'no changes allowed'; it cannot be signed again");
            }
            boolean hasSignatures = !doc.getSignatureDictionaries().isEmpty();

            String signerName = o.signerName != null && !o.signerName.isBlank() ? o.signerName.strip()
                    : signerCert != null ? Certificates.commonName(signerCert) : "Signer";

            PDSignature signature = new PDSignature();
            signature.setFilter(PDSignature.FILTER_ADOBE_PPKLITE);
            signature.setSubFilter(o.isPades()
                    ? COSName.getPDFName(PdfSignOptions.SUBFILTER_PADES)
                    : PDSignature.SUBFILTER_ADBE_PKCS7_DETACHED);
            signature.setName(signerName);
            if (notBlank(o.reason)) {
                signature.setReason(o.reason.strip());
            }
            if (notBlank(o.location)) {
                signature.setLocation(o.location.strip());
            }
            if (notBlank(o.contactInfo)) {
                signature.setContactInfo(o.contactInfo.strip());
            }
            Calendar cal = new GregorianCalendar(TimeZone.getTimeZone(zone(o.timeZone)));
            cal.setTimeInMillis(when.toEpochMilli());
            signature.setSignDate(cal);

            if (o.certificationLevel != null) {
                if (o.certificationLevel < 1 || o.certificationLevel > 3) {
                    throw SignerException.badRequest("certificationLevel must be 1, 2 or 3");
                }
                if (hasSignatures) {
                    throw SignerException.badRequest("A certification signature must be the first signature in the document");
                }
                setDocMdp(doc, signature, o.certificationLevel);
            }

            try (SignatureOptions so = new SignatureOptions()) {
                so.setPreferredSignatureSize(RESERVED_SIGNATURE_BYTES);
                if (o.visible) {
                    int pageIndex = pageIndex(doc, o.page);
                    PDPage page = doc.getPage(pageIndex);
                    PDRectangle rect = SignatureAppearance.placement(page, o);
                    List<String> lines = lines(o, signerName, when);
                    so.setVisualSignature(new ByteArrayInputStream(SignatureAppearance.template(page, rect, o, lines)));
                    so.setPage(pageIndex);
                }
                String fieldName = o.fieldName == null ? null : o.fieldName.strip();
                if (fieldName != null && !fieldName.isEmpty()) {
                    PDAcroForm existing = doc.getDocumentCatalog().getAcroForm(null);
                    if (existing != null && existing.getField(fieldName) != null) {
                        throw SignerException.badRequest("A field named '" + fieldName + "' already exists in the document");
                    }
                }
                doc.addSignature(signature, so);
                if (fieldName != null && !fieldName.isEmpty()) {
                    renameField(doc, signature, fieldName);
                }

                ByteArrayOutputStream out = new ByteArrayOutputStream(pdf.length + 80_000);
                ExternalSigningSupport external = doc.saveIncrementalForExternalSigning(out);
                byte[] digest = Bytes.digest("SHA-256", external.getContent());
                external.setSignature(new byte[0]);
                byte[] prepared = out.toByteArray();
                return new PreparedPdf(prepared, findByteRange(prepared), digest);
            }
        } catch (SignerException e) {
            throw e;
        } catch (IOException | RuntimeException e) {
            throw new SignerException(ErrorCode.PDF_INVALID, "Unable to prepare PDF for signing: " + e.getMessage(), e);
        }
    }

    /** Writes a DER encoded CMS signature into the placeholder of a prepared PDF. */
    public static byte[] inject(byte[] preparedPdf, byte[] cms) {
        long[] br = findByteRange(preparedPdf);
        int start = (int) br[1] + 1;
        int capacityHex = (int) (br[2] - br[1] - 2);
        String hex = Bytes.hex(cms).toUpperCase(Locale.ROOT);
        if (hex.length() > capacityHex) {
            throw new SignerException(ErrorCode.SIGNATURE_TOO_LARGE,
                    "Signature (" + cms.length + " bytes) exceeds the reserved space (" + capacityHex / 2 + " bytes)");
        }
        for (int i = start; i < start + capacityHex; i++) {
            if (preparedPdf[i] != '0') {
                throw new SignerException(ErrorCode.CONFLICT, "The PDF has already been signed");
            }
        }
        byte[] out = preparedPdf.clone();
        byte[] hexBytes = hex.getBytes(StandardCharsets.US_ASCII);
        System.arraycopy(hexBytes, 0, out, start, hexBytes.length);
        return out;
    }

    /** SHA-256 over the /ByteRange of the last signature (the value the CMS signs). */
    public static byte[] digest(byte[] pdf) {
        long[] br = findByteRange(pdf);
        var md = Bytes.digest("SHA-256");
        md.update(pdf, (int) br[0], (int) br[1]);
        md.update(pdf, (int) br[2], (int) br[3]);
        return md.digest();
    }

    /** Locates and validates the /ByteRange of the last signature dictionary in the file. */
    public static long[] findByteRange(byte[] pdf) {
        int idx = lastIndexOf(pdf, BYTE_RANGE);
        if (idx < 0) {
            throw new SignerException(ErrorCode.PDF_INVALID, "No signature placeholder found in PDF");
        }
        int open = indexOf(pdf, (byte) '[', idx);
        int close = indexOf(pdf, (byte) ']', open);
        if (open < 0 || close < 0 || close - open > 200) {
            throw new SignerException(ErrorCode.PDF_INVALID, "Malformed /ByteRange");
        }
        String[] parts = new String(pdf, open + 1, close - open - 1, StandardCharsets.US_ASCII).trim().split("\\s+");
        if (parts.length != 4) {
            throw new SignerException(ErrorCode.PDF_INVALID, "Malformed /ByteRange");
        }
        long[] br = Arrays.stream(parts).mapToLong(Long::parseLong).toArray();
        if (br[0] != 0 || br[1] <= 0 || br[2] <= br[1] || br[2] + br[3] != pdf.length
                || pdf[(int) br[1]] != '<' || pdf[(int) br[2] - 1] != '>') {
            throw new SignerException(ErrorCode.PDF_INVALID, "Inconsistent /ByteRange " + Arrays.toString(br));
        }
        return br;
    }

    static PDDocument load(byte[] pdf, String password) throws IOException {
        if (pdf == null || pdf.length < 8) {
            throw new SignerException(ErrorCode.PDF_INVALID, "Empty or truncated PDF");
        }
        try {
            return password == null ? Loader.loadPDF(pdf) : Loader.loadPDF(pdf, password);
        } catch (InvalidPasswordException e) {
            throw new SignerException(ErrorCode.PDF_PASSWORD_REQUIRED, "The PDF is password protected; supply pdfPassword");
        }
    }

    static int pageIndex(PDDocument doc, String page) {
        int count = doc.getNumberOfPages();
        if (count == 0) {
            throw new SignerException(ErrorCode.PDF_INVALID, "PDF has no pages");
        }
        String p = page == null ? "last" : page.strip().toLowerCase(Locale.ROOT);
        int idx;
        switch (p) {
            case "", "last" -> idx = count - 1;
            case "first" -> idx = 0;
            default -> {
                int n;
                try {
                    n = Integer.parseInt(p);
                } catch (NumberFormatException e) {
                    throw SignerException.badRequest("Invalid page '" + page + "'");
                }
                idx = n < 0 ? count + n : n - 1;
            }
        }
        if (idx < 0 || idx >= count) {
            throw SignerException.badRequest("Page " + page + " does not exist (document has " + count + " pages)");
        }
        return idx;
    }

    static List<String> lines(PdfSignOptions o, String signerName, Instant when) {
        List<String> lines = new ArrayList<>();
        lines.add("Digitally signed by " + signerName);
        lines.add("Date: " + formatDate(when, o.dateFormat, o.timeZone));
        if (o.showReason && notBlank(o.reason)) {
            lines.add("Reason: " + o.reason.strip());
        }
        if (o.showLocation && notBlank(o.location)) {
            lines.add("Location: " + o.location.strip());
        }
        if (notBlank(o.customText)) {
            lines.addAll(Arrays.asList(o.customText.split("\\r?\\n")));
        }
        return lines;
    }

    static String formatDate(Instant when, String pattern, String timeZone) {
        String p = notBlank(pattern) ? pattern.replace("tt", "a") : "dd-MMM-yyyy hh:mm a";
        try {
            return DateTimeFormatter.ofPattern(p, Locale.ENGLISH).format(ZonedDateTime.ofInstant(when, zone(timeZone)));
        } catch (IllegalArgumentException e) {
            throw SignerException.badRequest("Invalid dateFormat '" + pattern + "'");
        }
    }

    static ZoneId zone(String tz) {
        try {
            return notBlank(tz) ? ZoneId.of(tz.strip()) : ZoneId.of("Asia/Kolkata");
        } catch (RuntimeException e) {
            throw SignerException.badRequest("Invalid timeZone '" + tz + "'");
        }
    }

    /** Returns the DocMDP permission (1-3) of an existing certification signature, or 0 when there is none. */
    static int docMdpPermission(PDDocument doc) {
        COSDictionary perms = doc.getDocumentCatalog().getCOSObject().getCOSDictionary(COSName.PERMS);
        if (perms == null) {
            return 0;
        }
        COSDictionary sig = perms.getCOSDictionary(COSName.DOCMDP);
        if (sig == null) {
            return 0;
        }
        COSArray refs = sig.getCOSArray(COSName.getPDFName("Reference"));
        if (refs == null) {
            return 0;
        }
        for (COSBase base : refs) {
            if (base.getCOSObject() instanceof COSDictionary ref
                    && COSName.DOCMDP.equals(ref.getCOSName(COSName.getPDFName("TransformMethod")))) {
                COSDictionary params = ref.getCOSDictionary(COSName.getPDFName("TransformParams"));
                return params == null ? 2 : params.getInt(COSName.P, 2);
            }
        }
        return 0;
    }

    private static void setDocMdp(PDDocument doc, PDSignature signature, int level) {
        COSDictionary params = new COSDictionary();
        params.setItem(COSName.TYPE, COSName.getPDFName("TransformParams"));
        params.setInt(COSName.P, level);
        params.setName(COSName.V, "1.2");
        params.setDirect(true);

        COSDictionary ref = new COSDictionary();
        ref.setItem(COSName.TYPE, COSName.getPDFName("SigRef"));
        ref.setItem(COSName.getPDFName("TransformMethod"), COSName.DOCMDP);
        ref.setItem(COSName.getPDFName("TransformParams"), params);
        ref.setDirect(true);

        COSArray refs = new COSArray();
        refs.add(ref);
        refs.setDirect(true);
        signature.getCOSObject().setItem(COSName.getPDFName("Reference"), refs);

        COSDictionary catalog = doc.getDocumentCatalog().getCOSObject();
        COSDictionary perms = new COSDictionary();
        perms.setItem(COSName.DOCMDP, signature);
        perms.setDirect(true);
        catalog.setItem(COSName.PERMS, perms);
        catalog.setNeedToBeUpdated(true);
    }

    private static void renameField(PDDocument doc, PDSignature signature, String name) {
        PDAcroForm form = doc.getDocumentCatalog().getAcroForm(null);
        if (form == null) {
            return;
        }
        for (PDField f : form.getFieldTree()) {
            if (f instanceof PDSignatureField sf
                    && sf.getCOSObject().getDictionaryObject(COSName.V) == signature.getCOSObject()) {
                sf.setPartialName(name);
                return;
            }
        }
    }

    private static boolean notBlank(String s) {
        return s != null && !s.isBlank();
    }

    private static int lastIndexOf(byte[] data, byte[] pattern) {
        outer:
        for (int i = data.length - pattern.length; i >= 0; i--) {
            for (int j = 0; j < pattern.length; j++) {
                if (data[i + j] != pattern[j]) {
                    continue outer;
                }
            }
            return i;
        }
        return -1;
    }

    private static int indexOf(byte[] data, byte b, int from) {
        if (from < 0) {
            return -1;
        }
        for (int i = from; i < data.length; i++) {
            if (data[i] == b) {
                return i;
            }
        }
        return -1;
    }
}
