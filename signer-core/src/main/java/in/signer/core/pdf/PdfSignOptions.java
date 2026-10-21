package in.signer.core.pdf;

/**
 * Options for a PDF signature. Coordinates and sizes are in PDF points (1/72 inch), measured on the page
 * as displayed (page rotation is handled automatically).
 */
public class PdfSignOptions {

    public static final String SUBFILTER_PKCS7 = "adbe.pkcs7.detached";
    public static final String SUBFILTER_PADES = "ETSI.CAdES.detached";

    /** Draw a visible signature box. When false an invisible signature is created. */
    public boolean visible = true;
    /** 1-based page number, or "first" / "last" / negative numbers counted from the end (-1 = last). */
    public String page = "last";
    public float x = 360;
    public float y = 40;
    public float width = 200;
    public float height = 70;
    /** "bottom-left" (PDF default) or "top-left" (browser/screen style). */
    public String origin = "bottom-left";

    public String reason;
    public String location;
    public String contactInfo;
    /** Overrides the name shown in the box (defaults to the certificate common name). */
    public String signerName;
    /** Java or .NET style date pattern; "tt" is accepted as the AM/PM marker. */
    public String dateFormat = "dd-MMM-yyyy hh:mm a";
    public String timeZone = "Asia/Kolkata";
    public boolean greenTick = true;
    public boolean border = false;
    /** Additional free text, "\n" separates lines. */
    public String customText;
    /** Show the "Reason" and "Location" lines in the box. */
    public boolean showReason = true;
    public boolean showLocation = true;
    /** Font size in points; null auto-fits the text into the box. */
    public Float fontSize;
    /** Optional PNG/JPEG (Base64) drawn on the left side: scanned signature, seal or logo. */
    public String imageBase64;
    /** Optional TrueType font file on the signing machine, embedded for non-Latin names. */
    public String fontPath;

    /** Name of the signature field to create (auto-generated when empty). */
    public String fieldName;
    /** {@link #SUBFILTER_PKCS7} (widest compatibility) or {@link #SUBFILTER_PADES} (PAdES baseline). */
    public String subFilter = SUBFILTER_PKCS7;
    /** Null for an approval signature; 1, 2 or 3 for a DocMDP certification signature (first signature only). */
    public Integer certificationLevel;
    /** Add an RFC 3161 timestamp from the configured TSA. */
    public boolean timestamp = false;
    /** Embed certificate chain and OCSP/CRL data (DSS) for long-term validation. */
    public boolean ltv = false;
    /** Password of an encrypted input PDF. */
    public String pdfPassword;

    public boolean isPades() {
        return SUBFILTER_PADES.equalsIgnoreCase(subFilter) || "pades".equalsIgnoreCase(subFilter);
    }
}
