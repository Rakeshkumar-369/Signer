package in.signer.core.cert;

import java.util.List;
import java.util.Locale;

/**
 * Criteria used to pick a signing certificate. All non-null criteria must match.
 * Text criteria are case-insensitive "contains" matches; serial numbers and thumbprints are exact (hex).
 */
public record CertificateFilter(
        String id,
        String commonName,
        String serialNumber,
        String issuer,
        String organization,
        String organizationalUnit,
        String title,
        String email,
        Boolean validOnly,
        Boolean signingOnly,
        String certificateClass) {

    public static final CertificateFilter ANY = new CertificateFilter(null, null, null, null, null, null, null, null, null, null, null);

    public boolean matches(CertificateInfo c) {
        if (notBlank(id) && !id.replace(" ", "").equalsIgnoreCase(c.id())) {
            return false;
        }
        if (notBlank(serialNumber) && !stripZeros(serialNumber).equalsIgnoreCase(stripZeros(c.serialNumber()))) {
            return false;
        }
        if (!contains(c.commonName(), commonName) || !contains(c.issuer(), issuer)
                || !contains(c.organization(), organization) || !contains(c.organizationalUnit(), organizationalUnit)
                || !contains(c.title(), title) || !contains(c.email(), email)
                || !contains(c.certificateClass(), certificateClass)) {
            return false;
        }
        if (!Boolean.FALSE.equals(validOnly) && !c.currentlyValid()) {
            return false;
        }
        if (!Boolean.FALSE.equals(signingOnly)) {
            List<String> ku = c.keyUsage();
            return ku.isEmpty() || ku.contains("digitalSignature") || ku.contains("nonRepudiation");
        }
        return true;
    }

    private static boolean contains(String value, String wanted) {
        if (!notBlank(wanted)) {
            return true;
        }
        return value != null && value.toLowerCase(Locale.ROOT).contains(wanted.strip().toLowerCase(Locale.ROOT));
    }

    private static boolean notBlank(String s) {
        return s != null && !s.isBlank();
    }

    private static String stripZeros(String hex) {
        String h = hex.replace(" ", "").replace(":", "");
        int i = 0;
        while (i < h.length() - 1 && h.charAt(i) == '0') {
            i++;
        }
        return h.substring(i);
    }
}
