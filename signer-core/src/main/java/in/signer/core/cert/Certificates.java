package in.signer.core.cert;

import in.signer.core.ErrorCode;
import in.signer.core.SignerException;
import in.signer.core.util.Bytes;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1String;
import org.bouncycastle.asn1.x500.AttributeTypeAndValue;
import org.bouncycastle.asn1.x500.RDN;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.asn1.x509.AccessDescription;
import org.bouncycastle.asn1.x509.AuthorityInformationAccess;
import org.bouncycastle.asn1.x509.CRLDistPoint;
import org.bouncycastle.asn1.x509.CertificatePolicies;
import org.bouncycastle.asn1.x509.DistributionPoint;
import org.bouncycastle.asn1.x509.DistributionPointName;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.asn1.x509.PolicyInformation;
import org.bouncycastle.asn1.x509.X509ObjectIdentifiers;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPublicKey;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Date;
import java.util.List;
import java.util.Locale;

/** X.509 helpers: parsing, naming, Indian CCA class detection, AIA/CRL extraction. */
public final class Certificates {

    /** Indian CCA certificate policy OIDs (2.16.356.100.2.x) mapped to their class names. */
    private static final String CCA_POLICY_PREFIX = "2.16.356.100.2.";

    private static final String[] KEY_USAGE_NAMES = {
            "digitalSignature", "nonRepudiation", "keyEncipherment", "dataEncipherment",
            "keyAgreement", "keyCertSign", "cRLSign", "encipherOnly", "decipherOnly"};

    private Certificates() {
    }

    public static X509Certificate parse(byte[] der) {
        try {
            CertificateFactory cf = CertificateFactory.getInstance("X.509");
            return (X509Certificate) cf.generateCertificate(new ByteArrayInputStream(der));
        } catch (CertificateException e) {
            throw SignerException.badRequest("Invalid X.509 certificate: " + e.getMessage());
        }
    }

    public static List<X509Certificate> parseAll(byte[] data) {
        try {
            CertificateFactory cf = CertificateFactory.getInstance("X.509");
            Collection<? extends java.security.cert.Certificate> all = cf.generateCertificates(new ByteArrayInputStream(data));
            List<X509Certificate> out = new ArrayList<>();
            for (java.security.cert.Certificate c : all) {
                out.add((X509Certificate) c);
            }
            return out;
        } catch (CertificateException e) {
            throw SignerException.badRequest("Invalid certificate data: " + e.getMessage());
        }
    }

    public static byte[] encoded(X509Certificate cert) {
        try {
            return cert.getEncoded();
        } catch (java.security.cert.CertificateEncodingException e) {
            throw new SignerException(ErrorCode.INTERNAL_ERROR, "Certificate encoding failed", e);
        }
    }

    public static String thumbprint(X509Certificate cert) {
        return Bytes.hex(Bytes.sha1(encoded(cert))).toUpperCase(Locale.ROOT);
    }

    public static X500Name subject(X509Certificate cert) {
        return X500Name.getInstance(cert.getSubjectX500Principal().getEncoded());
    }

    public static X500Name issuer(X509Certificate cert) {
        return X500Name.getInstance(cert.getIssuerX500Principal().getEncoded());
    }

    public static String attribute(X500Name name, ASN1ObjectIdentifier oid) {
        for (RDN rdn : name.getRDNs(oid)) {
            for (AttributeTypeAndValue tv : rdn.getTypesAndValues()) {
                if (tv.getType().equals(oid)) {
                    ASN1Encodable v = tv.getValue();
                    return v instanceof ASN1String s ? s.getString() : v.toString();
                }
            }
        }
        return null;
    }

    public static String commonName(X509Certificate cert) {
        String cn = attribute(subject(cert), BCStyle.CN);
        return cn != null ? cn : cert.getSubjectX500Principal().getName();
    }

    public static boolean isSelfSigned(X509Certificate cert) {
        if (!cert.getSubjectX500Principal().equals(cert.getIssuerX500Principal())) {
            return false;
        }
        try {
            cert.verify(cert.getPublicKey());
            return true;
        } catch (Exception e) {
            return false;
        }
    }

    public static boolean isValidAt(X509Certificate cert, Date when) {
        return !when.before(cert.getNotBefore()) && !when.after(cert.getNotAfter());
    }

    public static List<String> keyUsage(X509Certificate cert) {
        boolean[] ku = cert.getKeyUsage();
        List<String> out = new ArrayList<>();
        if (ku != null) {
            for (int i = 0; i < ku.length && i < KEY_USAGE_NAMES.length; i++) {
                if (ku[i]) {
                    out.add(KEY_USAGE_NAMES[i]);
                }
            }
        }
        return out;
    }

    /** True when the certificate may be used for document signatures (no key usage, digitalSignature or nonRepudiation). */
    public static boolean isSigningCertificate(X509Certificate cert) {
        boolean[] ku = cert.getKeyUsage();
        if (ku == null) {
            return true;
        }
        return (ku.length > 0 && ku[0]) || (ku.length > 1 && ku[1]);
    }

    public static List<String> policies(X509Certificate cert) {
        List<String> out = new ArrayList<>();
        byte[] ext = cert.getExtensionValue(Extension.certificatePolicies.getId());
        if (ext == null) {
            return out;
        }
        try {
            CertificatePolicies cp = CertificatePolicies.getInstance(unwrap(ext));
            for (PolicyInformation pi : cp.getPolicyInformation()) {
                out.add(pi.getPolicyIdentifier().getId());
            }
        } catch (RuntimeException | IOException ignored) {
            // malformed extension: treat as no policies
        }
        return out;
    }

    /** Returns e.g. "Class 3" for certificates carrying an Indian CCA class policy OID, else null. */
    public static String ccaClass(List<String> policies) {
        String best = null;
        for (String p : policies) {
            if (p.startsWith(CCA_POLICY_PREFIX)) {
                String rest = p.substring(CCA_POLICY_PREFIX.length());
                int dot = rest.indexOf('.');
                String cls = dot < 0 ? rest : rest.substring(0, dot);
                if (cls.matches("[1-3]") && (best == null || cls.compareTo(best) > 0)) {
                    best = cls;
                }
            }
        }
        return best == null ? null : "Class " + best;
    }

    public static List<String> ocspUrls(X509Certificate cert) {
        return accessLocations(cert, X509ObjectIdentifiers.id_ad_ocsp);
    }

    public static List<String> caIssuerUrls(X509Certificate cert) {
        return accessLocations(cert, X509ObjectIdentifiers.id_ad_caIssuers);
    }

    private static List<String> accessLocations(X509Certificate cert, ASN1ObjectIdentifier method) {
        List<String> out = new ArrayList<>();
        byte[] ext = cert.getExtensionValue(Extension.authorityInfoAccess.getId());
        if (ext == null) {
            return out;
        }
        try {
            AuthorityInformationAccess aia = AuthorityInformationAccess.getInstance(unwrap(ext));
            for (AccessDescription ad : aia.getAccessDescriptions()) {
                if (ad.getAccessMethod().equals(method)
                        && ad.getAccessLocation().getTagNo() == GeneralName.uniformResourceIdentifier) {
                    out.add(ad.getAccessLocation().getName().toString());
                }
            }
        } catch (RuntimeException | IOException ignored) {
            // malformed extension
        }
        return out;
    }

    public static List<String> crlUrls(X509Certificate cert) {
        List<String> out = new ArrayList<>();
        byte[] ext = cert.getExtensionValue(Extension.cRLDistributionPoints.getId());
        if (ext == null) {
            return out;
        }
        try {
            CRLDistPoint dp = CRLDistPoint.getInstance(unwrap(ext));
            for (DistributionPoint p : dp.getDistributionPoints()) {
                DistributionPointName name = p.getDistributionPoint();
                if (name != null && name.getType() == DistributionPointName.FULL_NAME) {
                    for (GeneralName gn : GeneralNames.getInstance(name.getName()).getNames()) {
                        if (gn.getTagNo() == GeneralName.uniformResourceIdentifier) {
                            out.add(gn.getName().toString());
                        }
                    }
                }
            }
        } catch (RuntimeException | IOException ignored) {
            // malformed extension
        }
        return out;
    }

    private static ASN1Primitive unwrap(byte[] extensionValue) throws IOException {
        return ASN1Primitive.fromByteArray(ASN1OctetString.getInstance(extensionValue).getOctets());
    }

    public static CertificateInfo describe(X509Certificate cert, String source) {
        X500Name s = subject(cert);
        X500Name i = issuer(cert);
        List<String> policies = policies(cert);
        int keySize = 0;
        if (cert.getPublicKey() instanceof RSAPublicKey rsa) {
            keySize = rsa.getModulus().bitLength();
        } else if (cert.getPublicKey() instanceof ECPublicKey ec) {
            keySize = ec.getParams().getOrder().bitLength();
        }
        return new CertificateInfo(
                thumbprint(cert),
                commonName(cert),
                cert.getSubjectX500Principal().getName(),
                attribute(s, BCStyle.O),
                attribute(s, BCStyle.OU),
                attribute(s, BCStyle.T),
                attribute(s, BCStyle.EmailAddress),
                cert.getSerialNumber().toString(16).toUpperCase(Locale.ROOT),
                cert.getIssuerX500Principal().getName(),
                attribute(i, BCStyle.CN),
                cert.getNotBefore().toInstant(),
                cert.getNotAfter().toInstant(),
                isValidAt(cert, new Date()),
                keyUsage(cert),
                cert.getPublicKey().getAlgorithm(),
                keySize,
                ccaClass(policies),
                policies,
                source,
                Bytes.b64(encoded(cert)));
    }
}
