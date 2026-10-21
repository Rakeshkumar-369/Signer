package in.signer.core.testing;

import com.sun.net.httpserver.HttpServer;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.AccessDescription;
import org.bouncycastle.asn1.x509.AuthorityInformationAccess;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.CRLDistPoint;
import org.bouncycastle.asn1.x509.CRLReason;
import org.bouncycastle.asn1.x509.DistributionPoint;
import org.bouncycastle.asn1.x509.DistributionPointName;
import org.bouncycastle.asn1.x509.ExtendedKeyUsage;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.asn1.x509.KeyPurposeId;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.asn1.x509.PolicyInformation;
import org.bouncycastle.asn1.x509.X509ObjectIdentifiers;
import org.bouncycastle.cert.X509CRLHolder;
import org.bouncycastle.cert.X509v2CRLBuilder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaCertStore;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.cms.jcajce.JcaSimpleSignerInfoGeneratorBuilder;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;
import org.bouncycastle.tsp.TSPAlgorithms;
import org.bouncycastle.tsp.TimeStampRequest;
import org.bouncycastle.tsp.TimeStampResponseGenerator;
import org.bouncycastle.tsp.TimeStampTokenGenerator;

import java.io.ByteArrayOutputStream;
import java.io.OutputStream;
import java.math.BigInteger;
import java.net.InetSocketAddress;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.util.Date;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicLong;

/**
 * Self-contained test PKI: root CA, intermediate CA, a Class 3 style signer, a timestamp authority,
 * and an HTTP server publishing the CRLs and serving RFC 3161 timestamps.
 */
public final class TestPki implements AutoCloseable {

    private static final AtomicLong SERIAL = new AtomicLong(System.currentTimeMillis());

    public final KeyPair rootKey;
    public final X509Certificate root;
    public final KeyPair caKey;
    public final X509Certificate ca;
    public final KeyPair signerKey;
    public final X509Certificate signer;
    public final KeyPair tsaKey;
    public final X509Certificate tsa;

    private final HttpServer http;
    private final Map<String, byte[]> files = new ConcurrentHashMap<>();
    private final int port;

    public TestPki() throws Exception {
        http = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        port = http.getAddress().getPort();
        String base = "http://127.0.0.1:" + port;

        rootKey = rsa(2048);
        root = cert("CN=Test Root CA 2026,O=Signer Test,C=IN", rootKey, null, null, true, null, null, null);
        caKey = rsa(2048);
        ca = cert("CN=Test Sub CA 2026,O=Signer Test,C=IN", caKey, root, rootKey.getPrivate(), true,
                base + "/root.crl", base + "/root.cer", null);
        signerKey = rsa(2048);
        signer = cert("CN=RAVI KUMAR,O=Government of Andhra Pradesh,OU=IT Department,T=Deputy Secretary,C=IN,EmailAddress=ravi@example.in",
                signerKey, ca, caKey.getPrivate(), false, base + "/ca.crl", base + "/ca.cer", "2.16.356.100.2.3");
        tsaKey = rsa(2048);
        tsa = tsaCert(base + "/root.crl");

        files.put("/root.cer", root.getEncoded());
        files.put("/ca.cer", ca.getEncoded());
        files.put("/root.crl", crl(root, rootKey.getPrivate(), null));
        files.put("/ca.crl", crl(ca, caKey.getPrivate(), null));

        http.createContext("/", ex -> {
            byte[] body = files.get(ex.getRequestURI().getPath());
            if (body == null) {
                ex.sendResponseHeaders(404, -1);
            } else {
                ex.sendResponseHeaders(200, body.length);
                try (OutputStream os = ex.getResponseBody()) {
                    os.write(body);
                }
            }
            ex.close();
        });
        http.createContext("/tsa", ex -> {
            try {
                byte[] req = ex.getRequestBody().readAllBytes();
                byte[] resp = timestamp(req);
                ex.getResponseHeaders().add("Content-Type", "application/timestamp-reply");
                ex.sendResponseHeaders(200, resp.length);
                try (OutputStream os = ex.getResponseBody()) {
                    os.write(resp);
                }
            } catch (Exception e) {
                ex.sendResponseHeaders(500, -1);
            }
            ex.close();
        });
        http.start();
    }

    public String tsaUrl() {
        return "http://127.0.0.1:" + port + "/tsa";
    }

    public List<X509Certificate> chain() {
        return List.of(signer, ca, root);
    }

    /** Revokes the signer certificate by republishing the CA CRL. */
    public void revokeSigner() throws Exception {
        files.put("/ca.crl", crl(ca, caKey.getPrivate(), signer.getSerialNumber()));
    }

    /** Writes the signer key and chain to a PKCS#12 file. */
    public Path writePkcs12(Path file, char[] password) throws Exception {
        KeyStore ks = KeyStore.getInstance("PKCS12");
        ks.load(null, null);
        ks.setKeyEntry("signer", signerKey.getPrivate(), password, new X509Certificate[]{signer, ca, root});
        try (OutputStream os = Files.newOutputStream(file)) {
            ks.store(os, password);
        }
        return file;
    }

    public static KeyPair rsa(int bits) throws Exception {
        KeyPairGenerator g = KeyPairGenerator.getInstance("RSA");
        g.initialize(bits);
        return g.generateKeyPair();
    }

    private static X509Certificate cert(String dn, KeyPair key, X509Certificate issuer, PrivateKey issuerKey, boolean isCa,
                                        String crlUrl, String aiaUrl, String policy) throws Exception {
        Date from = new Date(System.currentTimeMillis() - 86_400_000L);
        Date to = new Date(System.currentTimeMillis() + 365L * 86_400_000L);
        X500Name subject = new X500Name(dn);
        X500Name issuerName = issuer == null ? subject : new JcaX509CertificateHolder(issuer).getSubject();
        X509v3CertificateBuilder b = new JcaX509v3CertificateBuilder(issuerName, BigInteger.valueOf(SERIAL.incrementAndGet()),
                from, to, subject, key.getPublic());
        if (isCa) {
            b.addExtension(Extension.basicConstraints, true, new BasicConstraints(true));
            b.addExtension(Extension.keyUsage, true, new KeyUsage(KeyUsage.keyCertSign | KeyUsage.cRLSign));
        } else {
            b.addExtension(Extension.basicConstraints, true, new BasicConstraints(false));
            b.addExtension(Extension.keyUsage, true, new KeyUsage(KeyUsage.digitalSignature | KeyUsage.nonRepudiation));
        }
        if (crlUrl != null) {
            DistributionPoint dp = new DistributionPoint(new DistributionPointName(
                    new GeneralNames(new GeneralName(GeneralName.uniformResourceIdentifier, crlUrl))), null, null);
            b.addExtension(Extension.cRLDistributionPoints, false, new CRLDistPoint(new DistributionPoint[]{dp}));
        }
        if (aiaUrl != null) {
            b.addExtension(Extension.authorityInfoAccess, false, new AuthorityInformationAccess(
                    new AccessDescription(X509ObjectIdentifiers.id_ad_caIssuers,
                            new GeneralName(GeneralName.uniformResourceIdentifier, aiaUrl))));
        }
        if (policy != null) {
            b.addExtension(Extension.certificatePolicies, false,
                    new DERSequence(new PolicyInformation(new ASN1ObjectIdentifier(policy))));
        }
        ContentSigner cs = new JcaContentSignerBuilder("SHA256withRSA").build(issuerKey == null ? key.getPrivate() : issuerKey);
        return new JcaX509CertificateConverter().getCertificate(b.build(cs));
    }

    private X509Certificate tsaCert(String crlUrl) throws Exception {
        Date from = new Date(System.currentTimeMillis() - 86_400_000L);
        Date to = new Date(System.currentTimeMillis() + 365L * 86_400_000L);
        X509v3CertificateBuilder b = new JcaX509v3CertificateBuilder(new JcaX509CertificateHolder(root).getSubject(),
                BigInteger.valueOf(SERIAL.incrementAndGet()), from, to, new X500Name("CN=Test TSA,O=Signer Test,C=IN"), tsaKey.getPublic());
        b.addExtension(Extension.extendedKeyUsage, true, new ExtendedKeyUsage(KeyPurposeId.id_kp_timeStamping));
        b.addExtension(Extension.keyUsage, true, new KeyUsage(KeyUsage.digitalSignature));
        DistributionPoint dp = new DistributionPoint(new DistributionPointName(
                new GeneralNames(new GeneralName(GeneralName.uniformResourceIdentifier, crlUrl))), null, null);
        b.addExtension(Extension.cRLDistributionPoints, false, new CRLDistPoint(new DistributionPoint[]{dp}));
        return new JcaX509CertificateConverter().getCertificate(b.build(new JcaContentSignerBuilder("SHA256withRSA").build(rootKey.getPrivate())));
    }

    private static byte[] crl(X509Certificate issuer, PrivateKey key, BigInteger revoked) throws Exception {
        Date now = new Date();
        X509v2CRLBuilder b = new X509v2CRLBuilder(new JcaX509CertificateHolder(issuer).getSubject(), now);
        b.setNextUpdate(new Date(now.getTime() + 7 * 86_400_000L));
        if (revoked != null) {
            b.addCRLEntry(revoked, now, CRLReason.keyCompromise);
        }
        X509CRLHolder h = b.build(new JcaContentSignerBuilder("SHA256withRSA").build(key));
        return h.getEncoded();
    }

    private byte[] timestamp(byte[] request) throws Exception {
        TimeStampRequest req = new TimeStampRequest(request);
        TimeStampTokenGenerator gen = new TimeStampTokenGenerator(
                new JcaSimpleSignerInfoGeneratorBuilder().build("SHA256withRSA", tsaKey.getPrivate(), tsa),
                new JcaDigestCalculatorProviderBuilder().build().get(
                        new org.bouncycastle.asn1.x509.AlgorithmIdentifier(org.bouncycastle.asn1.oiw.OIWObjectIdentifiers.idSHA1)),
                new ASN1ObjectIdentifier("1.2.3.4.1"));
        gen.addCertificates(new JcaCertStore(List.of(tsa, root)));
        TimeStampResponseGenerator rg = new TimeStampResponseGenerator(gen, TSPAlgorithms.ALLOWED);
        return rg.generate(req, BigInteger.valueOf(SERIAL.incrementAndGet()), new Date()).getEncoded();
    }

    /** Simple multi-page test PDF; page 2 is rotated by the given angle. */
    public static byte[] samplePdf(int pages, int rotationOfSecondPage) throws Exception {
        try (var doc = new org.apache.pdfbox.pdmodel.PDDocument()) {
            for (int i = 0; i < pages; i++) {
                var page = new org.apache.pdfbox.pdmodel.PDPage(org.apache.pdfbox.pdmodel.common.PDRectangle.A4);
                if (i == 1) {
                    page.setRotation(rotationOfSecondPage);
                }
                doc.addPage(page);
                try (var cs = new org.apache.pdfbox.pdmodel.PDPageContentStream(doc, page)) {
                    cs.beginText();
                    cs.setFont(new org.apache.pdfbox.pdmodel.font.PDType1Font(
                            org.apache.pdfbox.pdmodel.font.Standard14Fonts.FontName.HELVETICA), 14);
                    cs.newLineAtOffset(72, 760);
                    cs.showText("e-Office note file - page " + (i + 1));
                    cs.endText();
                }
            }
            ByteArrayOutputStream out = new ByteArrayOutputStream();
            doc.save(out);
            return out.toByteArray();
        }
    }

    @Override
    public void close() {
        http.stop(0);
    }
}
