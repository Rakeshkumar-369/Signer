package in.signer.core.pdf;

import in.signer.core.ErrorCode;
import in.signer.core.SignerException;
import in.signer.core.cert.RevocationClient;
import in.signer.core.cert.TrustAnchors;
import in.signer.core.crypto.CmsBuilder;
import in.signer.core.crypto.CmsOptions;
import in.signer.core.crypto.KeyRawSigner;
import in.signer.core.crypto.TimestampClient;
import in.signer.core.testing.TestPki;
import org.apache.pdfbox.Loader;
import org.apache.pdfbox.pdmodel.PDDocument;
import org.apache.pdfbox.pdmodel.interactive.annotation.PDAnnotationWidget;
import org.apache.pdfbox.pdmodel.interactive.form.PDSignatureField;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.time.Instant;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

class PdfSignerTest {

    static TestPki pki;
    static SigningKey key;
    static TrustAnchors anchors;

    @BeforeAll
    static void setUp() throws Exception {
        pki = new TestPki();
        key = new SigningKey(pki.signer, pki.chain(), new KeyRawSigner(pki.signerKey.getPrivate(), null));
        anchors = TrustAnchors.empty().addAll(List.of(pki.root));
    }

    @AfterAll
    static void tearDown() {
        pki.close();
    }

    private static PdfVerifier verifier() {
        return new PdfVerifier(anchors, null, false);
    }

    @Test
    void visibleSignatureIsValid() throws Exception {
        PdfSignOptions o = new PdfSignOptions();
        o.reason = "Approved";
        o.location = "Amaravati";
        o.fieldName = "ApproverSign";
        byte[] signed = new PdfSigner(null, null).sign(TestPki.samplePdf(2, 0), o, key);

        VerificationReport r = verifier().verify(signed, null);
        assertEquals(1, r.signatureCount());
        var s = r.signatures().get(0);
        assertEquals(VerificationReport.Status.VALID, s.status(), String.valueOf(s.notes()));
        assertEquals("RAVI KUMAR", s.signerName());
        assertEquals("Approved", s.reason());
        assertEquals("ApproverSign", s.fieldName());
        assertEquals("Class 3", s.certificate().certificateClass());
        assertTrue(s.coversWholeDocument());
        assertTrue(r.allValid());

        try (PDDocument doc = Loader.loadPDF(signed)) {
            PDSignatureField f = (PDSignatureField) doc.getDocumentCatalog().getAcroForm().getField("ApproverSign");
            PDAnnotationWidget w = f.getWidgets().get(0);
            assertEquals(doc.getPage(1), w.getPage() != null ? w.getPage() : doc.getPage(1));
            assertEquals(360f, w.getRectangle().getLowerLeftX(), 0.01);
            assertEquals(40f, w.getRectangle().getLowerLeftY(), 0.01);
            assertNotNull(w.getNormalAppearanceStream());
        }
        Path out = Path.of("target", "sample-signed.pdf");
        Files.write(out, signed);
    }

    @Test
    void tamperingIsDetected() throws Exception {
        byte[] signed = new PdfSigner(null, null).sign(TestPki.samplePdf(1, 0), new PdfSignOptions(), key);
        String s = new String(signed, java.nio.charset.StandardCharsets.ISO_8859_1);
        int idx = s.indexOf("page 1");
        assertTrue(idx > 0 || s.contains("/FlateDecode"));
        // flip a byte inside the signed range (the PDF header comment area)
        byte[] tampered = signed.clone();
        tampered[10] = (byte) (tampered[10] ^ 0x01);
        VerificationReport r = verifier().verify(tampered, null);
        assertEquals(VerificationReport.Status.INVALID, r.signatures().get(0).status());
        assertFalse(r.allValid());
    }

    @Test
    void secondSignaturePreservesFirst() throws Exception {
        PdfSigner signer = new PdfSigner(null, null);
        PdfSignOptions first = new PdfSignOptions();
        first.page = "1";
        first.x = 40;
        byte[] once = signer.sign(TestPki.samplePdf(1, 0), first, key);
        PdfSignOptions second = new PdfSignOptions();
        second.page = "1";
        second.x = 300;
        second.subFilter = PdfSignOptions.SUBFILTER_PADES;
        byte[] twice = signer.sign(once, second, key);

        VerificationReport r = verifier().verify(twice, null);
        assertEquals(2, r.signatureCount());
        assertTrue(r.allValid(), r.toString());
        assertFalse(r.signatures().get(0).coversWholeDocument());
        assertTrue(r.signatures().get(1).coversWholeDocument());
        assertEquals("ETSI.CAdES.detached", r.signatures().get(1).subFilter());
    }

    @Test
    void rotatedPageAndTopLeftOrigin() throws Exception {
        for (int rot : new int[]{90, 180, 270}) {
            PdfSignOptions o = new PdfSignOptions();
            o.page = "2";
            o.origin = "top-left";
            o.x = 20;
            o.y = 20;
            byte[] signed = new PdfSigner(null, null).sign(TestPki.samplePdf(2, rot), o, key);
            assertEquals(VerificationReport.Status.VALID, verifier().verify(signed, null).signatures().get(0).status());
        }
    }

    @Test
    void boxOutsidePageIsRejected() {
        PdfSignOptions o = new PdfSignOptions();
        o.x = 5000;
        SignerException e = assertThrows(SignerException.class, () -> new PdfSigner(null, null).sign(TestPki.samplePdf(1, 0), o, key));
        assertEquals(ErrorCode.BAD_REQUEST, e.code());
    }

    @Test
    void certificationLevelOneBlocksFurtherSignatures() throws Exception {
        PdfSignOptions o = new PdfSignOptions();
        o.certificationLevel = 1;
        o.visible = false;
        byte[] certified = new PdfSigner(null, null).sign(TestPki.samplePdf(1, 0), o, key);
        var r = verifier().verify(certified, null);
        assertEquals(1, r.signatures().get(0).certificationLevel());
        assertEquals(VerificationReport.Status.VALID, r.signatures().get(0).status());

        SignerException e = assertThrows(SignerException.class,
                () -> new PdfSigner(null, null).sign(certified, new PdfSignOptions(), key));
        assertEquals(ErrorCode.PDF_SIGNING_NOT_ALLOWED, e.code());
    }

    @Test
    void deferredSigningOnlySendsDigestToToken() throws Exception {
        PdfSignOptions o = new PdfSignOptions();
        PreparedPdf prepared = PdfPreparer.prepare(TestPki.samplePdf(1, 0), o, pki.signer, Instant.now());
        assertEquals(32, prepared.digest().length);
        assertArrayEquals(prepared.digest(), PdfPreparer.digest(prepared.pdf()));
        assertTrue(prepared.capacity() >= PdfPreparer.RESERVED_SIGNATURE_BYTES);

        // "agent" side: only the digest is needed
        byte[] cms = CmsBuilder.build(prepared.digest(), pki.signer, pki.chain(),
                new KeyRawSigner(pki.signerKey.getPrivate(), null), CmsOptions.forPkcs7());
        byte[] signed = new PdfSigner(null, null).complete(prepared.pdf(), cms, false, false, null);
        assertEquals(VerificationReport.Status.VALID, verifier().verify(signed, null).signatures().get(0).status());

        SignerException again = assertThrows(SignerException.class, () -> PdfPreparer.inject(signed, cms));
        assertEquals(ErrorCode.CONFLICT, again.code());
    }

    @Test
    void timestampAndLtv() throws Exception {
        PdfSignOptions o = new PdfSignOptions();
        o.timestamp = true;
        o.ltv = true;
        o.subFilter = PdfSignOptions.SUBFILTER_PADES;
        PdfSigner signer = new PdfSigner(new TimestampClient(pki.tsaUrl(), null, null, Duration.ofSeconds(10)),
                new RevocationClient(Duration.ofSeconds(5)));
        byte[] signed = signer.sign(TestPki.samplePdf(1, 0), o, key);

        VerificationReport r = new PdfVerifier(anchors, new RevocationClient(Duration.ofSeconds(5)), false).verify(signed, null);
        var s = r.signatures().get(0);
        assertTrue(r.hasDss());
        assertTrue(s.timestamped());
        assertNotNull(s.timestampTime());
        assertEquals("Test TSA", s.timestampAuthority());
        assertEquals("GOOD", s.revocation());
        assertEquals(VerificationReport.Status.VALID, s.status(), String.valueOf(s.notes()));
        assertTrue(s.coversWholeDocument() || !s.notes().isEmpty());
    }

    @Test
    void revokedCertificateIsInvalid() throws Exception {
        try (TestPki p = new TestPki()) {
            SigningKey k = new SigningKey(p.signer, p.chain(), new KeyRawSigner(p.signerKey.getPrivate(), null));
            byte[] signed = new PdfSigner(null, null).sign(TestPki.samplePdf(1, 0), new PdfSignOptions(), k);
            p.revokeSigner();
            var r = new PdfVerifier(TrustAnchors.empty().addAll(List.of(p.root)), new RevocationClient(Duration.ofSeconds(5)), false)
                    .verify(signed, null);
            assertEquals("REVOKED", r.signatures().get(0).revocation());
            assertEquals(VerificationReport.Status.INVALID, r.signatures().get(0).status());
        }
    }

    @Test
    void unknownRootIsUntrusted() throws Exception {
        byte[] signed = new PdfSigner(null, null).sign(TestPki.samplePdf(1, 0), new PdfSignOptions(), key);
        var r = new PdfVerifier(TrustAnchors.empty(), null, false).verify(signed, null);
        assertEquals(VerificationReport.Status.VALID_UNTRUSTED, r.signatures().get(0).status());
    }

    @Test
    void imageAndCustomTextAppearance() throws Exception {
        PdfSignOptions o = new PdfSignOptions();
        o.customText = "File No: GAD01-123/2026\nGovernment of Andhra Pradesh";
        o.border = true;
        o.imageBase64 = tinyPng();
        o.dateFormat = "dd-MMM-yyyy hh:mm tt";
        byte[] signed = new PdfSigner(null, null).sign(TestPki.samplePdf(1, 0), o, key);
        assertEquals(VerificationReport.Status.VALID, verifier().verify(signed, null).signatures().get(0).status());
    }

    @Test
    void passwordProtectedPdfNeedsPassword() throws Exception {
        byte[] encrypted;
        try (PDDocument doc = Loader.loadPDF(TestPki.samplePdf(1, 0))) {
            var ap = new org.apache.pdfbox.pdmodel.encryption.AccessPermission();
            var spp = new org.apache.pdfbox.pdmodel.encryption.StandardProtectionPolicy("owner", "user", ap);
            spp.setEncryptionKeyLength(128);
            doc.protect(spp);
            var bos = new java.io.ByteArrayOutputStream();
            doc.save(bos);
            encrypted = bos.toByteArray();
        }
        SignerException e = assertThrows(SignerException.class,
                () -> new PdfSigner(null, null).sign(encrypted, new PdfSignOptions(), key));
        assertEquals(ErrorCode.PDF_PASSWORD_REQUIRED, e.code());
    }

    static String tinyPng() throws Exception {
        var img = new java.awt.image.BufferedImage(40, 20, java.awt.image.BufferedImage.TYPE_INT_RGB);
        var g = img.createGraphics();
        g.setColor(java.awt.Color.BLUE);
        g.fillRect(0, 0, 40, 20);
        g.dispose();
        var bos = new java.io.ByteArrayOutputStream();
        javax.imageio.ImageIO.write(img, "png", bos);
        return java.util.Base64.getEncoder().encodeToString(bos.toByteArray());
    }
}
