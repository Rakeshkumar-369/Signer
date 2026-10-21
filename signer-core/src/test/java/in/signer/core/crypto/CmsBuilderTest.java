package in.signer.core.crypto;

import in.signer.core.testing.TestPki;
import in.signer.core.util.Bytes;
import org.bouncycastle.asn1.cms.CMSAttributes;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.cms.CMSProcessableByteArray;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.SignerInformation;
import org.bouncycastle.cms.jcajce.JcaSimpleSignerInfoVerifierBuilder;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.util.Date;

import static org.junit.jupiter.api.Assertions.*;

class CmsBuilderTest {

    static TestPki pki;

    @BeforeAll
    static void setUp() throws Exception {
        pki = new TestPki();
    }

    @AfterAll
    static void tearDown() {
        pki.close();
    }

    private RawSigner signer() {
        return new KeyRawSigner(pki.signerKey.getPrivate(), null);
    }

    @Test
    void detachedPkcs7VerifiesAgainstContent() throws Exception {
        byte[] data = "file note 42".getBytes(StandardCharsets.UTF_8);
        byte[] cms = CmsBuilder.build(Bytes.sha256(data), pki.signer, pki.chain(), signer(), CmsOptions.forPkcs7());

        CMSSignedData sd = new CMSSignedData(new CMSProcessableByteArray(data), cms);
        SignerInformation si = sd.getSignerInfos().getSigners().iterator().next();
        assertTrue(si.verify(new JcaSimpleSignerInfoVerifierBuilder().build(pki.signer)));
        assertNotNull(si.getSignedAttributes().get(CMSAttributes.signingTime));
        assertEquals(3, sd.getCertificates().getMatches(null).size());
    }

    @Test
    void padesOmitsSigningTimeAndAddsSigningCertificateV2() throws Exception {
        byte[] data = "pades".getBytes(StandardCharsets.UTF_8);
        byte[] cms = CmsBuilder.build(Bytes.sha256(data), pki.signer, pki.chain(), signer(), new CmsOptions(true, new Date()));
        SignerInformation si = new CMSSignedData(new CMSProcessableByteArray(data), cms).getSignerInfos().getSigners().iterator().next();
        assertNull(si.getSignedAttributes().get(CMSAttributes.signingTime));
        assertNotNull(si.getSignedAttributes().get(PKCSObjectIdentifiers.id_aa_signingCertificateV2));
        assertTrue(si.verify(new JcaSimpleSignerInfoVerifierBuilder().build(pki.signer)));
    }

    @Test
    void wrongContentFailsVerification() throws Exception {
        byte[] cms = CmsBuilder.build(Bytes.sha256("a".getBytes()), pki.signer, pki.chain(), signer(), CmsOptions.forPkcs7());
        SignerInformation si = new CMSSignedData(new CMSProcessableByteArray("b".getBytes()), cms).getSignerInfos().getSigners().iterator().next();
        assertThrows(Exception.class, () -> si.verify(new JcaSimpleSignerInfoVerifierBuilder().build(pki.signer)));
    }

    @Test
    void timestampIsEmbedded() throws Exception {
        byte[] data = "ts".getBytes();
        byte[] cms = CmsBuilder.build(Bytes.sha256(data), pki.signer, pki.chain(), signer(), CmsOptions.forPkcs7());
        byte[] stamped = CmsTimestamper.addSignatureTimestamp(cms, new TimestampClient(pki.tsaUrl(), null, null, null));
        SignerInformation si = new CMSSignedData(new CMSProcessableByteArray(data), stamped).getSignerInfos().getSigners().iterator().next();
        assertNotNull(si.getUnsignedAttributes().get(PKCSObjectIdentifiers.id_aa_signatureTimeStampToken));
        assertTrue(si.verify(new JcaSimpleSignerInfoVerifierBuilder().build(pki.signer)));
    }
}
