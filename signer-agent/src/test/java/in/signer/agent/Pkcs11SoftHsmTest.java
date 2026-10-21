package in.signer.agent;

import in.signer.agent.token.Pkcs11TokenProvider;
import in.signer.agent.token.TokenCertificate;
import in.signer.core.ErrorCode;
import in.signer.core.SignerException;
import in.signer.core.cert.TrustAnchors;
import in.signer.core.pdf.PdfSignOptions;
import in.signer.core.pdf.PdfSigner;
import in.signer.core.pdf.PdfVerifier;
import in.signer.core.pdf.SigningKey;
import in.signer.core.pdf.VerificationReport;
import in.signer.core.testing.TestPki;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.Test;

import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyStore;
import java.security.Provider;
import java.security.Security;
import java.security.cert.X509Certificate;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Exercises the real PKCS#11 code path against SoftHSM2, a software token that behaves like a USB DSC token.
 * Skipped automatically when SoftHSM2 is not installed.
 */
class Pkcs11SoftHsmTest {

    static final Path LIB = Path.of("/usr/lib/softhsm/libsofthsm2.so");

    @Test
    void signWithPkcs11Token() throws Exception {
        Assumptions.assumeTrue(Files.isRegularFile(LIB), "SoftHSM2 not installed");
        String conf = System.getenv("SOFTHSM2_CONF");
        Assumptions.assumeTrue(conf != null, "SOFTHSM2_CONF not set");
        Path confFile = Path.of(conf);
        Path tokens = confFile.getParent().resolve("tokens");
        Files.createDirectories(tokens);
        Files.writeString(confFile, "directories.tokendir = " + tokens + "\nobjectstore.backend = file\nlog.level = ERROR\n");
        Process init = new ProcessBuilder("softhsm2-util", "--init-token", "--free", "--label", "DSC", "--pin", "1234", "--so-pin", "5678")
                .redirectErrorStream(true).start();
        assertEquals(0, init.waitFor(), new String(init.getInputStream().readAllBytes()));

        try (TestPki pki = new TestPki()) {
            // Load key + certificate onto the token, as a CA does when issuing a DSC.
            Provider p = Security.getProvider("SunPKCS11").configure("--name=import\nlibrary=" + LIB + "\nslotListIndex=0\n");
            KeyStore ks = KeyStore.getInstance("PKCS11", p);
            ks.load(null, "1234".toCharArray());
            ks.setKeyEntry("ravi", pki.signerKey.getPrivate(), null, new X509Certificate[]{pki.signer, pki.ca});

            Pkcs11TokenProvider token = new Pkcs11TokenProvider(LIB, 0);
            List<TokenCertificate> certs = token.certificates();
            assertEquals(1, certs.size(), "certificate should be visible without PIN");
            assertEquals("RAVI KUMAR", certs.get(0).info().commonName());

            SignerException wrong = assertThrows(SignerException.class, () -> token.unlock(certs.get(0), "0000".toCharArray()));
            assertEquals(ErrorCode.PIN_INCORRECT, wrong.code());

            SigningKey key = token.unlock(certs.get(0), "1234".toCharArray());
            byte[] signed = new PdfSigner(null, null).sign(TestPki.samplePdf(1, 0), new PdfSignOptions(),
                    new SigningKey(key.certificate(), pki.chain(), key.signer()));
            token.release();

            var report = new PdfVerifier(TrustAnchors.empty().addAll(List.of(pki.root)), null, false).verify(signed, null);
            assertEquals(VerificationReport.Status.VALID, report.signatures().get(0).status(), report.toString());
        }
    }
}
