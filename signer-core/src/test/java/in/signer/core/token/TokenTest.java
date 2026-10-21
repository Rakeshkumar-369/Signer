package in.signer.core.token;

import in.signer.core.ErrorCode;
import in.signer.core.SignerException;
import in.signer.core.license.LicenseCodec;
import in.signer.core.license.LicenseInfo;
import org.junit.jupiter.api.Test;

import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyPair;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

class TokenTest {

    static TransactionToken token(Instant now) {
        return new TransactionToken("txn-1", "signer-server", "t1", "GAD", "https://eoffice.ap.gov.in",
                List.of("certificates", "sign"), 5, "FILE-1", now, now.plusSeconds(300));
    }

    @Test
    void roundTrip() {
        KeyPair kp = Ed25519Keys.generate();
        String kid = Ed25519Keys.keyId(kp.getPublic());
        Instant now = Instant.now();
        String jws = Jws.sign(token(now).toClaims(), TransactionToken.TYPE, kid, kp.getPrivate());

        TransactionToken t = new TokenVerifier(Map.of(kid, kp.getPublic())).verify(jws);
        assertEquals("txn-1", t.txn());
        assertEquals("https://eoffice.ap.gov.in", t.origin());
        assertTrue(t.allows("sign"));
        assertEquals(5, t.maxDocuments());
        assertEquals("FILE-1", t.reference());
    }

    @Test
    void rejectsExpiredTamperedAndUnknownKeys() {
        KeyPair kp = Ed25519Keys.generate();
        String kid = Ed25519Keys.keyId(kp.getPublic());
        String jws = Jws.sign(token(Instant.now()).toClaims(), TransactionToken.TYPE, kid, kp.getPrivate());

        Clock later = Clock.fixed(Instant.now().plus(Duration.ofHours(1)), ZoneOffset.UTC);
        var expired = assertThrows(SignerException.class,
                () -> new TokenVerifier(Map.of(kid, kp.getPublic()), Duration.ofSeconds(60), later).verify(jws));
        assertEquals(ErrorCode.TOKEN_EXPIRED, expired.code());

        String[] p = jws.split("\\.");
        String tampered = p[0] + "." + p[1].substring(0, p[1].length() - 2) + "AA." + p[2];
        assertThrows(SignerException.class, () -> new TokenVerifier(Map.of(kid, kp.getPublic())).verify(tampered));

        KeyPair other = Ed25519Keys.generate();
        var unknown = assertThrows(SignerException.class,
                () -> new TokenVerifier(Map.of(Ed25519Keys.keyId(other.getPublic()), other.getPublic())).verify(jws));
        assertEquals(ErrorCode.TOKEN_INVALID, unknown.code());
    }

    @Test
    void keyEncodingAndPersistence() throws Exception {
        Path dir = Files.createTempDirectory("keys");
        KeyPair kp = Ed25519Keys.loadOrCreate(dir.resolve("k.pem"));
        KeyPair again = Ed25519Keys.loadOrCreate(dir.resolve("k.pem"));
        assertEquals(Ed25519Keys.publicKeyToString(kp.getPublic()), Ed25519Keys.publicKeyToString(again.getPublic()));
        assertEquals(kp.getPublic(), Ed25519Keys.publicKeyFromString(Ed25519Keys.publicKeyToString(kp.getPublic())));
    }

    @Test
    void licenceRoundTrip() {
        KeyPair vendor = Ed25519Keys.generate();
        LicenseInfo l = new LicenseInfo("L-1", "APTS", "enterprise", Instant.now(), Instant.now().plusSeconds(86400),
                10, 100000, List.of("server-signing", "ltv"));
        String text = LicenseCodec.issue(l, vendor.getPrivate());
        LicenseInfo back = LicenseCodec.verify(text, vendor.getPublic());
        assertEquals("APTS", back.licensee());
        assertTrue(back.hasFeature("ltv"));
        assertFalse(back.expired(Instant.now()));
        var e = assertThrows(SignerException.class, () -> LicenseCodec.verify(text, Ed25519Keys.generate().getPublic()));
        assertEquals(ErrorCode.LICENSE_INVALID, e.code());
    }
}
