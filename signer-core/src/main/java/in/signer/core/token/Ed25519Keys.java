package in.signer.core.token;

import in.signer.core.util.Bytes;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;
import java.util.Base64;

/** Ed25519 key helpers: generation, PEM/raw encoding and key ids. */
public final class Ed25519Keys {

    /** DER SubjectPublicKeyInfo prefix for a raw 32-byte Ed25519 public key. */
    private static final byte[] SPKI_PREFIX = Bytes.fromHex("302a300506032b6570032100");

    private Ed25519Keys() {
    }

    public static KeyPair generate() {
        try {
            return KeyPairGenerator.getInstance("Ed25519").generateKeyPair();
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("Ed25519 not available", e);
        }
    }

    /** Raw 32-byte public key, base64url encoded (the JWK "x" value). */
    public static String publicKeyToString(PublicKey key) {
        byte[] spki = key.getEncoded();
        return Bytes.b64url(Arrays.copyOfRange(spki, spki.length - 32, spki.length));
    }

    public static PublicKey publicKeyFromString(String value) {
        String v = value.strip();
        byte[] raw = v.startsWith("-----") ? pemBody(v) : Bytes.fromB64url(v);
        byte[] spki = raw.length == 32 ? concat(SPKI_PREFIX, raw) : raw;
        try {
            return KeyFactory.getInstance("Ed25519").generatePublic(new X509EncodedKeySpec(spki));
        } catch (GeneralSecurityException e) {
            throw new IllegalArgumentException("Invalid Ed25519 public key", e);
        }
    }

    public static String keyId(PublicKey key) {
        return Bytes.b64url(Bytes.sha256(Bytes.fromB64url(publicKeyToString(key)))).substring(0, 16);
    }

    public static String privateKeyToPem(PrivateKey key) {
        return "-----BEGIN PRIVATE KEY-----\n"
                + Base64.getMimeEncoder(64, "\n".getBytes(StandardCharsets.US_ASCII)).encodeToString(key.getEncoded())
                + "\n-----END PRIVATE KEY-----\n";
    }

    public static PrivateKey privateKeyFromPem(String pem) {
        try {
            return KeyFactory.getInstance("Ed25519").generatePrivate(new PKCS8EncodedKeySpec(pemBody(pem)));
        } catch (GeneralSecurityException e) {
            throw new IllegalArgumentException("Invalid Ed25519 private key", e);
        }
    }

    /** Derives the public key from an Ed25519 PKCS#8 private key file written by {@link #privateKeyToPem}. */
    public static PublicKey publicFromPrivate(PrivateKey key) {
        try {
            var bc = org.bouncycastle.crypto.params.Ed25519PrivateKeyParameters.class;
            byte[] pkcs8 = key.getEncoded();
            byte[] seed = Arrays.copyOfRange(pkcs8, pkcs8.length - 32, pkcs8.length);
            byte[] pub = bc.getConstructor(byte[].class, int.class).newInstance(seed, 0).generatePublicKey().getEncoded();
            return publicKeyFromString(Bytes.b64url(pub));
        } catch (ReflectiveOperationException e) {
            throw new IllegalStateException(e);
        }
    }

    public static KeyPair loadOrCreate(Path privateKeyFile) throws java.io.IOException {
        if (Files.isRegularFile(privateKeyFile)) {
            PrivateKey priv = privateKeyFromPem(Files.readString(privateKeyFile));
            return new KeyPair(publicFromPrivate(priv), priv);
        }
        KeyPair kp = generate();
        if (privateKeyFile.getParent() != null) {
            Files.createDirectories(privateKeyFile.getParent());
        }
        Files.writeString(privateKeyFile, privateKeyToPem(kp.getPrivate()));
        try {
            Files.setPosixFilePermissions(privateKeyFile, java.nio.file.attribute.PosixFilePermissions.fromString("rw-------"));
        } catch (UnsupportedOperationException ignored) {
            // Windows: protected by the directory ACL
        }
        return kp;
    }

    private static byte[] pemBody(String pem) {
        String body = pem.replaceAll("-----[A-Z ]+-----", "").replaceAll("\\s", "");
        return Base64.getDecoder().decode(body);
    }

    private static byte[] concat(byte[] a, byte[] b) {
        byte[] out = Arrays.copyOf(a, a.length + b.length);
        System.arraycopy(b, 0, out, a.length, b.length);
        return out;
    }
}
