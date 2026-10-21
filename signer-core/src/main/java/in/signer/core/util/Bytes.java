package in.signer.core.util;

import in.signer.core.ErrorCode;
import in.signer.core.SignerException;

import java.io.IOException;
import java.io.InputStream;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;
import java.util.HexFormat;

/** Small byte helpers: hashing, Base64 and hex. */
public final class Bytes {

    private static final HexFormat HEX = HexFormat.of();

    private Bytes() {
    }

    public static MessageDigest digest(String algorithm) {
        try {
            return MessageDigest.getInstance(algorithm);
        } catch (NoSuchAlgorithmException e) {
            throw new SignerException(ErrorCode.BAD_REQUEST, "Unsupported digest algorithm: " + algorithm);
        }
    }

    public static byte[] sha256(byte[] data) {
        return digest("SHA-256").digest(data);
    }

    public static byte[] sha1(byte[] data) {
        return digest("SHA-1").digest(data);
    }

    public static byte[] digest(String algorithm, InputStream in) throws IOException {
        MessageDigest md = digest(algorithm);
        byte[] buf = new byte[64 * 1024];
        int n;
        while ((n = in.read(buf)) > 0) {
            md.update(buf, 0, n);
        }
        return md.digest();
    }

    public static String hex(byte[] data) {
        return HEX.formatHex(data);
    }

    public static byte[] fromHex(String hex) {
        return HEX.parseHex(hex);
    }

    public static String b64(byte[] data) {
        return Base64.getEncoder().encodeToString(data);
    }

    public static String b64url(byte[] data) {
        return Base64.getUrlEncoder().withoutPadding().encodeToString(data);
    }

    public static byte[] fromB64url(String value) {
        try {
            return Base64.getUrlDecoder().decode(value);
        } catch (IllegalArgumentException e) {
            throw new SignerException(ErrorCode.BAD_REQUEST, "Invalid base64url value");
        }
    }

    /** Decodes standard or URL-safe Base64, tolerating whitespace and an optional data-URI prefix. */
    public static byte[] fromB64(String value, String fieldName) {
        if (value == null || value.isBlank()) {
            throw SignerException.badRequest("Missing " + fieldName);
        }
        String v = value.strip();
        int comma = v.indexOf(',');
        if (v.startsWith("data:") && comma > 0) {
            v = v.substring(comma + 1);
        }
        v = v.replaceAll("\\s", "");
        try {
            if (v.indexOf('-') >= 0 || v.indexOf('_') >= 0) {
                return Base64.getUrlDecoder().decode(v);
            }
            return Base64.getDecoder().decode(v);
        } catch (IllegalArgumentException e) {
            throw SignerException.badRequest("Field '" + fieldName + "' is not valid Base64");
        }
    }
}
