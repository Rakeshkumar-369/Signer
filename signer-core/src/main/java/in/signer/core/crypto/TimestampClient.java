package in.signer.core.crypto;

import in.signer.core.ErrorCode;
import in.signer.core.SignerException;
import in.signer.core.util.Bytes;
import in.signer.core.util.Http;
import org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
import org.bouncycastle.tsp.TSPException;
import org.bouncycastle.tsp.TimeStampRequest;
import org.bouncycastle.tsp.TimeStampRequestGenerator;
import org.bouncycastle.tsp.TimeStampResponse;
import org.bouncycastle.tsp.TimeStampToken;

import java.io.IOException;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.time.Duration;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.Map;

/** RFC 3161 Time-Stamp Protocol client. */
public final class TimestampClient {

    private static final SecureRandom RANDOM = new SecureRandom();

    private final String url;
    private final String username;
    private final String password;
    private final Duration timeout;

    public TimestampClient(String url, String username, String password, Duration timeout) {
        if (url == null || url.isBlank()) {
            throw new IllegalArgumentException("TSA URL is required");
        }
        this.url = url.strip();
        this.username = username;
        this.password = password;
        this.timeout = timeout == null ? Duration.ofSeconds(20) : timeout;
    }

    public String url() {
        return url;
    }

    /** Requests a timestamp token for a SHA-256 message imprint. */
    public TimeStampToken timestamp(byte[] sha256Imprint) {
        TimeStampRequestGenerator gen = new TimeStampRequestGenerator();
        gen.setCertReq(true);
        BigInteger nonce = new BigInteger(64, RANDOM);
        TimeStampRequest request = gen.generate(NISTObjectIdentifiers.id_sha256, sha256Imprint, nonce);
        try {
            Map<String, String> headers = new LinkedHashMap<>();
            headers.put("Content-Type", "application/timestamp-query");
            if (username != null && !username.isBlank()) {
                String basic = Base64.getEncoder().encodeToString((username + ":" + (password == null ? "" : password))
                        .getBytes(StandardCharsets.UTF_8));
                headers.put("Authorization", "Basic " + basic);
            }
            byte[] body = Http.post(url, request.getEncoded(), headers, timeout);
            TimeStampResponse response = new TimeStampResponse(body);
            response.validate(request);
            TimeStampToken token = response.getTimeStampToken();
            if (token == null) {
                throw new SignerException(ErrorCode.TIMESTAMP_FAILED,
                        "Timestamp authority refused the request: " + response.getStatusString());
            }
            return token;
        } catch (IOException | TSPException e) {
            throw new SignerException(ErrorCode.TIMESTAMP_FAILED, "Timestamp request to " + url + " failed: " + e.getMessage(), e);
        }
    }

    public TimeStampToken timestampData(byte[] data) {
        return timestamp(Bytes.sha256(data));
    }
}
