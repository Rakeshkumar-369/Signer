package in.signer.core.cert;

import in.signer.core.ErrorCode;
import in.signer.core.SignerException;
import in.signer.core.util.Http;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.ocsp.OCSPObjectIdentifiers;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.Extensions;
import org.bouncycastle.cert.jcajce.JcaX509CertificateHolder;
import org.bouncycastle.cert.ocsp.BasicOCSPResp;
import org.bouncycastle.cert.ocsp.CertificateID;
import org.bouncycastle.cert.ocsp.OCSPReq;
import org.bouncycastle.cert.ocsp.OCSPReqBuilder;
import org.bouncycastle.cert.ocsp.OCSPResp;
import org.bouncycastle.cert.ocsp.RevokedStatus;
import org.bouncycastle.cert.ocsp.SingleResp;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.ByteArrayInputStream;
import java.math.BigInteger;
import java.security.SecureRandom;
import java.security.cert.CertificateFactory;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.util.Map;

/** Fetches OCSP responses and CRLs for LTV embedding and revocation checks. */
public final class RevocationClient {

    private static final Logger log = LoggerFactory.getLogger(RevocationClient.class);
    private static final SecureRandom RANDOM = new SecureRandom();

    public enum Status { GOOD, REVOKED, UNKNOWN }

    public record Result(Status status, String source, byte[] ocspResponse, byte[] crl, String detail) {
    }

    private final Duration timeout;

    public RevocationClient(Duration timeout) {
        this.timeout = timeout == null ? Duration.ofSeconds(15) : timeout;
    }

    /** Returns the DER encoded OCSPResponse, or null when the certificate has no usable OCSP responder. */
    public byte[] fetchOcsp(X509Certificate cert, X509Certificate issuer) {
        for (String url : Certificates.ocspUrls(cert)) {
            try {
                CertificateID id = new CertificateID(
                        new JcaDigestCalculatorProviderBuilder().build().get(CertificateID.HASH_SHA1),
                        new JcaX509CertificateHolder(issuer), cert.getSerialNumber());
                OCSPReqBuilder builder = new OCSPReqBuilder().addRequest(id);
                byte[] nonce = new BigInteger(64, RANDOM).toByteArray();
                builder.setRequestExtensions(new Extensions(new Extension(
                        OCSPObjectIdentifiers.id_pkix_ocsp_nonce, false, new DEROctetString(nonce))));
                OCSPReq req = builder.build();
                byte[] body = Http.post(url, req.getEncoded(), Map.of("Content-Type", "application/ocsp-request"), timeout);
                OCSPResp resp = new OCSPResp(body);
                if (resp.getStatus() == OCSPResp.SUCCESSFUL) {
                    return resp.getEncoded();
                }
                log.warn("OCSP responder {} returned status {}", url, resp.getStatus());
            } catch (Exception e) {
                log.warn("OCSP request to {} failed: {}", url, e.getMessage());
            }
        }
        return null;
    }

    public byte[] fetchCrl(X509Certificate cert) {
        for (String url : Certificates.crlUrls(cert)) {
            if (!url.startsWith("http")) {
                continue;
            }
            try {
                return Http.get(url, timeout);
            } catch (Exception e) {
                log.warn("CRL download from {} failed: {}", url, e.getMessage());
            }
        }
        return null;
    }

    /** Checks revocation using OCSP first and the CRL as a fallback. */
    public Result check(X509Certificate cert, X509Certificate issuer) {
        byte[] ocsp = issuer == null ? null : fetchOcsp(cert, issuer);
        if (ocsp != null) {
            try {
                BasicOCSPResp basic = (BasicOCSPResp) new OCSPResp(ocsp).getResponseObject();
                for (SingleResp r : basic.getResponses()) {
                    if (r.getCertID().getSerialNumber().equals(cert.getSerialNumber())) {
                        Object st = r.getCertStatus();
                        if (st == null) {
                            return new Result(Status.GOOD, "OCSP", ocsp, null, "Certificate is not revoked (OCSP)");
                        }
                        if (st instanceof RevokedStatus rs) {
                            return new Result(Status.REVOKED, "OCSP", ocsp, null, "Revoked on " + rs.getRevocationTime());
                        }
                    }
                }
            } catch (Exception e) {
                log.warn("Unreadable OCSP response: {}", e.getMessage());
            }
        }
        byte[] crlBytes = fetchCrl(cert);
        if (crlBytes != null) {
            try {
                X509CRL crl = parseCrl(crlBytes);
                if (issuer != null) {
                    crl.verify(issuer.getPublicKey());
                }
                if (crl.isRevoked(cert)) {
                    return new Result(Status.REVOKED, "CRL", null, crlBytes, "Certificate is listed in the CRL");
                }
                return new Result(Status.GOOD, "CRL", null, crlBytes, "Certificate is not listed in the CRL");
            } catch (Exception e) {
                log.warn("Unusable CRL: {}", e.getMessage());
            }
        }
        return new Result(Status.UNKNOWN, null, null, null, "Revocation information unavailable");
    }

    public static X509CRL parseCrl(byte[] data) {
        try {
            return (X509CRL) CertificateFactory.getInstance("X.509").generateCRL(new ByteArrayInputStream(data));
        } catch (Exception e) {
            throw new SignerException(ErrorCode.REVOCATION_FETCH_FAILED, "Invalid CRL: " + e.getMessage(), e);
        }
    }
}
