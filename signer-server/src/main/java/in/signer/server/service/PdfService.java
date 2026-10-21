package in.signer.server.service;

import in.signer.core.ErrorCode;
import in.signer.core.SignerException;
import in.signer.core.cert.CertificateInfo;
import in.signer.core.cert.Certificates;
import in.signer.core.cert.RevocationClient;
import in.signer.core.cert.TrustAnchors;
import in.signer.core.crypto.TimestampClient;
import in.signer.core.pdf.PdfPreparer;
import in.signer.core.pdf.PdfSignOptions;
import in.signer.core.pdf.PdfSigner;
import in.signer.core.pdf.PdfVerifier;
import in.signer.core.pdf.PreparedPdf;
import in.signer.core.pdf.VerificationReport;
import in.signer.core.util.Bytes;
import in.signer.server.config.SignerProperties;
import in.signer.server.repo.SessionRepository;
import in.signer.server.repo.SigningSession;
import in.signer.server.repo.Tenant;
import in.signer.server.repo.Txn;
import in.signer.server.repo.TxnRepository;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.cms.Attribute;
import org.bouncycastle.asn1.cms.CMSAttributes;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.SignerInformation;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;

import java.nio.file.Path;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.List;
import java.util.UUID;

/**
 * Server-side PDF signing: the server prepares the PDF and keeps it; only the 32-byte digest goes to the
 * user's token through the agent; the returned CMS is embedded here (optionally timestamped / LTV-enabled).
 */
@Service
public class PdfService {

    private static final Logger log = LoggerFactory.getLogger(PdfService.class);

    public record Prepared(String sessionId, String digest, String digestAlgorithm, String format, Instant expiresAt) {
    }

    public record Completed(byte[] pdf, CertificateInfo signer, boolean timestamped, boolean ltv) {
    }

    private final SessionRepository sessions;
    private final TxnRepository txns;
    private final SignerProperties props;
    private final PdfSigner signer;
    private final TrustAnchors anchors;
    private final RevocationClient revocation;

    public PdfService(SessionRepository sessions, TxnRepository txns, SignerProperties props) {
        this.sessions = sessions;
        this.txns = txns;
        this.props = props;
        String tsaUrl = props.getTsa().getUrl();
        TimestampClient tsa = tsaUrl == null || tsaUrl.isBlank() ? null
                : new TimestampClient(tsaUrl, props.getTsa().getUsername(), props.getTsa().getPassword(), Duration.ofSeconds(20));
        this.revocation = new RevocationClient(Duration.ofSeconds(15));
        this.signer = new PdfSigner(tsa, revocation);
        this.anchors = TrustAnchors.fromDirectory(Path.of(props.getVerification().getTrustAnchorsDir()));
    }

    public boolean hasTsa() {
        return signer.hasTsa();
    }

    public Prepared prepare(Tenant tenant, String txn, byte[] pdf, String name, PdfSignOptions options, String certificateB64) {
        checkSize(pdf);
        PdfSignOptions o = options == null ? new PdfSignOptions() : options;
        if (o.timestamp && !signer.hasTsa()) {
            throw new SignerException(ErrorCode.TIMESTAMP_FAILED, "No timestamp authority is configured on the server (signer.tsa.url)");
        }
        // Fonts on the server file system must not be selectable by API callers.
        o.fontPath = null;
        X509Certificate cert = certificateB64 == null || certificateB64.isBlank() ? null
                : Certificates.parse(Bytes.fromB64(certificateB64, "certificate"));
        if (cert != null && !Certificates.isValidAt(cert, new java.util.Date())) {
            throw new SignerException(ErrorCode.CERTIFICATE_EXPIRED, "The signer certificate has expired or is not yet valid");
        }
        Instant now = Instant.now();
        PreparedPdf p = PdfPreparer.prepare(pdf, o, cert, now);
        String id = UUID.randomUUID().toString();
        Instant expires = now.plus(Duration.ofMinutes(props.getSessions().getTtlMinutes()));
        sessions.insert(new SigningSession(id, tenant.id(), txn, SigningSession.PREPARED, name, Bytes.hex(p.digest()),
                certificateB64 == null || certificateB64.isBlank() ? null : Bytes.b64(Certificates.encoded(cert)),
                o.timestamp, o.ltv, now, expires), p.pdf());
        return new Prepared(id, Bytes.b64(p.digest()), "SHA-256", o.isPades() ? "pades" : "cms", expires);
    }

    public Completed complete(Tenant tenant, String sessionId, byte[] cms) {
        SigningSession s = sessions.findById(sessionId)
                .filter(x -> x.tenantId().equals(tenant.id()))
                .orElseThrow(() -> new SignerException(ErrorCode.NOT_FOUND, "Signing session not found"));
        if (!SigningSession.PREPARED.equals(s.status())) {
            throw new SignerException(ErrorCode.CONFLICT, "This document has already been signed");
        }
        if (Instant.now().isAfter(s.expiresAt())) {
            throw new SignerException(ErrorCode.NOT_FOUND, "Signing session has expired; prepare the document again");
        }
        X509Certificate signerCert;
        List<X509Certificate> cmsCerts = new ArrayList<>();
        try {
            CMSSignedData sd = new CMSSignedData(cms);
            SignerInformation si = sd.getSignerInfos().getSigners().iterator().next();
            Attribute md = si.getSignedAttributes() == null ? null : si.getSignedAttributes().get(CMSAttributes.messageDigest);
            if (md == null || !Arrays.equals(ASN1OctetString.getInstance(md.getAttrValues().getObjectAt(0)).getOctets(),
                    Bytes.fromHex(s.digestHex()))) {
                throw SignerException.badRequest("The signature does not belong to the prepared document");
            }
            JcaX509CertificateConverter conv = new JcaX509CertificateConverter();
            for (X509CertificateHolder h : sd.getCertificates().getMatches(null)) {
                cmsCerts.add(conv.getCertificate(h));
            }
            @SuppressWarnings("unchecked")
            Collection<X509CertificateHolder> m = sd.getCertificates().getMatches(si.getSID());
            if (m.isEmpty()) {
                throw SignerException.badRequest("The signature does not contain the signer certificate");
            }
            signerCert = conv.getCertificate(m.iterator().next());
        } catch (SignerException e) {
            throw e;
        } catch (Exception e) {
            throw SignerException.badRequest("signature is not a valid CMS/PKCS#7 structure: " + e.getMessage());
        }
        if (s.certificate() != null && !s.certificate().equals(Bytes.b64(Certificates.encoded(signerCert)))) {
            throw SignerException.badRequest("The document was signed with a different certificate than the one it was prepared for");
        }
        byte[] prepared = sessions.pdf(sessionId);
        if (prepared == null) {
            throw new SignerException(ErrorCode.CONFLICT, "This document has already been signed");
        }
        byte[] signed = signer.complete(prepared, cms, s.timestamp(), s.ltv(), cmsCerts);
        VerificationReport check = new PdfVerifier(anchors, null, false).verify(signed, null);
        VerificationReport.SignatureResult last = check.signatures().get(check.signatures().size() - 1);
        if (!last.integrityValid()) {
            throw new SignerException(ErrorCode.SIGNING_FAILED, "The signature could not be validated: " + last.notes());
        }
        if (!sessions.markCompleted(sessionId)) {
            throw new SignerException(ErrorCode.CONFLICT, "This document has already been signed");
        }
        if (s.txn() != null) {
            txns.complete(s.txn(), Txn.COMPLETED, 1, Certificates.commonName(signerCert),
                    signerCert.getSerialNumber().toString(16).toUpperCase(), Bytes.hex(Bytes.sha256(signed)), null);
        }
        return new Completed(signed, Certificates.describe(signerCert, "signature"), s.timestamp(), s.ltv());
    }

    public VerificationReport verify(byte[] pdf, String password) {
        checkSize(pdf);
        return new PdfVerifier(anchors, props.getVerification().isCheckRevocation() ? revocation : null,
                props.getVerification().isFetchIssuers()).verify(pdf, password);
    }

    private void checkSize(byte[] pdf) {
        long max = props.getSessions().getMaxPdfMb() * 1024L * 1024L;
        if (pdf.length > max) {
            throw new SignerException(ErrorCode.PAYLOAD_TOO_LARGE, "PDF exceeds " + props.getSessions().getMaxPdfMb() + " MB");
        }
    }

    @Scheduled(fixedDelay = 600_000, initialDelay = 60_000)
    public void cleanup() {
        int n = sessions.deleteExpired(Instant.now().minus(Duration.ofHours(1)));
        if (n > 0) {
            log.info("Removed {} expired signing sessions", n);
        }
    }
}
