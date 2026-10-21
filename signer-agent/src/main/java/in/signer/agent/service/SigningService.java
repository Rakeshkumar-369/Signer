package in.signer.agent.service;

import in.signer.agent.security.RequestContext;
import in.signer.agent.token.TokenCertificate;
import in.signer.agent.token.TokenManager;
import in.signer.agent.ui.ConsentDecision;
import in.signer.agent.ui.ConsentRequest;
import in.signer.agent.ui.ConsentService;
import in.signer.core.ErrorCode;
import in.signer.core.SignerException;
import in.signer.core.cert.CertificateFilter;
import in.signer.core.cert.CertificateInfo;
import in.signer.core.cert.ChainBuilder;
import in.signer.core.cert.Certificates;
import in.signer.core.cert.TrustAnchors;
import in.signer.core.crypto.CmsBuilder;
import in.signer.core.crypto.CmsOptions;
import in.signer.core.crypto.CmsTimestamper;
import in.signer.core.crypto.KeyRawSigner;
import in.signer.core.crypto.TimestampClient;
import in.signer.core.pdf.PdfSignOptions;
import in.signer.core.pdf.PdfSigner;
import in.signer.core.pdf.SigningKey;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.Set;
import java.util.concurrent.locks.ReentrantLock;
import java.util.function.Function;
import java.util.stream.Collectors;

/** Orchestrates a signing transaction: certificate choice, user consent and PIN, token access and signing. */
public final class SigningService {

    private static final Logger log = LoggerFactory.getLogger(SigningService.class);
    private static final int PIN_ATTEMPTS = 3;

    public record PdfJob(String name, byte[] pdf, PdfSignOptions options) {
    }

    public record PdfOutcome(String name, byte[] signedPdf) {
    }

    public record HashJob(String id, byte[] digest) {
    }

    public record HashOutcome(String id, byte[] signature) {
    }

    public record Result<T>(CertificateInfo certificate, List<String> chain, List<T> items) {
    }

    private final TokenManager tokens;
    private final ConsentService consent;
    private final PdfSigner pdfSigner;
    private final TimestampClient tsa;
    private final TrustAnchors anchors;
    private final boolean fetchIssuers;
    private final boolean logoutAfterSign;
    private final boolean ltvAllowed;
    private final AuditLog audit;
    private final ReentrantLock lock = new ReentrantLock(true);

    public SigningService(TokenManager tokens, ConsentService consent, PdfSigner pdfSigner, TimestampClient tsa,
                          TrustAnchors anchors, boolean fetchIssuers, boolean logoutAfterSign, boolean ltvAllowed, AuditLog audit) {
        this.tokens = tokens;
        this.consent = consent;
        this.pdfSigner = pdfSigner;
        this.tsa = tsa;
        this.anchors = anchors;
        this.fetchIssuers = fetchIssuers;
        this.logoutAfterSign = logoutAfterSign;
        this.ltvAllowed = ltvAllowed;
        this.audit = audit;
    }

    public List<CertificateInfo> certificates(CertificateFilter filter) {
        return tokens.certificates(filter).stream().map(TokenCertificate::info).toList();
    }

    public TokenManager tokens() {
        return tokens;
    }

    public Result<PdfOutcome> signPdfs(RequestContext ctx, List<PdfJob> jobs, CertificateFilter filter) {
        for (PdfJob j : jobs) {
            if (j.options().ltv && !ltvAllowed) {
                throw SignerException.badRequest("LTV is disabled on this computer (ltv.enabled=false)");
            }
            if (j.options().timestamp && tsa == null) {
                throw new SignerException(ErrorCode.TIMESTAMP_FAILED, "No timestamp authority configured on this computer (tsa.url)");
            }
        }
        String action = jobs.size() == 1 ? "Digitally sign this document?" : "Digitally sign " + jobs.size() + " documents?";
        List<String> names = jobs.stream().map(PdfJob::name).toList();
        return withKey(ctx, filter, action, names, key -> {
            List<PdfOutcome> out = new ArrayList<>();
            for (PdfJob j : jobs) {
                out.add(new PdfOutcome(j.name(), pdfSigner.sign(j.pdf(), j.options(), key)));
            }
            return out;
        });
    }

    /**
     * Signs pre-computed SHA-256 digests.
     *
     * @param format {@code cms} (adbe.pkcs7.detached), {@code pades} (ETSI.CAdES.detached) or {@code raw} (bare signature value)
     */
    public Result<HashOutcome> signHashes(RequestContext ctx, List<HashJob> jobs, CertificateFilter filter, String format,
                                          boolean timestamp, List<String> documentNames) {
        String f = format == null ? "cms" : format.toLowerCase(java.util.Locale.ROOT);
        if (!Set.of("cms", "pades", "raw").contains(f)) {
            throw SignerException.badRequest("format must be cms, pades or raw");
        }
        if (timestamp && (tsa == null || "raw".equals(f))) {
            throw new SignerException(ErrorCode.TIMESTAMP_FAILED,
                    "raw".equals(f) ? "Timestamps are not available for raw signatures" : "No timestamp authority configured on this computer (tsa.url)");
        }
        String action = jobs.size() == 1 ? "Digitally sign this document?" : "Digitally sign " + jobs.size() + " documents?";
        List<String> names = documentNames != null && !documentNames.isEmpty() ? documentNames
                : jobs.stream().map(HashJob::id).toList();
        return withKey(ctx, filter, action, names, key -> {
            List<HashOutcome> out = new ArrayList<>();
            for (HashJob j : jobs) {
                byte[] sig;
                if ("raw".equals(f)) {
                    if (!(key.signer() instanceof KeyRawSigner krs)) {
                        throw new SignerException(ErrorCode.SIGNING_FAILED, "Raw signatures are not supported by this token");
                    }
                    sig = krs.signDigest(j.digest());
                } else {
                    sig = CmsBuilder.build(j.digest(), key.certificate(), key.chain(), key.signer(),
                            new CmsOptions("pades".equals(f), new Date()));
                    if (timestamp) {
                        sig = CmsTimestamper.addSignatureTimestamp(sig, tsa);
                    }
                }
                out.add(new HashOutcome(j.id(), sig));
            }
            return out;
        });
    }

    private <T> Result<T> withKey(RequestContext ctx, CertificateFilter filter, String action, List<String> documents,
                                  Function<SigningKey, List<T>> work) {
        if (!lock.tryLock()) {
            throw new SignerException(ErrorCode.BUSY, "Another signing request is waiting for confirmation on this computer");
        }
        String certName = null;
        try {
            List<TokenCertificate> candidates = tokens.certificates(filter);
            if (candidates.isEmpty()) {
                if (tokens.certificates().isEmpty()) {
                    throw new SignerException(ErrorCode.TOKEN_NOT_PRESENT,
                            "No digital signature certificate found. Insert your DSC USB token and try again");
                }
                throw new SignerException(ErrorCode.CERTIFICATE_NOT_FOUND,
                        "None of the certificates on the token matches the requested signer");
            }
            Set<String> pinFor = candidates.stream().filter(c -> c.provider().requiresPin())
                    .map(TokenCertificate::id).collect(Collectors.toSet());
            ConsentRequest request = new ConsentRequest(ctx.origin(), ctx.organisation(), ctx.reference(), action, documents,
                    candidates.stream().map(TokenCertificate::info).toList(),
                    candidates.size() == 1 ? candidates.get(0).id() : null, pinFor, null);

            SigningKey key = null;
            TokenCertificate chosen = null;
            for (int attempt = 1; key == null; attempt++) {
                ConsentDecision decision = consent.ask(request);
                chosen = candidates.stream().filter(c -> c.id().equals(decision.certificateId())).findFirst()
                        .orElseThrow(() -> new SignerException(ErrorCode.CERTIFICATE_NOT_FOUND, "Selected certificate not available"));
                certName = chosen.info().commonName();
                if (!chosen.info().currentlyValid()) {
                    throw new SignerException(ErrorCode.CERTIFICATE_EXPIRED, "The selected certificate has expired or is not yet valid");
                }
                try {
                    key = chosen.provider().unlock(chosen, decision.pin());
                } catch (SignerException e) {
                    if (e.code() == ErrorCode.PIN_INCORRECT && chosen.provider().requiresPin() && attempt < PIN_ATTEMPTS) {
                        request = request.withError("Incorrect PIN. Please try again (attempt " + (attempt + 1) + " of " + PIN_ATTEMPTS + ").");
                        continue;
                    }
                    throw e;
                }
            }
            try {
                List<X509Certificate> chain = new ChainBuilder(anchors, fetchIssuers).withCertificates(key.chain()).build(key.certificate());
                SigningKey full = new SigningKey(key.certificate(), chain, key.signer());
                List<T> items = work.apply(full);
                audit.record("sign", ctx.origin(), ctx.txn(), certName, documents.size(), "OK", null);
                return new Result<>(chosen.info(), chain.stream().map(Certificates::commonName).toList(), items);
            } finally {
                if (logoutAfterSign) {
                    chosen.provider().release();
                }
            }
        } catch (SignerException e) {
            audit.record("sign", ctx.origin(), ctx.txn(), certName, documents.size(), e.code().name(), e.getMessage());
            log.info("Signing failed for {}: {} {}", ctx.origin(), e.code(), e.getMessage());
            throw e;
        } finally {
            lock.unlock();
        }
    }
}
