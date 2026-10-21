package in.signer.server.web;

import in.signer.core.ErrorCode;
import in.signer.core.SignerException;
import in.signer.core.pdf.PdfSignOptions;
import in.signer.core.pdf.VerificationReport;
import in.signer.core.token.TransactionToken;
import in.signer.core.util.Bytes;
import in.signer.server.repo.Tenant;
import in.signer.server.repo.Txn;
import in.signer.server.service.PdfService;
import in.signer.server.service.TokenKeyService;
import in.signer.server.service.TransactionService;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/** Integration API used by customer applications (see docs/SERVER-API.md). */
@RestController
public class PublicApiController {

    public record TokenRequest(String origin, List<String> operations, Integer ttlSeconds, Integer maxDocuments, String reference) {
    }

    public record CompleteTxnRequest(String status, Integer documents, String signerName, String signerSerial,
                                     String documentHash, String error) {
    }

    public record PrepareRequest(String pdf, String name, PdfSignOptions options, String certificate) {
    }

    public record CompletePdfRequest(String sessionId, String signature) {
    }

    public record VerifyRequest(String pdf, String password) {
    }

    private final AuthResolver auth;
    private final TransactionService transactions;
    private final PdfService pdfs;
    private final TokenKeyService keys;

    public PublicApiController(AuthResolver auth, TransactionService transactions, PdfService pdfs, TokenKeyService keys) {
        this.auth = auth;
        this.transactions = transactions;
        this.pdfs = pdfs;
        this.keys = keys;
    }

    @GetMapping("/.well-known/signer-keys")
    public Map<String, Object> jwks() {
        return Map.of("keys", keys.jwks());
    }

    @GetMapping("/api/v1/health")
    public Map<String, Object> health() {
        return Map.of("ok", true, "time", Instant.now().toString(), "timestampAuthority", pdfs.hasTsa());
    }

    /** Issues a single-use transaction token (equivalent of the "generatekey" call). Server-to-server only. */
    @PostMapping("/api/v1/tokens")
    public Map<String, Object> token(HttpServletRequest req, @RequestBody TokenRequest body) {
        Tenant tenant = auth.apiKey(req);
        TransactionService.Issued i = transactions.issue(tenant, body.origin(), body.operations(), body.ttlSeconds(),
                body.maxDocuments(), body.reference(), AuthResolver.clientIp(req));
        Map<String, Object> out = new LinkedHashMap<>();
        out.put("ok", true);
        out.put("token", i.token());
        out.put("txn", i.txn());
        out.put("expiresAt", i.expiresAt().toString());
        out.put("operations", i.operations());
        out.put("maxDocuments", i.maxDocuments());
        return out;
    }

    @GetMapping("/api/v1/transactions/{txn}")
    public Map<String, Object> transaction(HttpServletRequest req, @PathVariable String txn) {
        AuthResolver.TenantAuth a = auth.tenantOrToken(req, null);
        if (a.token() != null && !a.txn().equals(txn)) {
            throw new SignerException(ErrorCode.FORBIDDEN, "Token belongs to another transaction");
        }
        return Map.of("ok", true, "transaction", transactions.get(a.tenant().id(), txn));
    }

    @PostMapping("/api/v1/transactions/{txn}/complete")
    public Map<String, Object> completeTxn(HttpServletRequest req, @PathVariable String txn, @RequestBody CompleteTxnRequest body) {
        AuthResolver.TenantAuth a = auth.tenantOrToken(req, null);
        if (a.token() != null && !a.txn().equals(txn)) {
            throw new SignerException(ErrorCode.FORBIDDEN, "Token belongs to another transaction");
        }
        Txn t = transactions.complete(a.tenant().id(), txn, body.status(), body.documents(), body.signerName(),
                body.signerSerial(), body.documentHash(), body.error());
        return Map.of("ok", true, "transaction", t);
    }

    @PostMapping("/api/v1/pdf/prepare")
    public Map<String, Object> prepare(HttpServletRequest req, @RequestBody PrepareRequest body) {
        AuthResolver.TenantAuth a = auth.tenantOrToken(req, TransactionToken.OP_SIGN);
        PdfService.Prepared p = pdfs.prepare(a.tenant(), a.txn(), Bytes.fromB64(body.pdf(), "pdf"), body.name(), body.options(),
                body.certificate());
        Map<String, Object> out = new LinkedHashMap<>();
        out.put("ok", true);
        out.put("sessionId", p.sessionId());
        out.put("digest", p.digest());
        out.put("digestAlgorithm", p.digestAlgorithm());
        out.put("format", p.format());
        out.put("expiresAt", p.expiresAt().toString());
        return out;
    }

    @PostMapping("/api/v1/pdf/complete")
    public Map<String, Object> complete(HttpServletRequest req, @RequestBody CompletePdfRequest body) {
        AuthResolver.TenantAuth a = auth.tenantOrToken(req, TransactionToken.OP_SIGN);
        if (body.sessionId() == null) {
            throw SignerException.badRequest("sessionId is required");
        }
        PdfService.Completed c = pdfs.complete(a.tenant(), body.sessionId(), Bytes.fromB64(body.signature(), "signature"));
        Map<String, Object> out = new LinkedHashMap<>();
        out.put("ok", true);
        out.put("pdf", Bytes.b64(c.pdf()));
        out.put("size", c.pdf().length);
        out.put("sha256", Bytes.hex(Bytes.sha256(c.pdf())));
        out.put("signer", c.signer());
        out.put("timestamped", c.timestamped());
        out.put("ltv", c.ltv());
        return out;
    }

    @PostMapping("/api/v1/pdf/verify")
    public Map<String, Object> verify(HttpServletRequest req, @RequestBody VerifyRequest body) {
        auth.tenantOrToken(req, null);
        VerificationReport r = pdfs.verify(Bytes.fromB64(body.pdf(), "pdf"), body.password());
        return Map.of("ok", true, "report", r);
    }
}
