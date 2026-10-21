package in.signer.server.service;

import in.signer.core.ErrorCode;
import in.signer.core.SignerException;
import in.signer.core.token.Jws;
import in.signer.core.token.TokenVerifier;
import in.signer.core.token.TransactionToken;
import in.signer.server.config.SignerProperties;
import in.signer.server.repo.Tenant;
import in.signer.server.repo.TenantRepository;
import in.signer.server.repo.Txn;
import in.signer.server.repo.TxnRepository;
import org.springframework.stereotype.Service;

import java.time.Instant;
import java.time.LocalDate;
import java.time.ZoneOffset;
import java.util.List;
import java.util.Locale;
import java.util.Set;
import java.util.UUID;

/** Issues transaction tokens (the billable unit), records their outcome and enforces quotas. */
@Service
public class TransactionService {

    private static final Set<String> OPERATIONS = Set.of(TransactionToken.OP_CERTIFICATES, TransactionToken.OP_SIGN);

    public record Issued(String token, String txn, Instant expiresAt, List<String> operations, int maxDocuments) {
    }

    private final TxnRepository txns;
    private final TenantRepository tenants;
    private final TokenKeyService keys;
    private final LicenseService license;
    private final SignerProperties props;

    public TransactionService(TxnRepository txns, TenantRepository tenants, TokenKeyService keys, LicenseService license,
                              SignerProperties props) {
        this.txns = txns;
        this.tenants = tenants;
        this.keys = keys;
        this.license = license;
        this.props = props;
    }

    public static Instant monthStart() {
        LocalDate now = LocalDate.now(ZoneOffset.UTC);
        return now.withDayOfMonth(1).atStartOfDay().toInstant(ZoneOffset.UTC);
    }

    public Issued issue(Tenant tenant, String origin, List<String> operations, Integer ttlSeconds, Integer maxDocuments,
                        String reference, String clientIp) {
        String o = TenantService.normalizeOrigin(origin);
        if (o == null || o.isEmpty()) {
            throw SignerException.badRequest("origin is required (the web origin that will call the agent)");
        }
        if (!tenant.allowedOrigins().contains(o)) {
            throw new SignerException(ErrorCode.ORIGIN_NOT_ALLOWED,
                    "Origin " + o + " is not registered for tenant '" + tenant.code() + "'");
        }
        List<String> ops = operations == null || operations.isEmpty()
                ? List.of(TransactionToken.OP_CERTIFICATES, TransactionToken.OP_SIGN)
                : operations.stream().map(s -> s.strip().toLowerCase(Locale.ROOT)).distinct().toList();
        if (!OPERATIONS.containsAll(ops)) {
            throw SignerException.badRequest("operations may contain only 'certificates' and 'sign'");
        }
        int ttl = ttlSeconds == null ? props.getToken().getDefaultTtlSeconds() : ttlSeconds;
        if (ttl < 30 || ttl > props.getToken().getMaxTtlSeconds()) {
            throw SignerException.badRequest("ttlSeconds must be between 30 and " + props.getToken().getMaxTtlSeconds());
        }
        int max = maxDocuments == null ? 1 : maxDocuments;
        if (max < 1 || max > props.getToken().getMaxDocuments()) {
            throw SignerException.badRequest("maxDocuments must be between 1 and " + props.getToken().getMaxDocuments());
        }
        if (reference != null && reference.length() > 255) {
            throw SignerException.badRequest("reference is limited to 255 characters");
        }
        Instant month = monthStart();
        if (tenant.monthlyQuota() > 0 && txns.countSince(tenant.id(), month) >= tenant.monthlyQuota()) {
            throw new SignerException(ErrorCode.QUOTA_EXCEEDED,
                    "Monthly quota of " + tenant.monthlyQuota() + " transactions reached for '" + tenant.code() + "'");
        }
        license.checkTransactionAllowed(txns.countSince(null, month));

        Instant now = Instant.now();
        String txn = UUID.randomUUID().toString();
        TransactionToken t = new TransactionToken(txn, props.getIssuer(), tenant.id(), tenant.name(), o, ops, max,
                reference == null || reference.isBlank() ? null : reference.strip(), now, now.plusSeconds(ttl));
        String jws = Jws.sign(t.toClaims(), TransactionToken.TYPE, keys.keyId(), keys.privateKey());
        txns.insert(new Txn(txn, tenant.id(), o, String.join(",", ops), max, t.reference(), Txn.ISSUED, now, t.expiresAt(),
                null, 0, null, null, null, clientIp, null));
        return new Issued(jws, txn, t.expiresAt(), ops, max);
    }

    /** Verifies a transaction token presented as a bearer credential by the browser. */
    public TransactionToken verifyBearer(String token) {
        TransactionToken t = new TokenVerifier(keys.publishedKeys()).verify(token);
        Tenant tenant = tenants.findById(t.tenantId())
                .orElseThrow(() -> new SignerException(ErrorCode.TOKEN_INVALID, "Unknown tenant"));
        if (!tenant.active(Instant.now())) {
            throw new SignerException(ErrorCode.FORBIDDEN, "Tenant is suspended or its subscription has ended");
        }
        return t;
    }

    public Txn get(String tenantId, String txn) {
        Txn t = txns.findById(txn).orElseThrow(() -> new SignerException(ErrorCode.NOT_FOUND, "Transaction not found"));
        if (tenantId != null && !t.tenantId().equals(tenantId)) {
            throw new SignerException(ErrorCode.NOT_FOUND, "Transaction not found");
        }
        return t;
    }

    public Txn complete(String tenantId, String txn, String status, Integer documents, String signerName, String signerSerial,
                        String documentHash, String error) {
        get(tenantId, txn);
        String s = status == null ? Txn.COMPLETED : status.toUpperCase(Locale.ROOT);
        if (!Txn.COMPLETED.equals(s) && !Txn.FAILED.equals(s)) {
            throw SignerException.badRequest("status must be COMPLETED or FAILED");
        }
        txns.complete(txn, s, documents == null ? (Txn.COMPLETED.equals(s) ? 1 : 0) : Math.max(0, documents),
                signerName, signerSerial, documentHash, error);
        return get(tenantId, txn);
    }
}
