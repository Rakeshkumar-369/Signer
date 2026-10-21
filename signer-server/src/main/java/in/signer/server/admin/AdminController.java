package in.signer.server.admin;

import in.signer.core.ErrorCode;
import in.signer.core.SignerException;
import in.signer.server.config.SignerProperties;
import in.signer.server.repo.AdminUser;
import in.signer.server.repo.ApiKey;
import in.signer.server.repo.AuditRepository;
import in.signer.server.repo.Tenant;
import in.signer.server.repo.TenantRepository;
import in.signer.server.repo.Txn;
import in.signer.server.repo.TxnRepository;
import in.signer.server.service.AdminAuthService;
import in.signer.server.service.ApiKeyService;
import in.signer.server.service.AuditService;
import in.signer.server.service.LicenseService;
import in.signer.server.service.PdfService;
import in.signer.server.service.TenantService;
import in.signer.server.service.TokenKeyService;
import in.signer.server.service.TransactionService;
import in.signer.server.web.AuthResolver;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.time.LocalDate;
import java.time.YearMonth;
import java.time.ZoneOffset;
import java.time.format.DateTimeParseException;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.function.Function;
import java.util.stream.Collectors;

/** REST API behind the admin console (/admin/). */
@RestController
@RequestMapping("/api/admin")
public class AdminController {

    public record LoginRequest(String username, String password) {
    }

    public record PasswordRequest(String currentPassword, String newPassword) {
    }

    public record StatusRequest(String status) {
    }

    public record KeyRequest(String label) {
    }

    public record UserRequest(String username, String password, String role) {
    }

    public record LicenseRequest(String license) {
    }

    private final AuthResolver auth;
    private final AdminAuthService admins;
    private final TenantService tenants;
    private final TenantRepository tenantRepo;
    private final ApiKeyService apiKeys;
    private final TxnRepository txns;
    private final AuditRepository auditRepo;
    private final AuditService audit;
    private final LicenseService license;
    private final TokenKeyService keys;
    private final PdfService pdfs;
    private final SignerProperties props;

    public AdminController(AuthResolver auth, AdminAuthService admins, TenantService tenants, TenantRepository tenantRepo,
                           ApiKeyService apiKeys, TxnRepository txns, AuditRepository auditRepo, AuditService audit,
                           LicenseService license, TokenKeyService keys, PdfService pdfs, SignerProperties props) {
        this.auth = auth;
        this.admins = admins;
        this.tenants = tenants;
        this.tenantRepo = tenantRepo;
        this.apiKeys = apiKeys;
        this.txns = txns;
        this.auditRepo = auditRepo;
        this.audit = audit;
        this.license = license;
        this.keys = keys;
        this.pdfs = pdfs;
        this.props = props;
    }

    // ------------------------------------------------------------- session

    @PostMapping("/login")
    public Map<String, Object> login(HttpServletRequest req, @RequestBody LoginRequest body) {
        try {
            AdminAuthService.Session s = admins.login(body.username(), body.password());
            audit.record(s.user().username(), "LOGIN", null, null, AuthResolver.clientIp(req));
            return session(s);
        } catch (SignerException e) {
            audit.record(String.valueOf(body.username()), "LOGIN_FAILED", null, e.code().name(), AuthResolver.clientIp(req));
            throw e;
        }
    }

    @GetMapping("/me")
    public Map<String, Object> me(HttpServletRequest req) {
        return Map.of("ok", true, "user", auth.admin(req));
    }

    @PostMapping("/password")
    public Map<String, Object> password(HttpServletRequest req, @RequestBody PasswordRequest body) {
        AdminAuthService.Principal p = auth.admin(req);
        AdminAuthService.Session s = admins.changePassword(p, body.currentPassword(), body.newPassword());
        audit.record(p.username(), "PASSWORD_CHANGED", p.username(), null, AuthResolver.clientIp(req));
        return session(s);
    }

    private static Map<String, Object> session(AdminAuthService.Session s) {
        Map<String, Object> out = new LinkedHashMap<>();
        out.put("ok", true);
        out.put("token", s.token());
        out.put("expiresAt", s.expiresAt().toString());
        out.put("user", s.user());
        out.put("mustChangePassword", s.mustChangePassword());
        return out;
    }

    // ------------------------------------------------------------ overview

    @GetMapping("/overview")
    public Map<String, Object> overview(HttpServletRequest req) {
        auth.admin(req);
        Instant month = TransactionService.monthStart();
        Instant today = LocalDate.now(ZoneOffset.UTC).atStartOfDay().toInstant(ZoneOffset.UTC);
        Map<String, Object> out = new LinkedHashMap<>();
        out.put("ok", true);
        out.put("tenants", tenantRepo.count());
        out.put("transactionsThisMonth", txns.countSince(null, month));
        out.put("transactionsToday", txns.countSince(null, today));
        out.put("completedThisMonth", txns.count(null, Txn.COMPLETED, month, null, null));
        out.put("failedThisMonth", txns.count(null, Txn.FAILED, month, null, null));
        out.put("daily", txns.daily(today.minusSeconds(29L * 86400)));
        out.put("license", license.status());
        out.put("tokenKeyId", keys.keyId());
        out.put("timestampAuthority", pdfs.hasTsa());
        out.put("publicUrl", props.getPublicUrl());
        out.put("agentConfig", agentConfig());
        return out;
    }

    private String agentConfig() {
        return "# Signer Agent settings (agent.properties)\n"
                + "security.mode=token\n"
                + "security.serverUrl=" + props.getPublicUrl() + "\n"
                + "# Offline alternative to serverUrl:\n"
                + "# " + keys.agentTrustedKeysLine() + "\n";
    }

    // ------------------------------------------------------------- tenants

    @GetMapping("/tenants")
    public Map<String, Object> tenants(HttpServletRequest req) {
        auth.admin(req);
        Instant month = TransactionService.monthStart();
        List<Map<String, Object>> list = new ArrayList<>();
        for (Tenant t : tenants.all()) {
            Map<String, Object> m = new LinkedHashMap<>();
            m.put("tenant", t);
            m.put("usedThisMonth", txns.countSince(t.id(), month));
            list.add(m);
        }
        return Map.of("ok", true, "tenants", list);
    }

    @PostMapping("/tenants")
    public Map<String, Object> createTenant(HttpServletRequest req, @RequestBody TenantService.TenantInput body) {
        AdminAuthService.Principal p = auth.adminWrite(req);
        Tenant t = tenants.create(body);
        audit.record(p.username(), "TENANT_CREATED", t.code(), t.name(), AuthResolver.clientIp(req));
        return Map.of("ok", true, "tenant", t);
    }

    @GetMapping("/tenants/{id}")
    public Map<String, Object> tenant(HttpServletRequest req, @PathVariable String id) {
        auth.admin(req);
        return Map.of("ok", true, "tenant", tenants.get(id), "apiKeys", apiKeys.list(id),
                "usedThisMonth", txns.countSince(id, TransactionService.monthStart()));
    }

    @PutMapping("/tenants/{id}")
    public Map<String, Object> updateTenant(HttpServletRequest req, @PathVariable String id, @RequestBody TenantService.TenantInput body) {
        AdminAuthService.Principal p = auth.adminWrite(req);
        Tenant t = tenants.update(id, body);
        audit.record(p.username(), "TENANT_UPDATED", t.code(), null, AuthResolver.clientIp(req));
        return Map.of("ok", true, "tenant", t);
    }

    @PostMapping("/tenants/{id}/status")
    public Map<String, Object> tenantStatus(HttpServletRequest req, @PathVariable String id, @RequestBody StatusRequest body) {
        AdminAuthService.Principal p = auth.adminWrite(req);
        Tenant t = tenants.setStatus(id, body.status());
        audit.record(p.username(), "TENANT_" + t.status(), t.code(), null, AuthResolver.clientIp(req));
        return Map.of("ok", true, "tenant", t);
    }

    @PostMapping("/tenants/{id}/keys")
    public Map<String, Object> createKey(HttpServletRequest req, @PathVariable String id, @RequestBody(required = false) KeyRequest body) {
        AdminAuthService.Principal p = auth.adminWrite(req);
        ApiKeyService.Created c = apiKeys.create(id, body == null ? null : body.label());
        audit.record(p.username(), "API_KEY_CREATED", tenants.get(id).code(), c.key().prefix() + "...", AuthResolver.clientIp(req));
        return Map.of("ok", true, "apiKey", c.key(), "secret", c.secret());
    }

    @DeleteMapping("/keys/{keyId}")
    public Map<String, Object> revokeKey(HttpServletRequest req, @PathVariable String keyId) {
        AdminAuthService.Principal p = auth.adminWrite(req);
        ApiKey k = apiKeys.revoke(keyId);
        audit.record(p.username(), "API_KEY_REVOKED", k.tenantId(), k.prefix() + "...", AuthResolver.clientIp(req));
        return Map.of("ok", true);
    }

    // -------------------------------------------------------- transactions

    @GetMapping("/transactions")
    public Map<String, Object> transactions(HttpServletRequest req,
                                            @RequestParam(required = false) String tenantId,
                                            @RequestParam(required = false) String status,
                                            @RequestParam(required = false) String from,
                                            @RequestParam(required = false) String to,
                                            @RequestParam(required = false) String q,
                                            @RequestParam(defaultValue = "1") int page,
                                            @RequestParam(defaultValue = "25") int size) {
        auth.admin(req);
        int s = Math.max(1, Math.min(200, size));
        int pg = Math.max(1, page);
        Instant f = day(from), t = day(to);
        if (t != null) {
            t = t.plusSeconds(86400);
        }
        Map<String, String> names = tenants.all().stream().collect(Collectors.toMap(Tenant::id, Tenant::code));
        List<Map<String, Object>> rows = new ArrayList<>();
        for (Txn x : txns.search(tenantId, status, f, t, q, s, (pg - 1) * s)) {
            Map<String, Object> m = new LinkedHashMap<>();
            m.put("transaction", x);
            m.put("tenantCode", names.get(x.tenantId()));
            rows.add(m);
        }
        return Map.of("ok", true, "items", rows, "total", txns.count(tenantId, status, f, t, q), "page", pg, "size", s);
    }

    // --------------------------------------------------------------- usage

    @GetMapping("/usage")
    public Map<String, Object> usage(HttpServletRequest req, @RequestParam(required = false) String month) {
        auth.admin(req);
        return Map.of("ok", true, "month", ym(month).toString(), "rows", usageRows(ym(month)));
    }

    @GetMapping("/usage.csv")
    public ResponseEntity<byte[]> usageCsv(HttpServletRequest req, @RequestParam(required = false) String month) {
        auth.admin(req);
        YearMonth m = ym(month);
        StringBuilder sb = new StringBuilder("month,tenant_code,tenant_name,plan,monthly_quota,transactions_issued,completed,failed,documents_signed\n");
        for (Map<String, Object> r : usageRows(m)) {
            sb.append(m).append(',').append(csv(r.get("code"))).append(',').append(csv(r.get("name"))).append(',')
                    .append(csv(r.get("plan"))).append(',').append(r.get("monthlyQuota")).append(',').append(r.get("issued")).append(',')
                    .append(r.get("completed")).append(',').append(r.get("failed")).append(',').append(r.get("documents")).append('\n');
        }
        return ResponseEntity.ok()
                .header(HttpHeaders.CONTENT_DISPOSITION, "attachment; filename=\"signer-usage-" + m + ".csv\"")
                .contentType(new MediaType("text", "csv", StandardCharsets.UTF_8))
                .body(sb.toString().getBytes(StandardCharsets.UTF_8));
    }

    private List<Map<String, Object>> usageRows(YearMonth m) {
        Instant from = m.atDay(1).atStartOfDay().toInstant(ZoneOffset.UTC);
        Instant to = m.plusMonths(1).atDay(1).atStartOfDay().toInstant(ZoneOffset.UTC);
        Map<String, TxnRepository.Usage> byTenant = txns.usage(from, to).stream()
                .collect(Collectors.toMap(TxnRepository.Usage::tenantId, Function.identity()));
        List<Map<String, Object>> rows = new ArrayList<>();
        for (Tenant t : tenants.all()) {
            TxnRepository.Usage u = byTenant.getOrDefault(t.id(), new TxnRepository.Usage(t.id(), 0, 0, 0, 0));
            Map<String, Object> r = new LinkedHashMap<>();
            r.put("tenantId", t.id());
            r.put("code", t.code());
            r.put("name", t.name());
            r.put("plan", t.plan());
            r.put("monthlyQuota", t.monthlyQuota());
            r.put("issued", u.issued());
            r.put("completed", u.completed());
            r.put("failed", u.failed());
            r.put("documents", u.documents());
            rows.add(r);
        }
        return rows;
    }

    // --------------------------------------------------------------- audit

    @GetMapping("/audit")
    public Map<String, Object> audit(HttpServletRequest req, @RequestParam(defaultValue = "1") int page,
                                     @RequestParam(defaultValue = "50") int size) {
        auth.admin(req);
        int s = Math.max(1, Math.min(200, size));
        int pg = Math.max(1, page);
        return Map.of("ok", true, "items", auditRepo.page(s, (pg - 1) * s), "total", auditRepo.count(), "page", pg, "size", s);
    }

    // --------------------------------------------------------------- users

    @GetMapping("/users")
    public Map<String, Object> users(HttpServletRequest req) {
        auth.adminWrite(req);
        return Map.of("ok", true, "users", admins.list().stream().map(AdminController::userView).toList());
    }

    @PostMapping("/users")
    public Map<String, Object> createUser(HttpServletRequest req, @RequestBody UserRequest body) {
        AdminAuthService.Principal p = auth.adminWrite(req);
        AdminUser u = admins.create(body.username(), body.password(), body.role(), true);
        audit.record(p.username(), "USER_CREATED", u.username(), u.role(), AuthResolver.clientIp(req));
        return Map.of("ok", true, "user", userView(u));
    }

    @PostMapping("/users/{id}/password")
    public Map<String, Object> resetPassword(HttpServletRequest req, @PathVariable String id, @RequestBody UserRequest body) {
        AdminAuthService.Principal p = auth.adminWrite(req);
        admins.resetPassword(id, body.password());
        audit.record(p.username(), "USER_PASSWORD_RESET", id, null, AuthResolver.clientIp(req));
        return Map.of("ok", true);
    }

    @DeleteMapping("/users/{id}")
    public Map<String, Object> deleteUser(HttpServletRequest req, @PathVariable String id) {
        AdminAuthService.Principal p = auth.adminWrite(req);
        AdminUser u = admins.delete(p, id);
        audit.record(p.username(), "USER_DELETED", u.username(), null, AuthResolver.clientIp(req));
        return Map.of("ok", true);
    }

    private static Map<String, Object> userView(AdminUser u) {
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("id", u.id());
        m.put("username", u.username());
        m.put("role", u.role());
        m.put("mustChangePassword", u.mustChangePassword());
        m.put("createdAt", u.createdAt());
        m.put("lastLoginAt", u.lastLoginAt());
        return m;
    }

    // ------------------------------------------------------------- licence

    @GetMapping("/license")
    public Map<String, Object> license(HttpServletRequest req) {
        auth.admin(req);
        return Map.of("ok", true, "status", license.status());
    }

    @PostMapping("/license")
    public Map<String, Object> installLicense(HttpServletRequest req, @RequestBody LicenseRequest body) {
        AdminAuthService.Principal p = auth.adminWrite(req);
        if (body.license() == null || body.license().isBlank()) {
            throw SignerException.badRequest("license text is required");
        }
        LicenseService.Status s = license.install(body.license());
        audit.record(p.username(), "LICENSE_INSTALLED", s.license().licenseId(), s.license().licensee(), AuthResolver.clientIp(req));
        return Map.of("ok", true, "status", s);
    }

    // ------------------------------------------------------------- helpers

    private static Instant day(String s) {
        if (s == null || s.isBlank()) {
            return null;
        }
        try {
            return LocalDate.parse(s).atStartOfDay().toInstant(ZoneOffset.UTC);
        } catch (DateTimeParseException e) {
            throw new SignerException(ErrorCode.BAD_REQUEST, "Dates must be YYYY-MM-DD");
        }
    }

    private static YearMonth ym(String s) {
        if (s == null || s.isBlank()) {
            return YearMonth.now(ZoneOffset.UTC);
        }
        try {
            return YearMonth.parse(s);
        } catch (DateTimeParseException e) {
            throw new SignerException(ErrorCode.BAD_REQUEST, "month must be YYYY-MM");
        }
    }

    private static String csv(Object o) {
        String s = o == null ? "" : o.toString();
        if (s.startsWith("=") || s.startsWith("+") || s.startsWith("-") || s.startsWith("@")) {
            s = "'" + s;
        }
        return s.contains(",") || s.contains("\"") || s.contains("\n") ? "\"" + s.replace("\"", "\"\"") + "\"" : s;
    }
}
