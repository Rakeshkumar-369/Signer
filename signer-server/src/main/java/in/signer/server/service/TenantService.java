package in.signer.server.service;

import in.signer.core.ErrorCode;
import in.signer.core.SignerException;
import in.signer.server.repo.Tenant;
import in.signer.server.repo.TenantRepository;
import org.springframework.stereotype.Service;

import java.time.Instant;
import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Set;
import java.util.regex.Pattern;

@Service
public class TenantService {

    private static final Pattern CODE = Pattern.compile("[a-z0-9][a-z0-9-]{1,62}");
    private static final Pattern ORIGIN = Pattern.compile("(https?://[a-z0-9.-]+(:\\d{1,5})?|native)");

    public record TenantInput(String code, String name, String contactEmail, String plan, Long monthlyQuota,
                              Instant validUntil, List<String> allowedOrigins) {
    }

    private final TenantRepository repo;
    private final LicenseService license;
    private volatile Set<String> originCache;
    private volatile long originCacheAt;

    public TenantService(TenantRepository repo, LicenseService license) {
        this.repo = repo;
        this.license = license;
    }

    public List<Tenant> all() {
        return repo.findAll();
    }

    public Tenant get(String id) {
        return repo.findById(id).orElseThrow(() -> new SignerException(ErrorCode.NOT_FOUND, "Tenant not found"));
    }

    public java.util.Optional<Tenant> byCode(String code) {
        return repo.findByCode(code);
    }

    public Tenant create(TenantInput in) {
        String code = in.code() == null ? "" : in.code().strip().toLowerCase(Locale.ROOT);
        if (!CODE.matcher(code).matches()) {
            throw SignerException.badRequest("Code must be 2-63 characters: lower-case letters, digits and '-'");
        }
        if (repo.findByCode(code).isPresent()) {
            throw new SignerException(ErrorCode.CONFLICT, "A tenant with code '" + code + "' already exists");
        }
        license.checkTenantLimit(repo.count());
        Tenant t = repo.insert(code, requireName(in.name()), blankToNull(in.contactEmail()), plan(in.plan()), quota(in.monthlyQuota()),
                in.validUntil(), origins(in.allowedOrigins()));
        invalidate();
        return t;
    }

    public Tenant update(String id, TenantInput in) {
        get(id);
        repo.update(id, requireName(in.name()), blankToNull(in.contactEmail()), plan(in.plan()), quota(in.monthlyQuota()),
                in.validUntil(), origins(in.allowedOrigins()));
        invalidate();
        return get(id);
    }

    public Tenant setStatus(String id, String status) {
        String s = status == null ? "" : status.toUpperCase(Locale.ROOT);
        if (!Tenant.ACTIVE.equals(s) && !Tenant.SUSPENDED.equals(s)) {
            throw SignerException.badRequest("Status must be ACTIVE or SUSPENDED");
        }
        get(id);
        repo.setStatus(id, s);
        invalidate();
        return get(id);
    }

    /** Union of all active tenants' origins, used for CORS on browser-callable endpoints. */
    public Set<String> activeOrigins() {
        if (originCache == null || System.currentTimeMillis() - originCacheAt > 30_000) {
            Set<String> s = new LinkedHashSet<>();
            Instant now = Instant.now();
            repo.findAll().stream().filter(t -> t.active(now)).forEach(t -> s.addAll(t.allowedOrigins()));
            originCache = s;
            originCacheAt = System.currentTimeMillis();
        }
        return originCache;
    }

    public void invalidate() {
        originCache = null;
    }

    public static String normalizeOrigin(String o) {
        return o == null ? null : o.strip().toLowerCase(Locale.ROOT).replaceAll("/+$", "");
    }

    static List<String> origins(List<String> in) {
        if (in == null || in.isEmpty()) {
            throw SignerException.badRequest("At least one allowed origin (e.g. https://eoffice.example.gov.in) is required");
        }
        List<String> out = new ArrayList<>();
        for (String o : in) {
            String n = normalizeOrigin(o);
            if (n == null || n.isEmpty()) {
                continue;
            }
            if (!ORIGIN.matcher(n).matches()) {
                throw SignerException.badRequest("Invalid origin '" + o + "': use scheme://host[:port] without a path");
            }
            if (!out.contains(n)) {
                out.add(n);
            }
        }
        if (out.isEmpty()) {
            throw SignerException.badRequest("At least one allowed origin is required");
        }
        return out;
    }

    private static String requireName(String name) {
        if (name == null || name.isBlank()) {
            throw SignerException.badRequest("Name is required");
        }
        return name.strip();
    }

    private static String plan(String plan) {
        return plan == null || plan.isBlank() ? "standard" : plan.strip();
    }

    private static long quota(Long q) {
        if (q != null && q < 0) {
            throw SignerException.badRequest("monthlyQuota cannot be negative");
        }
        return q == null ? 0 : q;
    }

    private static String blankToNull(String s) {
        return s == null || s.isBlank() ? null : s.strip();
    }
}
