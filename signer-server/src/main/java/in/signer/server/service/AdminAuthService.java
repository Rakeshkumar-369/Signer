package in.signer.server.service;

import in.signer.core.ErrorCode;
import in.signer.core.SignerException;
import in.signer.core.token.Jws;
import in.signer.core.util.Bytes;
import in.signer.core.util.Json;
import in.signer.server.config.SignerProperties;
import in.signer.server.repo.AdminUser;
import in.signer.server.repo.AdminUserRepository;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.node.ObjectNode;

import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/** Administrator accounts, password hashing (bcrypt), login throttling and signed session tokens. */
@Service
public class AdminAuthService {

    public static final String SESSION_TYPE = "signer-admin+jwt";
    private static final int MAX_FAILURES = 5;
    private static final Duration LOCKOUT = Duration.ofMinutes(15);

    public record Principal(String id, String username, String role) {
        public boolean isAdmin() {
            return AdminUser.ADMIN.equals(role);
        }
    }

    public record Session(String token, Instant expiresAt, Principal user, boolean mustChangePassword) {
    }

    private record Failures(int count, Instant lockedUntil) {
    }

    private final AdminUserRepository users;
    private final TokenKeyService keys;
    private final SignerProperties props;
    private final BCryptPasswordEncoder encoder = new BCryptPasswordEncoder(12);
    private final Map<String, Failures> failures = new ConcurrentHashMap<>();

    public AdminAuthService(AdminUserRepository users, TokenKeyService keys, SignerProperties props) {
        this.users = users;
        this.keys = keys;
        this.props = props;
    }

    public Session login(String username, String password) {
        String u = username == null ? "" : username.strip().toLowerCase(Locale.ROOT);
        Failures f = failures.get(u);
        if (f != null && f.lockedUntil() != null && Instant.now().isBefore(f.lockedUntil())) {
            throw new SignerException(ErrorCode.RATE_LIMITED, "Too many failed logins; try again in a few minutes");
        }
        AdminUser user = users.findByUsername(u).orElse(null);
        if (user == null || password == null || !encoder.matches(password, user.passwordHash())) {
            int count = f == null ? 1 : f.count() + 1;
            failures.put(u, new Failures(count, count >= MAX_FAILURES ? Instant.now().plus(LOCKOUT) : null));
            throw new SignerException(ErrorCode.UNAUTHORIZED, "Invalid username or password");
        }
        failures.remove(u);
        users.touchLogin(user.id());
        return issue(user);
    }

    private Session issue(AdminUser user) {
        Instant now = Instant.now();
        Instant exp = now.plus(Duration.ofHours(props.getAdmin().getSessionHours()));
        ObjectNode claims = Json.MAPPER.createObjectNode();
        claims.put("sub", user.id());
        claims.put("usr", user.username());
        claims.put("role", user.role());
        claims.put("pwd", fingerprint(user.passwordHash()));
        claims.put("iat", now.getEpochSecond());
        claims.put("exp", exp.getEpochSecond());
        String token = Jws.sign(claims, SESSION_TYPE, keys.keyId(), keys.privateKey());
        return new Session(token, exp, new Principal(user.id(), user.username(), user.role()), user.mustChangePassword());
    }

    public Principal authenticate(String bearer) {
        if (bearer == null || bearer.isBlank()) {
            throw new SignerException(ErrorCode.UNAUTHORIZED, "Login required");
        }
        JsonNode c;
        try {
            c = Jws.verify(bearer, SESSION_TYPE, keys.publishedKeys());
        } catch (SignerException e) {
            throw new SignerException(ErrorCode.UNAUTHORIZED, "Session is invalid; please log in again");
        }
        if (Instant.now().getEpochSecond() > c.path("exp").asLong(0)) {
            throw new SignerException(ErrorCode.UNAUTHORIZED, "Session expired; please log in again");
        }
        AdminUser user = users.findById(c.path("sub").asString("")).orElseThrow(
                () -> new SignerException(ErrorCode.UNAUTHORIZED, "Account no longer exists"));
        if (!fingerprint(user.passwordHash()).equals(c.path("pwd").asString(""))) {
            throw new SignerException(ErrorCode.UNAUTHORIZED, "Password was changed; please log in again");
        }
        return new Principal(user.id(), user.username(), user.role());
    }

    public Session changePassword(Principal p, String current, String next) {
        AdminUser user = users.findById(p.id()).orElseThrow();
        if (current == null || !encoder.matches(current, user.passwordHash())) {
            throw new SignerException(ErrorCode.UNAUTHORIZED, "Current password is incorrect");
        }
        validatePassword(next);
        users.setPassword(user.id(), encoder.encode(next), false);
        return issue(users.findById(user.id()).orElseThrow());
    }

    public AdminUser create(String username, String password, String role, boolean mustChange) {
        String u = username == null ? "" : username.strip().toLowerCase(Locale.ROOT);
        if (!u.matches("[a-z0-9._-]{3,64}")) {
            throw SignerException.badRequest("Username must be 3-64 characters (letters, digits, . _ -)");
        }
        if (users.findByUsername(u).isPresent()) {
            throw new SignerException(ErrorCode.CONFLICT, "User already exists");
        }
        String r = role == null ? AdminUser.VIEWER : role.toUpperCase(Locale.ROOT);
        if (!AdminUser.ADMIN.equals(r) && !AdminUser.VIEWER.equals(r)) {
            throw SignerException.badRequest("Role must be ADMIN or VIEWER");
        }
        validatePassword(password);
        return users.insert(u, encoder.encode(password), r, mustChange);
    }

    public void resetPassword(String userId, String password) {
        users.findById(userId).orElseThrow(() -> new SignerException(ErrorCode.NOT_FOUND, "User not found"));
        validatePassword(password);
        users.setPassword(userId, encoder.encode(password), true);
    }

    public List<AdminUser> list() {
        return users.findAll();
    }

    public AdminUser delete(Principal actor, String id) {
        AdminUser u = users.findById(id).orElseThrow(() -> new SignerException(ErrorCode.NOT_FOUND, "User not found"));
        if (u.id().equals(actor.id())) {
            throw SignerException.badRequest("You cannot delete your own account");
        }
        if (AdminUser.ADMIN.equals(u.role()) && users.findAll().stream().filter(x -> AdminUser.ADMIN.equals(x.role())).count() <= 1) {
            throw SignerException.badRequest("At least one administrator must remain");
        }
        users.delete(id);
        return u;
    }

    public boolean hasUsers() {
        return users.count() > 0;
    }

    static void validatePassword(String p) {
        if (p == null || p.length() < 10 || !p.matches(".*[A-Za-z].*") || !p.matches(".*[0-9].*")) {
            throw SignerException.badRequest("Password must be at least 10 characters and contain letters and digits");
        }
    }

    private static String fingerprint(String hash) {
        return Bytes.b64url(Bytes.sha256(hash.getBytes(StandardCharsets.UTF_8))).substring(0, 12);
    }
}
