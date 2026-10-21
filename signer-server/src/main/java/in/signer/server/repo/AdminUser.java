package in.signer.server.repo;

import java.time.Instant;

public record AdminUser(String id, String username, String passwordHash, String role, boolean mustChangePassword,
                        Instant createdAt, Instant lastLoginAt) {

    public static final String ADMIN = "ADMIN";
    public static final String VIEWER = "VIEWER";
}
