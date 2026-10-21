package in.signer.server.repo;

import org.springframework.jdbc.core.RowMapper;
import org.springframework.jdbc.core.simple.JdbcClient;
import org.springframework.stereotype.Repository;

import java.time.Instant;
import java.util.List;
import java.util.Optional;

@Repository
public class AdminUserRepository {

    private static final RowMapper<AdminUser> MAPPER = (rs, i) -> new AdminUser(
            rs.getString("id"), rs.getString("username"), rs.getString("password_hash"), rs.getString("role"),
            rs.getBoolean("must_change_password"), Db.instant(rs, "created_at"), Db.instant(rs, "last_login_at"));

    private final JdbcClient jdbc;

    public AdminUserRepository(JdbcClient jdbc) {
        this.jdbc = jdbc;
    }

    public long count() {
        return jdbc.sql("SELECT COUNT(*) FROM admin_users").query(Long.class).single();
    }

    public List<AdminUser> findAll() {
        return jdbc.sql("SELECT * FROM admin_users ORDER BY username").query(MAPPER).list();
    }

    public Optional<AdminUser> findByUsername(String username) {
        return jdbc.sql("SELECT * FROM admin_users WHERE username = ?").param(username).query(MAPPER).optional();
    }

    public Optional<AdminUser> findById(String id) {
        return jdbc.sql("SELECT * FROM admin_users WHERE id = ?").param(id).query(MAPPER).optional();
    }

    public AdminUser insert(String username, String hash, String role, boolean mustChange) {
        String id = Db.newId();
        jdbc.sql("INSERT INTO admin_users (id, username, password_hash, role, must_change_password, created_at) VALUES (?, ?, ?, ?, ?, ?)")
                .params(id, username, hash, role, mustChange, Db.ts(Instant.now())).update();
        return findById(id).orElseThrow();
    }

    public void setPassword(String id, String hash, boolean mustChange) {
        jdbc.sql("UPDATE admin_users SET password_hash = ?, must_change_password = ? WHERE id = ?").params(hash, mustChange, id).update();
    }

    public void touchLogin(String id) {
        jdbc.sql("UPDATE admin_users SET last_login_at = ? WHERE id = ?").params(Db.ts(Instant.now()), id).update();
    }

    public int delete(String id) {
        return jdbc.sql("DELETE FROM admin_users WHERE id = ?").param(id).update();
    }
}
