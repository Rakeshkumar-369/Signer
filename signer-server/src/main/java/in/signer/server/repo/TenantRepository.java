package in.signer.server.repo;

import org.springframework.jdbc.core.RowMapper;
import org.springframework.jdbc.core.simple.JdbcClient;
import org.springframework.stereotype.Repository;

import java.time.Instant;
import java.util.Arrays;
import java.util.List;
import java.util.Optional;

@Repository
public class TenantRepository {

    private static final RowMapper<Tenant> MAPPER = (rs, i) -> new Tenant(
            rs.getString("id"), rs.getString("code"), rs.getString("name"), rs.getString("contact_email"),
            rs.getString("status"), rs.getString("plan"), rs.getLong("monthly_quota"), Db.instant(rs, "valid_until"),
            Arrays.stream(rs.getString("allowed_origins").split(",")).map(String::strip).filter(s -> !s.isEmpty()).toList(),
            Db.instant(rs, "created_at"), Db.instant(rs, "updated_at"));

    private final JdbcClient jdbc;

    public TenantRepository(JdbcClient jdbc) {
        this.jdbc = jdbc;
    }

    public List<Tenant> findAll() {
        return jdbc.sql("SELECT * FROM tenants ORDER BY name").query(MAPPER).list();
    }

    public Optional<Tenant> findById(String id) {
        return jdbc.sql("SELECT * FROM tenants WHERE id = ?").param(id).query(MAPPER).optional();
    }

    public Optional<Tenant> findByCode(String code) {
        return jdbc.sql("SELECT * FROM tenants WHERE code = ?").param(code).query(MAPPER).optional();
    }

    public long count() {
        return jdbc.sql("SELECT COUNT(*) FROM tenants").query(Long.class).single();
    }

    public Tenant insert(String code, String name, String email, String plan, long quota, Instant validUntil, List<String> origins) {
        String id = Db.newId();
        Instant now = Instant.now();
        jdbc.sql("""
                INSERT INTO tenants (id, code, name, contact_email, status, plan, monthly_quota, valid_until, allowed_origins, created_at, updated_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""")
                .params(id, code, name, email, Tenant.ACTIVE, plan, quota, Db.ts(validUntil), String.join(",", origins), Db.ts(now), Db.ts(now))
                .update();
        return findById(id).orElseThrow();
    }

    public void update(String id, String name, String email, String plan, long quota, Instant validUntil, List<String> origins) {
        jdbc.sql("""
                UPDATE tenants SET name = ?, contact_email = ?, plan = ?, monthly_quota = ?, valid_until = ?, allowed_origins = ?, updated_at = ?
                WHERE id = ?""")
                .params(name, email, plan, quota, Db.ts(validUntil), String.join(",", origins), Db.ts(Instant.now()), id)
                .update();
    }

    public void setStatus(String id, String status) {
        jdbc.sql("UPDATE tenants SET status = ?, updated_at = ? WHERE id = ?").params(status, Db.ts(Instant.now()), id).update();
    }
}
