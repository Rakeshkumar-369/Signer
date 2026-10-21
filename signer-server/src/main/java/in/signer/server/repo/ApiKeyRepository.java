package in.signer.server.repo;

import org.springframework.jdbc.core.RowMapper;
import org.springframework.jdbc.core.simple.JdbcClient;
import org.springframework.stereotype.Repository;

import java.time.Instant;
import java.util.List;
import java.util.Optional;

@Repository
public class ApiKeyRepository {

    private static final RowMapper<ApiKey> MAPPER = (rs, i) -> new ApiKey(
            rs.getString("id"), rs.getString("tenant_id"), rs.getString("label"), rs.getString("prefix"),
            Db.instant(rs, "created_at"), Db.instant(rs, "last_used_at"), Db.instant(rs, "revoked_at"));

    private final JdbcClient jdbc;

    public ApiKeyRepository(JdbcClient jdbc) {
        this.jdbc = jdbc;
    }

    public ApiKey insert(String tenantId, String label, String prefix, String hash) {
        String id = Db.newId();
        jdbc.sql("INSERT INTO api_keys (id, tenant_id, label, prefix, key_hash, created_at) VALUES (?, ?, ?, ?, ?, ?)")
                .params(id, tenantId, label, prefix, hash, Db.ts(Instant.now())).update();
        return findById(id).orElseThrow();
    }

    public Optional<ApiKey> findById(String id) {
        return jdbc.sql("SELECT * FROM api_keys WHERE id = ?").param(id).query(MAPPER).optional();
    }

    public Optional<ApiKey> findActiveByHash(String hash) {
        return jdbc.sql("SELECT * FROM api_keys WHERE key_hash = ? AND revoked_at IS NULL").param(hash).query(MAPPER).optional();
    }

    public List<ApiKey> findByTenant(String tenantId) {
        return jdbc.sql("SELECT * FROM api_keys WHERE tenant_id = ? ORDER BY created_at DESC").param(tenantId).query(MAPPER).list();
    }

    public void touch(String id) {
        jdbc.sql("UPDATE api_keys SET last_used_at = ? WHERE id = ?").params(Db.ts(Instant.now()), id).update();
    }

    public int revoke(String id) {
        return jdbc.sql("UPDATE api_keys SET revoked_at = ? WHERE id = ? AND revoked_at IS NULL").params(Db.ts(Instant.now()), id).update();
    }
}
