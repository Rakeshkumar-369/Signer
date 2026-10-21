package in.signer.server.repo;

import org.springframework.jdbc.core.RowMapper;
import org.springframework.jdbc.core.simple.JdbcClient;
import org.springframework.stereotype.Repository;

import java.time.Instant;
import java.util.List;

@Repository
public class AuditRepository {

    private static final RowMapper<AuditEntry> MAPPER = (rs, i) -> new AuditEntry(
            rs.getString("id"), Db.instant(rs, "occurred_at"), rs.getString("actor"), rs.getString("action"),
            rs.getString("target"), rs.getString("detail"), rs.getString("ip"));

    private final JdbcClient jdbc;

    public AuditRepository(JdbcClient jdbc) {
        this.jdbc = jdbc;
    }

    public void insert(String actor, String action, String target, String detail, String ip) {
        jdbc.sql("INSERT INTO audit_log (id, occurred_at, actor, action, target, detail, ip) VALUES (?, ?, ?, ?, ?, ?, ?)")
                .params(Db.newId(), Db.ts(Instant.now()), actor, action, target,
                        detail == null ? null : detail.substring(0, Math.min(1000, detail.length())), ip)
                .update();
    }

    public List<AuditEntry> page(int limit, int offset) {
        return jdbc.sql("SELECT * FROM audit_log ORDER BY occurred_at DESC LIMIT ? OFFSET ?").params(limit, offset).query(MAPPER).list();
    }

    public long count() {
        return jdbc.sql("SELECT COUNT(*) FROM audit_log").query(Long.class).single();
    }
}
