package in.signer.server.repo;

import org.springframework.jdbc.core.RowMapper;
import org.springframework.jdbc.core.simple.JdbcClient;
import org.springframework.stereotype.Repository;

import java.time.Instant;
import java.time.LocalDate;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

@Repository
public class TxnRepository {

    private static final RowMapper<Txn> MAPPER = (rs, i) -> new Txn(
            rs.getString("id"), rs.getString("tenant_id"), rs.getString("origin"), rs.getString("operations"),
            rs.getInt("max_documents"), rs.getString("reference"), rs.getString("status"),
            Db.instant(rs, "issued_at"), Db.instant(rs, "expires_at"), Db.instant(rs, "completed_at"),
            rs.getInt("documents"), rs.getString("signer_name"), rs.getString("signer_serial"),
            rs.getString("document_hash"), rs.getString("client_ip"), rs.getString("error"));

    public record Usage(String tenantId, long issued, long completed, long failed, long documents) {
    }

    public record Daily(LocalDate day, long issued, long completed, long failed) {
    }

    private final JdbcClient jdbc;

    public TxnRepository(JdbcClient jdbc) {
        this.jdbc = jdbc;
    }

    public void insert(Txn t) {
        jdbc.sql("""
                INSERT INTO transactions (id, tenant_id, origin, operations, max_documents, reference, status, issued_at, expires_at, documents, client_ip)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 0, ?)""")
                .params(t.id(), t.tenantId(), t.origin(), t.operations(), t.maxDocuments(), t.reference(), t.status(),
                        Db.ts(t.issuedAt()), Db.ts(t.expiresAt()), t.clientIp())
                .update();
    }

    public Optional<Txn> findById(String id) {
        return jdbc.sql("SELECT * FROM transactions WHERE id = ?").param(id).query(MAPPER).optional();
    }

    public void complete(String id, String status, int documents, String signerName, String signerSerial, String documentHash, String error) {
        jdbc.sql("""
                UPDATE transactions SET status = ?, completed_at = ?, documents = documents + ?, signer_name = COALESCE(?, signer_name),
                       signer_serial = COALESCE(?, signer_serial), document_hash = COALESCE(?, document_hash), error = ?
                WHERE id = ?""")
                .params(status, Db.ts(Instant.now()), documents, signerName, signerSerial, documentHash,
                        error == null ? null : error.substring(0, Math.min(500, error.length())), id)
                .update();
    }

    public long countSince(String tenantId, Instant since) {
        if (tenantId == null) {
            return jdbc.sql("SELECT COUNT(*) FROM transactions WHERE issued_at >= ?").param(Db.ts(since)).query(Long.class).single();
        }
        return jdbc.sql("SELECT COUNT(*) FROM transactions WHERE tenant_id = ? AND issued_at >= ?")
                .params(tenantId, Db.ts(since)).query(Long.class).single();
    }

    public List<Txn> search(String tenantId, String status, Instant from, Instant to, String q, int limit, int offset) {
        StringBuilder sql = new StringBuilder("SELECT * FROM transactions WHERE 1 = 1");
        List<Object> params = new ArrayList<>();
        where(sql, params, tenantId, status, from, to, q);
        sql.append(" ORDER BY issued_at DESC LIMIT ? OFFSET ?");
        params.add(limit);
        params.add(offset);
        return jdbc.sql(sql.toString()).params(params).query(MAPPER).list();
    }

    public long count(String tenantId, String status, Instant from, Instant to, String q) {
        StringBuilder sql = new StringBuilder("SELECT COUNT(*) FROM transactions WHERE 1 = 1");
        List<Object> params = new ArrayList<>();
        where(sql, params, tenantId, status, from, to, q);
        return jdbc.sql(sql.toString()).params(params).query(Long.class).single();
    }

    private static void where(StringBuilder sql, List<Object> params, String tenantId, String status, Instant from, Instant to, String q) {
        if (tenantId != null && !tenantId.isBlank()) {
            sql.append(" AND tenant_id = ?");
            params.add(tenantId);
        }
        if (status != null && !status.isBlank()) {
            sql.append(" AND status = ?");
            params.add(status);
        }
        if (from != null) {
            sql.append(" AND issued_at >= ?");
            params.add(Db.ts(from));
        }
        if (to != null) {
            sql.append(" AND issued_at < ?");
            params.add(Db.ts(to));
        }
        if (q != null && !q.isBlank()) {
            sql.append(" AND (id = ? OR LOWER(reference) LIKE ? OR LOWER(signer_name) LIKE ?)");
            String like = "%" + q.strip().toLowerCase() + "%";
            params.add(q.strip());
            params.add(like);
            params.add(like);
        }
    }

    public List<Usage> usage(Instant from, Instant to) {
        return jdbc.sql("""
                SELECT tenant_id,
                       COUNT(*) AS issued,
                       SUM(CASE WHEN status = 'COMPLETED' THEN 1 ELSE 0 END) AS completed,
                       SUM(CASE WHEN status = 'FAILED' THEN 1 ELSE 0 END) AS failed,
                       SUM(documents) AS docs
                FROM transactions WHERE issued_at >= ? AND issued_at < ?
                GROUP BY tenant_id""")
                .params(Db.ts(from), Db.ts(to))
                .query((rs, i) -> new Usage(rs.getString("tenant_id"), rs.getLong("issued"), rs.getLong("completed"),
                        rs.getLong("failed"), rs.getLong("docs")))
                .list();
    }

    public List<Daily> daily(Instant from) {
        return jdbc.sql("""
                SELECT CAST(issued_at AS DATE) AS tx_day,
                       COUNT(*) AS issued,
                       SUM(CASE WHEN status = 'COMPLETED' THEN 1 ELSE 0 END) AS completed,
                       SUM(CASE WHEN status = 'FAILED' THEN 1 ELSE 0 END) AS failed
                FROM transactions WHERE issued_at >= ?
                GROUP BY CAST(issued_at AS DATE) ORDER BY tx_day""")
                .param(Db.ts(from))
                .query((rs, i) -> new Daily(rs.getDate("tx_day").toLocalDate(), rs.getLong("issued"), rs.getLong("completed"), rs.getLong("failed")))
                .list();
    }
}
