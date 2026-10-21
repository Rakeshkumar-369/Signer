package in.signer.server.repo;

import org.springframework.jdbc.core.RowMapper;
import org.springframework.jdbc.core.simple.JdbcClient;
import org.springframework.stereotype.Repository;

import java.time.Instant;
import java.util.Optional;

@Repository
public class SessionRepository {

    private static final RowMapper<SigningSession> MAPPER = (rs, i) -> new SigningSession(
            rs.getString("id"), rs.getString("tenant_id"), rs.getString("txn"), rs.getString("status"),
            rs.getString("document_name"), rs.getString("digest"), rs.getString("certificate"),
            rs.getBoolean("timestamp_req"), rs.getBoolean("ltv_req"), Db.instant(rs, "created_at"), Db.instant(rs, "expires_at"));

    private final JdbcClient jdbc;

    public SessionRepository(JdbcClient jdbc) {
        this.jdbc = jdbc;
    }

    public void insert(SigningSession s, byte[] pdf) {
        jdbc.sql("""
                INSERT INTO signing_sessions (id, tenant_id, txn, status, document_name, digest, certificate, timestamp_req, ltv_req,
                                              prepared_pdf, created_at, expires_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""")
                .params(s.id(), s.tenantId(), s.txn(), s.status(), s.documentName(), s.digestHex(), s.certificate(),
                        s.timestamp(), s.ltv(), pdf, Db.ts(s.createdAt()), Db.ts(s.expiresAt()))
                .update();
    }

    public Optional<SigningSession> findById(String id) {
        return jdbc.sql("SELECT id, tenant_id, txn, status, document_name, digest, certificate, timestamp_req, ltv_req, created_at, expires_at "
                + "FROM signing_sessions WHERE id = ?").param(id).query(MAPPER).optional();
    }

    public byte[] pdf(String id) {
        return jdbc.sql("SELECT prepared_pdf FROM signing_sessions WHERE id = ?").param(id)
                .query((rs, i) -> rs.getBytes(1)).optional().orElse(null);
    }

    /** Marks the session completed and drops the stored document (it is returned to the caller). */
    public boolean markCompleted(String id) {
        return jdbc.sql("UPDATE signing_sessions SET status = 'COMPLETED', prepared_pdf = NULL WHERE id = ? AND status = 'PREPARED'")
                .param(id).update() == 1;
    }

    public int deleteExpired(Instant now) {
        return jdbc.sql("DELETE FROM signing_sessions WHERE expires_at < ?").param(Db.ts(now)).update();
    }
}
