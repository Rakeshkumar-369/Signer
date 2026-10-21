package in.signer.agent.service;

import in.signer.core.util.Json;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import tools.jackson.databind.node.ObjectNode;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.time.Instant;
import java.time.YearMonth;
import java.time.ZoneOffset;

/** Append-only JSON-lines audit trail of signing activity (never contains document content or PINs). */
public final class AuditLog {

    private static final Logger log = LoggerFactory.getLogger(AuditLog.class);

    private final Path dir;

    public AuditLog(Path dir) {
        this.dir = dir;
    }

    public synchronized void record(String event, String origin, String txn, String certificate, int documents, String status, String detail) {
        if (dir == null) {
            return;
        }
        ObjectNode n = Json.MAPPER.createObjectNode();
        n.put("at", Instant.now().toString());
        n.put("event", event);
        n.put("origin", origin);
        n.put("txn", txn);
        n.put("certificate", certificate);
        n.put("documents", documents);
        n.put("status", status);
        if (detail != null) {
            n.put("detail", detail);
        }
        try {
            Files.createDirectories(dir);
            Path file = dir.resolve("audit-" + YearMonth.now(ZoneOffset.UTC) + ".log");
            Files.writeString(file, Json.MAPPER.writeValueAsString(n) + System.lineSeparator(), StandardCharsets.UTF_8,
                    StandardOpenOption.CREATE, StandardOpenOption.APPEND);
        } catch (IOException e) {
            log.warn("Could not write audit log: {}", e.getMessage());
        }
    }
}
