package in.signer.server.service;

import in.signer.server.repo.AuditRepository;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

@Service
public class AuditService {

    private static final Logger log = LoggerFactory.getLogger(AuditService.class);

    private final AuditRepository repo;

    public AuditService(AuditRepository repo) {
        this.repo = repo;
    }

    public void record(String actor, String action, String target, String detail, String ip) {
        try {
            repo.insert(actor, action, target, detail, ip);
        } catch (RuntimeException e) {
            log.warn("Audit write failed: {}", e.getMessage());
        }
    }
}
