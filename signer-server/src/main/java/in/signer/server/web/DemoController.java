package in.signer.server.web;

import in.signer.core.ErrorCode;
import in.signer.core.SignerException;
import in.signer.server.config.SignerProperties;
import in.signer.server.repo.Tenant;
import in.signer.server.service.Bootstrap;
import in.signer.server.service.TenantService;
import in.signer.server.service.TransactionService;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

import java.time.Instant;
import java.util.List;
import java.util.Map;

/**
 * Plays the role of the integrating application's back end for the bundled demo page: it issues
 * transaction tokens for the "demo" tenant. Disabled with {@code signer.demo.enabled=false}.
 */
@RestController
public class DemoController {

    public record DemoTokenRequest(List<String> operations, Integer maxDocuments, String reference) {
    }

    private final SignerProperties props;
    private final TenantService tenants;
    private final TransactionService transactions;

    public DemoController(SignerProperties props, TenantService tenants, TransactionService transactions) {
        this.props = props;
        this.tenants = tenants;
        this.transactions = transactions;
    }

    @PostMapping("/demo/api/token")
    public Map<String, Object> token(HttpServletRequest req, @RequestBody(required = false) DemoTokenRequest body) {
        if (!props.getDemo().isEnabled()) {
            throw new SignerException(ErrorCode.NOT_FOUND, "Demo is disabled");
        }
        Tenant demo = tenants.byCode(Bootstrap.DEMO_CODE)
                .filter(t -> t.active(Instant.now()))
                .orElseThrow(() -> new SignerException(ErrorCode.NOT_FOUND, "Demo tenant is not available"));
        String origin = req.getHeader("Origin");
        if (origin == null) {
            throw new SignerException(ErrorCode.ORIGIN_NOT_ALLOWED, "Open the demo page in a browser");
        }
        DemoTokenRequest b = body == null ? new DemoTokenRequest(null, null, null) : body;
        TransactionService.Issued i = transactions.issue(demo, origin, b.operations(), null, b.maxDocuments(),
                b.reference() == null ? "DEMO" : b.reference(), AuthResolver.clientIp(req));
        return Map.of("ok", true, "token", i.token(), "txn", i.txn(), "expiresAt", i.expiresAt().toString());
    }
}
