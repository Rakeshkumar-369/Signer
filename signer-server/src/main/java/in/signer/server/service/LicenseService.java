package in.signer.server.service;

import in.signer.core.ErrorCode;
import in.signer.core.SignerException;
import in.signer.core.license.LicenseCodec;
import in.signer.core.license.LicenseInfo;
import in.signer.core.token.Ed25519Keys;
import in.signer.server.config.SignerProperties;
import in.signer.server.repo.SettingsRepository;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.PublicKey;
import java.time.Instant;
import java.util.List;

/**
 * Enforces the commercial licence of this installation. Without a valid licence the server runs in
 * evaluation mode with small limits.
 */
@Service
public class LicenseService {

    private static final Logger log = LoggerFactory.getLogger(LicenseService.class);
    private static final String SETTING = "license";

    public static final LicenseInfo EVALUATION = new LicenseInfo("EVALUATION", "Evaluation", "evaluation",
            Instant.EPOCH, null, 3, 1000, List.of("*"));

    public record Status(LicenseInfo license, boolean evaluation, boolean expired, String message) {
    }

    private final SignerProperties props;
    private final SettingsRepository settings;
    private final PublicKey vendorKey;
    private volatile Status status;

    public LicenseService(SignerProperties props, SettingsRepository settings) {
        this.props = props;
        this.settings = settings;
        this.vendorKey = loadVendorKey();
        reload();
    }

    private static PublicKey loadVendorKey() {
        try (InputStream in = LicenseService.class.getResourceAsStream("/license/vendor-public-key.txt")) {
            if (in == null) {
                return null;
            }
            for (String line : new String(in.readAllBytes(), StandardCharsets.UTF_8).split("\\R")) {
                String l = line.strip();
                if (!l.isEmpty() && !l.startsWith("#")) {
                    return Ed25519Keys.publicKeyFromString(l);
                }
            }
        } catch (IOException | RuntimeException e) {
            log.warn("Vendor licence key unreadable: {}", e.getMessage());
        }
        return null;
    }

    public final synchronized void reload() {
        String text = settings.get(SETTING).orElse(null);
        Path file = Path.of(props.getLicense().getFile());
        if (text == null && Files.isRegularFile(file)) {
            try {
                text = Files.readString(file);
            } catch (IOException e) {
                log.warn("Cannot read licence file {}: {}", file, e.getMessage());
            }
        }
        status = evaluate(text);
        log.info("Licence: {}", status.message());
    }

    private Status evaluate(String text) {
        if (text == null || text.isBlank()) {
            return new Status(EVALUATION, true, false, "Evaluation mode (no licence installed)");
        }
        if (vendorKey == null) {
            return new Status(EVALUATION, true, false, "Evaluation mode (no vendor key built into this server)");
        }
        try {
            LicenseInfo l = LicenseCodec.verify(text, vendorKey);
            boolean expired = l.expired(Instant.now());
            return new Status(l, false, expired, expired
                    ? "Licence " + l.licenseId() + " for " + l.licensee() + " expired on " + l.expiresAt()
                    : "Licensed to " + l.licensee() + " (" + l.edition() + ")");
        } catch (SignerException e) {
            return new Status(EVALUATION, true, false, "Evaluation mode (installed licence is invalid)");
        }
    }

    /** Validates and stores a licence uploaded by an administrator. */
    public Status install(String text) {
        if (vendorKey == null) {
            throw new SignerException(ErrorCode.LICENSE_INVALID, "This server build has no vendor licence key");
        }
        LicenseCodec.verify(text, vendorKey);
        settings.put(SETTING, text.strip());
        reload();
        return status;
    }

    public Status status() {
        return status;
    }

    public void checkTenantLimit(long currentTenants) {
        Status s = status;
        int max = s.license().maxTenants();
        if (max > 0 && currentTenants >= max) {
            throw new SignerException(ErrorCode.LICENSE_INVALID,
                    "The licence allows " + max + " tenant(s)" + (s.evaluation() ? " in evaluation mode" : ""));
        }
    }

    public void checkTransactionAllowed(long transactionsThisMonth) {
        Status s = status;
        if (s.expired()) {
            throw new SignerException(ErrorCode.LICENSE_INVALID, "The server licence has expired; contact your vendor");
        }
        long max = s.license().maxSignaturesPerMonth();
        if (max > 0 && transactionsThisMonth >= max) {
            throw new SignerException(ErrorCode.QUOTA_EXCEEDED,
                    "Monthly transaction limit of the server licence reached (" + max + ")");
        }
    }

    public void checkFeature(String feature) {
        if (!status.license().hasFeature(feature)) {
            throw new SignerException(ErrorCode.LICENSE_INVALID, "Feature '" + feature + "' is not included in the licence");
        }
    }
}
