package in.signer.server.service;

import in.signer.core.SignerException;
import in.signer.core.util.Bytes;
import in.signer.server.config.SignerProperties;
import in.signer.server.repo.AdminUser;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.ApplicationArguments;
import org.springframework.boot.ApplicationRunner;
import org.springframework.stereotype.Component;

import java.net.URI;
import java.security.SecureRandom;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;

/** First-start initialisation: the initial administrator and (optionally) the demo tenant. */
@Component
public class Bootstrap implements ApplicationRunner {

    private static final Logger log = LoggerFactory.getLogger(Bootstrap.class);
    public static final String DEMO_CODE = "demo";

    private final AdminAuthService admins;
    private final TenantService tenants;
    private final SignerProperties props;

    public Bootstrap(AdminAuthService admins, TenantService tenants, SignerProperties props) {
        this.admins = admins;
        this.tenants = tenants;
        this.props = props;
    }

    @Override
    public void run(ApplicationArguments args) {
        if (!admins.hasUsers()) {
            String password = props.getAdmin().getInitialPassword();
            boolean generated = password == null || password.isBlank();
            if (generated) {
                byte[] r = new byte[12];
                new SecureRandom().nextBytes(r);
                password = "Sg" + Bytes.b64url(r) + "7";
            }
            admins.create(props.getAdmin().getInitialUsername(), password, AdminUser.ADMIN, true);
            log.warn("""

                    ============================================================
                     Initial administrator created
                       username: {}
                       password: {}
                     Log in at {}/admin/ and change the password.
                    ============================================================""",
                    props.getAdmin().getInitialUsername(), generated ? password : "(from signer.admin.initial-password)",
                    props.getPublicUrl());
        }
        if (props.getDemo().isEnabled() && tenants.byCode(DEMO_CODE).isEmpty()) {
            Set<String> origins = new LinkedHashSet<>();
            origins.add(origin(props.getPublicUrl()));
            origins.add("http://localhost:8080");
            origins.add("http://127.0.0.1:8080");
            try {
                tenants.create(new TenantService.TenantInput(DEMO_CODE, "Demo Department", null, "demo", 0L, null, List.copyOf(origins)));
                log.info("Demo tenant created for origins {}", origins);
            } catch (SignerException e) {
                log.warn("Demo tenant not created: {}", e.getMessage());
            }
        }
    }

    static String origin(String url) {
        URI u = URI.create(url);
        return u.getScheme() + "://" + u.getHost() + (u.getPort() > 0 ? ":" + u.getPort() : "");
    }
}
