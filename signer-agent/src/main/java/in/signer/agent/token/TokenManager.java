package in.signer.agent.token;

import in.signer.agent.config.AgentConfig;
import in.signer.core.cert.CertificateFilter;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.regex.Pattern;

/** Aggregates all configured token providers and applies the certificate policy (issuer filter, expiry). */
public final class TokenManager {

    private static final Logger log = LoggerFactory.getLogger(TokenManager.class);

    public record ProviderStatus(String name, boolean requiresPin, int certificates, String error) {
    }

    private final List<TokenProvider> providers;
    private final Pattern issuerFilter;
    private final boolean hideExpired;

    public TokenManager(List<TokenProvider> providers, String issuerFilterRegex, boolean hideExpired) {
        this.providers = List.copyOf(providers);
        this.issuerFilter = issuerFilterRegex == null || issuerFilterRegex.isBlank() ? null : Pattern.compile(issuerFilterRegex);
        this.hideExpired = hideExpired;
    }

    public static TokenManager fromConfig(AgentConfig cfg) {
        List<TokenProvider> list = new ArrayList<>();
        for (String type : cfg.getList("token.providers", ",")) {
            switch (type.toLowerCase(Locale.ROOT)) {
                case "windows" -> {
                    if (AgentConfig.isWindows()) {
                        list.add(new WindowsStoreTokenProvider());
                    }
                }
                case "pkcs11" -> {
                    int slots = Math.max(1, cfg.getInt("pkcs11.maxSlots", 4));
                    for (String lib : cfg.getList("pkcs11.libraries", ";")) {
                        Path p = Path.of(lib);
                        if (Files.isRegularFile(p)) {
                            for (int s = 0; s < slots; s++) {
                                list.add(new Pkcs11TokenProvider(p, s));
                            }
                            log.info("PKCS#11 library found: {}", p);
                        }
                    }
                }
                case "pkcs12" -> {
                    String f = cfg.get("pkcs12.file");
                    if (f != null) {
                        list.add(new Pkcs12TokenProvider(Path.of(f), cfg.get("pkcs12.password", "")));
                    }
                }
                default -> log.warn("Unknown token provider '{}'", type);
            }
        }
        return new TokenManager(list, cfg.get("certificates.issuerFilter"), cfg.getBool("certificates.hideExpired", true));
    }

    /** All usable signing certificates, de-duplicated by thumbprint (first provider wins). */
    public synchronized List<TokenCertificate> certificates() {
        Map<String, TokenCertificate> byId = new LinkedHashMap<>();
        for (TokenProvider p : providers) {
            for (TokenCertificate c : p.certificates()) {
                if (issuerFilter != null && !issuerFilter.matcher(c.info().issuer()).matches()) {
                    continue;
                }
                if (hideExpired && !c.info().currentlyValid()) {
                    continue;
                }
                byId.putIfAbsent(c.id(), c);
            }
        }
        return new ArrayList<>(byId.values());
    }

    public List<TokenCertificate> certificates(CertificateFilter filter) {
        CertificateFilter f = filter == null ? CertificateFilter.ANY : filter;
        return certificates().stream().filter(c -> f.matches(c.info())).toList();
    }

    public List<ProviderStatus> status() {
        List<ProviderStatus> out = new ArrayList<>();
        for (TokenProvider p : providers) {
            int count = p.certificates().size();
            if (count > 0 || p.lastError() == null || !p.name().startsWith("pkcs11:") || p.name().endsWith("#0")) {
                out.add(new ProviderStatus(p.name(), p.requiresPin(), count, p.lastError()));
            }
        }
        return out;
    }

    public boolean hasProviders() {
        return !providers.isEmpty();
    }
}
