package in.signer.agent;

import in.signer.agent.config.AgentConfig;
import in.signer.agent.http.AgentApi;
import in.signer.agent.http.AgentHttpServer;
import in.signer.agent.security.KeyRing;
import in.signer.agent.security.RequestGuard;
import in.signer.agent.service.AuditLog;
import in.signer.agent.service.SigningService;
import in.signer.agent.token.TokenManager;
import in.signer.agent.ui.AutoConsentService;
import in.signer.agent.ui.ConsentService;
import in.signer.agent.ui.SwingConsentService;
import in.signer.agent.ui.Tray;
import in.signer.core.cert.RevocationClient;
import in.signer.core.cert.TrustAnchors;
import in.signer.core.crypto.TimestampClient;
import in.signer.core.pdf.PdfSigner;

import javax.swing.JOptionPane;
import java.awt.GraphicsEnvironment;
import java.io.IOException;
import java.io.InputStream;
import java.net.BindException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.util.Properties;

/** Entry point of the desktop signing agent. */
public final class AgentMain {

    private AgentMain() {
    }

    /** A fully wired agent, used by {@link #main} and by integration tests. */
    public record Agent(AgentHttpServer server, SigningService signing, KeyRing keyRing) {
        public void stop() {
            server.stop();
        }
    }

    public static void main(String[] args) throws Exception {
        Path configFile = null;
        boolean headless = false;
        boolean console = false;
        for (int i = 0; i < args.length; i++) {
            switch (args[i]) {
                case "--config" -> configFile = Path.of(args[++i]);
                case "--headless" -> headless = true;
                case "--console" -> console = true;
                case "--version" -> {
                    System.out.println("Signer Agent " + version());
                    return;
                }
                case "--print-defaults" -> {
                    try (InputStream in = AgentMain.class.getResourceAsStream("/agent-defaults.properties")) {
                        System.out.write(in.readAllBytes());
                    }
                    System.out.flush();
                    return;
                }
                default -> {
                    System.err.println("Usage: signer-agent [--config file] [--headless] [--console] [--version] [--print-defaults]");
                    System.exit(2);
                }
            }
        }
        configureLogging(console);
        headless = headless || GraphicsEnvironment.isHeadless();
        AgentConfig cfg = AgentConfig.load(configFile);

        Agent agent;
        try {
            agent = start(cfg, headless);
        } catch (BindException e) {
            String msg = "Signer Agent is already running (port " + cfg.port() + " is in use).";
            org.slf4j.LoggerFactory.getLogger(AgentMain.class).warn(msg);
            if (!headless) {
                JOptionPane.showMessageDialog(null, msg, "Signer Agent", JOptionPane.INFORMATION_MESSAGE);
            }
            return;
        }
        Runtime.getRuntime().addShutdownHook(new Thread(agent::stop));
        if (!headless) {
            Tray.install(version(), agent.server().port(), () -> {
                agent.stop();
                System.exit(0);
            });
        }
        if (cfg.getBool("autostart", true)) {
            registerAutostart();
        }
    }

    public static Agent start(AgentConfig cfg, boolean headless) throws IOException {
        TrustAnchors anchors = TrustAnchors.fromDirectory(trustDir(cfg));
        String tsaUrl = cfg.get("tsa.url");
        TimestampClient tsa = tsaUrl == null ? null
                : new TimestampClient(tsaUrl, cfg.get("tsa.username"), cfg.get("tsa.password"), Duration.ofSeconds(20));
        PdfSigner pdfSigner = new PdfSigner(tsa, new RevocationClient(Duration.ofSeconds(15)));

        ConsentService consent;
        if (cfg.autoConsent()) {
            consent = new AutoConsentService(cfg.get("consent.autoPin"));
        } else if (headless) {
            throw new IllegalStateException("consent.mode=dialog needs a desktop session; run without --headless or set consent.mode=auto");
        } else {
            consent = new SwingConsentService(cfg.getInt("consent.timeoutSeconds", 120));
        }

        KeyRing keyRing = new KeyRing(cfg);
        if (cfg.get("security.serverUrl") != null) {
            Thread.ofVirtual().start(() -> keyRing.refresh(true));
        }
        RequestGuard guard = new RequestGuard(cfg, keyRing);
        SigningService signing = new SigningService(TokenManager.fromConfig(cfg), consent, pdfSigner, tsa, anchors,
                cfg.getBool("network.fetchIssuers", true), cfg.getBool("pkcs11.logoutAfterSign", true),
                cfg.getBool("ltv.enabled", true), new AuditLog(AgentConfig.userDataDir().resolve("logs")));

        long maxDoc = cfg.maxDocumentBytes();
        int maxBatch = cfg.getInt("signing.maxBatch", 50);
        long maxBody = Math.max(maxDoc * 4 / 3 + 1_000_000, Math.min(maxDoc * 4 / 3 * maxBatch, 512L * 1024 * 1024));

        AgentHttpServer server = new AgentHttpServer(cfg.port(), guard, maxBody);
        server.start(new AgentApi(guard, signing, version(), maxDoc, maxBatch, cfg.getBool("legacy.enabled", true),
                tsa != null, server.port(), cfg.sources()));
        return new Agent(server, signing, keyRing);
    }

    private static Path trustDir(AgentConfig cfg) {
        String configured = cfg.get("trust.anchorsDir");
        if (configured != null) {
            return Path.of(configured);
        }
        Path user = AgentConfig.userConfigDir().resolve("trust");
        if (Files.isDirectory(user)) {
            return user;
        }
        return AgentConfig.installDir().map(d -> AgentConfig.installFile(d, "trust")).orElse(user);
    }

    public static String version() {
        try (InputStream in = AgentMain.class.getResourceAsStream("/agent-version.properties")) {
            Properties p = new Properties();
            if (in != null) {
                p.load(in);
            }
            return p.getProperty("version", "dev");
        } catch (IOException e) {
            return "dev";
        }
    }

    private static void configureLogging(boolean console) {
        System.setProperty("org.slf4j.simpleLogger.showDateTime", "true");
        System.setProperty("org.slf4j.simpleLogger.dateTimeFormat", "yyyy-MM-dd HH:mm:ss");
        System.setProperty("org.slf4j.simpleLogger.defaultLogLevel", System.getProperty("signer.logLevel", "info"));
        if (!console) {
            try {
                Path logs = AgentConfig.userDataDir().resolve("logs");
                Files.createDirectories(logs);
                System.setProperty("org.slf4j.simpleLogger.logFile", logs.resolve("agent.log").toString());
            } catch (IOException ignored) {
                // fall back to stderr
            }
        }
    }

    /** Adds the installed launcher to HKCU\...\Run so the agent starts at logon (Windows, installed builds only). */
    private static void registerAutostart() {
        String app = System.getProperty("jpackage.app-path");
        if (app == null || !AgentConfig.isWindows()) {
            return;
        }
        try {
            new ProcessBuilder("reg", "add", "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
                    "/v", "SignerAgent", "/t", "REG_SZ", "/d", "\"" + app + "\"", "/f")
                    .redirectErrorStream(true).redirectOutput(ProcessBuilder.Redirect.DISCARD).start();
        } catch (IOException e) {
            org.slf4j.LoggerFactory.getLogger(AgentMain.class).warn("Could not register autostart: {}", e.getMessage());
        }
    }
}
