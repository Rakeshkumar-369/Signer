package in.signer.agent.config;

import java.io.IOException;
import java.io.InputStream;
import java.io.Reader;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Locale;
import java.util.Properties;

/** Layered agent configuration: built-in defaults, install folder, user folder, then JVM system properties. */
public final class AgentConfig {

    private final Properties props;
    private final List<Path> sources;

    private AgentConfig(Properties props, List<Path> sources) {
        this.props = props;
        this.sources = sources;
    }

    public static AgentConfig load(Path explicitFile) {
        Properties p = new Properties();
        try (InputStream in = AgentConfig.class.getResourceAsStream("/agent-defaults.properties")) {
            if (in != null) {
                p.load(new java.io.InputStreamReader(in, StandardCharsets.UTF_8));
            }
        } catch (IOException e) {
            throw new IllegalStateException("Cannot read built-in defaults", e);
        }
        List<Path> sources = new ArrayList<>();
        List<Path> candidates = new ArrayList<>();
        installDir().ifPresent(d -> candidates.add(d.resolve("agent.properties")));
        candidates.add(userConfigDir().resolve("agent.properties"));
        if (explicitFile != null) {
            candidates.add(explicitFile);
        }
        for (Path c : candidates) {
            if (Files.isRegularFile(c)) {
                try (Reader r = Files.newBufferedReader(c, StandardCharsets.UTF_8)) {
                    p.load(r);
                    sources.add(c);
                } catch (IOException e) {
                    System.err.println("Ignoring unreadable config " + c + ": " + e.getMessage());
                }
            }
        }
        System.getProperties().stringPropertyNames().stream()
                .filter(k -> k.startsWith("signer."))
                .forEach(k -> p.setProperty(k.substring("signer.".length()), System.getProperty(k)));
        return new AgentConfig(p, sources);
    }

    public static AgentConfig of(Properties overrides) {
        AgentConfig base = load(null);
        base.props.putAll(overrides);
        return base;
    }

    public List<Path> sources() {
        return sources;
    }

    public String get(String key, String def) {
        String v = props.getProperty(key);
        return v == null || v.isBlank() ? def : v.strip();
    }

    public String get(String key) {
        return get(key, null);
    }

    public int getInt(String key, int def) {
        String v = get(key);
        try {
            return v == null ? def : Integer.parseInt(v);
        } catch (NumberFormatException e) {
            return def;
        }
    }

    public boolean getBool(String key, boolean def) {
        String v = get(key);
        return v == null ? def : Boolean.parseBoolean(v);
    }

    public List<String> getList(String key, String separatorRegex) {
        String v = get(key);
        if (v == null) {
            return List.of();
        }
        return Arrays.stream(v.split(separatorRegex)).map(String::strip).filter(s -> !s.isEmpty()).toList();
    }

    public void set(String key, String value) {
        props.setProperty(key, value);
    }

    // ---- typed accessors -------------------------------------------------

    public int port() {
        return getInt("agent.port", 1645);
    }

    public boolean tokenMode() {
        return !"allowlist".equalsIgnoreCase(get("security.mode", "token"));
    }

    public List<String> allowedOrigins() {
        return getList("security.allowedOrigins", ",").stream().map(o -> o.toLowerCase(Locale.ROOT).replaceAll("/+$", "")).toList();
    }

    public boolean autoConsent() {
        return "auto".equalsIgnoreCase(get("consent.mode", "dialog"));
    }

    public long maxDocumentBytes() {
        return getInt("signing.maxDocumentMb", 25) * 1024L * 1024L;
    }

    // ---- locations -------------------------------------------------------

    /** Folder of the installed application (jpackage sets jpackage.app-path to the launcher). */
    public static java.util.Optional<Path> installDir() {
        String app = System.getProperty("jpackage.app-path");
        if (app == null) {
            return java.util.Optional.empty();
        }
        Path launcher = Path.of(app).toAbsolutePath();
        Path dir = launcher.getParent();
        // Windows: <dir>\Signer Agent.exe + <dir>\app ; Linux: <dir>/bin/launcher + <dir>/lib/app
        if (dir != null && dir.getFileName() != null && dir.getFileName().toString().equals("bin")) {
            dir = dir.getParent();
        }
        return java.util.Optional.ofNullable(dir);
    }

    public static Path userConfigDir() {
        String os = System.getProperty("os.name", "").toLowerCase(Locale.ROOT);
        String appData = System.getenv("APPDATA");
        if (os.contains("win") && appData != null) {
            return Path.of(appData, "Signer");
        }
        return Path.of(System.getProperty("user.home"), ".config", "signer");
    }

    public static Path userDataDir() {
        String os = System.getProperty("os.name", "").toLowerCase(Locale.ROOT);
        String local = System.getenv("LOCALAPPDATA");
        if (os.contains("win") && local != null) {
            return Path.of(local, "Signer");
        }
        return Path.of(System.getProperty("user.home"), ".local", "share", "signer");
    }

    public static boolean isWindows() {
        return System.getProperty("os.name", "").toLowerCase(Locale.ROOT).contains("win");
    }
}
