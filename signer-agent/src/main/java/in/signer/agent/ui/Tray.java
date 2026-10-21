package in.signer.agent.ui;

import in.signer.agent.config.AgentConfig;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.awt.Desktop;
import java.awt.MenuItem;
import java.awt.PopupMenu;
import java.awt.SystemTray;
import java.awt.TrayIcon;
import java.net.URI;
import java.nio.file.Files;
import java.nio.file.Path;

/** System-tray icon with shortcuts to diagnostics, logs and settings. */
public final class Tray {

    private static final Logger log = LoggerFactory.getLogger(Tray.class);

    private Tray() {
    }

    public static void install(String version, int port, Runnable onExit) {
        if (!SystemTray.isSupported()) {
            return;
        }
        try {
            PopupMenu menu = new PopupMenu();
            MenuItem header = new MenuItem("Signer Agent " + version + " - running on port " + port);
            header.setEnabled(false);
            menu.add(header);
            menu.addSeparator();
            menu.add(item("Diagnostics and certificates", () -> browse("http://127.0.0.1:" + port + "/")));
            menu.add(item("Open log folder", () -> open(AgentConfig.userDataDir().resolve("logs"))));
            menu.add(item("Edit settings", () -> {
                Path cfg = AgentConfig.userConfigDir().resolve("agent.properties");
                if (!Files.exists(cfg)) {
                    Files.createDirectories(cfg.getParent());
                    Files.writeString(cfg, "# Signer Agent user settings - see agent-defaults.properties for all keys\n# agent.port=1645\n");
                }
                open(cfg);
            }));
            menu.addSeparator();
            menu.add(item("Exit", onExit::run));

            TrayIcon icon = new TrayIcon(Icons.app(32), "Signer Agent " + version, menu);
            icon.setImageAutoSize(true);
            SystemTray.getSystemTray().add(icon);
        } catch (Exception e) {
            log.warn("System tray unavailable: {}", e.getMessage());
        }
    }

    private interface Action {
        void run() throws Exception;
    }

    private static MenuItem item(String label, Action action) {
        MenuItem mi = new MenuItem(label);
        mi.addActionListener(e -> {
            try {
                action.run();
            } catch (Exception ex) {
                log.warn("{} failed: {}", label, ex.getMessage());
            }
        });
        return mi;
    }

    private static void browse(String url) throws Exception {
        if (Desktop.isDesktopSupported()) {
            Desktop.getDesktop().browse(URI.create(url));
        }
    }

    private static void open(Path p) throws Exception {
        Files.createDirectories(Files.isDirectory(p) || !p.toString().contains(".") ? p : p.getParent());
        if (Desktop.isDesktopSupported()) {
            Desktop.getDesktop().open(p.toFile());
        }
    }
}
