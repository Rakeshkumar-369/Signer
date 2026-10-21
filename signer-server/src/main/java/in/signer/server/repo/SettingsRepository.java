package in.signer.server.repo;

import org.springframework.jdbc.core.simple.JdbcClient;
import org.springframework.stereotype.Repository;

import java.util.Optional;

/** Small key/value store for server-wide settings (e.g. the uploaded licence). */
@Repository
public class SettingsRepository {

    private final JdbcClient jdbc;

    public SettingsRepository(JdbcClient jdbc) {
        this.jdbc = jdbc;
    }

    public Optional<String> get(String key) {
        return jdbc.sql("SELECT setting_value FROM settings WHERE setting_key = ?").param(key).query(String.class).optional();
    }

    public void put(String key, String value) {
        if (jdbc.sql("UPDATE settings SET setting_value = ? WHERE setting_key = ?").params(value, key).update() == 0) {
            jdbc.sql("INSERT INTO settings (setting_key, setting_value) VALUES (?, ?)").params(key, value).update();
        }
    }
}
