package in.signer.server.cli;

import in.signer.core.license.LicenseCodec;
import in.signer.core.license.LicenseInfo;
import in.signer.core.token.Ed25519Keys;

import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.time.Instant;
import java.time.LocalDate;
import java.time.ZoneOffset;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;

/**
 * Vendor tooling for licence management.
 * <pre>
 *   java -jar signer-server.jar license generate-keys --out vendor-keys
 *   java -jar signer-server.jar license issue --key vendor-keys/vendor-private.pem --licensee "APTS" \
 *        --expires 2027-12-31 --tenants 25 --monthly 500000 --edition enterprise --out apts.lic
 * </pre>
 */
public final class LicenseTool {

    private LicenseTool() {
    }

    public static void run(String[] args) throws Exception {
        if (args.length == 0) {
            usage();
            return;
        }
        Map<String, String> opts = new HashMap<>();
        for (int i = 1; i + 1 < args.length; i += 2) {
            opts.put(args[i].replaceFirst("^--", ""), args[i + 1]);
        }
        switch (args[0]) {
            case "generate-keys" -> {
                Path out = Path.of(opts.getOrDefault("out", "vendor-keys"));
                Files.createDirectories(out);
                Path priv = out.resolve("vendor-private.pem");
                if (Files.exists(priv)) {
                    System.err.println("Refusing to overwrite " + priv);
                    System.exit(1);
                }
                KeyPair kp = Ed25519Keys.loadOrCreate(priv);
                String pub = Ed25519Keys.publicKeyToString(kp.getPublic());
                Files.writeString(out.resolve("vendor-public.txt"), pub + "\n");
                System.out.println("Private key : " + priv.toAbsolutePath() + "   (keep offline, never commit)");
                System.out.println("Public key  : " + pub);
                System.out.println("Paste the public key into signer-server/src/main/resources/license/vendor-public-key.txt and rebuild.");
            }
            case "issue" -> {
                PrivateKey key = Ed25519Keys.privateKeyFromPem(Files.readString(Path.of(require(opts, "key"))));
                String expires = opts.get("expires");
                LicenseInfo l = new LicenseInfo(
                        opts.getOrDefault("id", "LIC-" + UUID.randomUUID().toString().substring(0, 8).toUpperCase()),
                        require(opts, "licensee"),
                        opts.getOrDefault("edition", "standard"),
                        Instant.now(),
                        expires == null ? null : LocalDate.parse(expires).plusDays(1).atStartOfDay().toInstant(ZoneOffset.UTC),
                        Integer.parseInt(opts.getOrDefault("tenants", "10")),
                        Long.parseLong(opts.getOrDefault("monthly", "0")),
                        List.copyOf(Arrays.asList(opts.getOrDefault("features", "*").split(","))));
                String text = LicenseCodec.issue(l, key);
                String out = opts.get("out");
                if (out != null) {
                    Files.writeString(Path.of(out), text + "\n");
                    System.out.println("Licence written to " + out);
                } else {
                    System.out.println(text);
                }
            }
            default -> usage();
        }
    }

    private static String require(Map<String, String> opts, String name) {
        String v = opts.get(name);
        if (v == null) {
            throw new IllegalArgumentException("--" + name + " is required");
        }
        return v;
    }

    private static void usage() {
        System.out.println("""
                Usage:
                  license generate-keys [--out dir]
                  license issue --key vendor-private.pem --licensee NAME [--expires YYYY-MM-DD] [--tenants N]
                                [--monthly N] [--edition NAME] [--features a,b] [--id ID] [--out file]""");
    }
}
