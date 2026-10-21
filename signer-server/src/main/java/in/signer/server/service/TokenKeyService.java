package in.signer.server.service;

import in.signer.core.token.Ed25519Keys;
import in.signer.server.config.SignerProperties;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.file.Path;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/** The Ed25519 key that signs transaction tokens and admin sessions, plus the published key set. */
@Service
public class TokenKeyService {

    private static final Logger log = LoggerFactory.getLogger(TokenKeyService.class);

    public record Jwk(String kid, String kty, String crv, String x, String use, String alg) {
    }

    private final KeyPair keyPair;
    private final String keyId;
    private final Map<String, PublicKey> published = new LinkedHashMap<>();

    public TokenKeyService(SignerProperties props) {
        try {
            this.keyPair = Ed25519Keys.loadOrCreate(Path.of(props.getToken().getKeyFile()));
        } catch (IOException e) {
            throw new UncheckedIOException("Cannot load or create the token signing key " + props.getToken().getKeyFile(), e);
        }
        this.keyId = Ed25519Keys.keyId(keyPair.getPublic());
        published.put(keyId, keyPair.getPublic());
        String extra = props.getToken().getAdditionalPublicKeys();
        if (extra != null) {
            for (String e : extra.split(",")) {
                if (e.isBlank()) {
                    continue;
                }
                int eq = e.indexOf('=');
                PublicKey k = Ed25519Keys.publicKeyFromString(eq > 0 ? e.substring(eq + 1).strip() : e.strip());
                published.put(eq > 0 ? e.substring(0, eq).strip() : Ed25519Keys.keyId(k), k);
            }
        }
        log.info("Token signing key id: {}", keyId);
    }

    public String keyId() {
        return keyId;
    }

    public PrivateKey privateKey() {
        return keyPair.getPrivate();
    }

    public PublicKey publicKey() {
        return keyPair.getPublic();
    }

    public Map<String, PublicKey> publishedKeys() {
        return published;
    }

    public List<Jwk> jwks() {
        List<Jwk> out = new ArrayList<>();
        published.forEach((kid, k) -> out.add(new Jwk(kid, "OKP", "Ed25519", Ed25519Keys.publicKeyToString(k), "sig", "EdDSA")));
        return out;
    }

    /** Line to paste into agent.properties when the agent cannot reach the server URL. */
    public String agentTrustedKeysLine() {
        return "security.trustedKeys=" + keyId + "=" + Ed25519Keys.publicKeyToString(keyPair.getPublic());
    }
}
