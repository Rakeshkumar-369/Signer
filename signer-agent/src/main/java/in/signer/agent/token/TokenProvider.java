package in.signer.agent.token;

import in.signer.core.pdf.SigningKey;

import java.util.List;

/** A source of signing certificates and keys: a PKCS#11 token slot, the Windows certificate store, or a file. */
public interface TokenProvider {

    /** Short identifier shown in diagnostics, e.g. {@code pkcs11:eps2003csp11.dll#0}. */
    String name();

    /** Lists the signing certificates currently available (empty when no token is connected). */
    List<TokenCertificate> certificates();

    /** True when the agent must collect a PIN before signing (PKCS#11); false when the OS/driver prompts. */
    boolean requiresPin();

    /** Opens the private key that belongs to {@code cert}; {@code pin} may be null when not required. */
    SigningKey unlock(TokenCertificate cert, char[] pin);

    /** Ends the token session (logout) after a transaction. */
    void release();

    /** Last error seen while talking to the token, or null. */
    String lastError();
}
