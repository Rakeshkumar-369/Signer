package in.signer.agent.ui;

/** The user's approval: the chosen certificate and (for PKCS#11 tokens) the PIN. */
public record ConsentDecision(String certificateId, char[] pin) {
}
