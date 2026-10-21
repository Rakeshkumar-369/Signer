package in.signer.agent.ui;

/** Asks the user to approve a signing transaction. Throws {@code USER_CANCELLED} when declined. */
public interface ConsentService {

    ConsentDecision ask(ConsentRequest request);
}
