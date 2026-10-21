package in.signer.agent.ui;

import in.signer.core.ErrorCode;
import in.signer.core.SignerException;

/** Approves automatically (kiosk / automated testing). Uses the preselected or first certificate. */
public final class AutoConsentService implements ConsentService {

    private final String pin;

    public AutoConsentService(String pin) {
        this.pin = pin;
    }

    @Override
    public ConsentDecision ask(ConsentRequest request) {
        if (request.errorMessage() != null) {
            // A retry means the configured PIN was wrong: do not loop.
            throw new SignerException(ErrorCode.PIN_INCORRECT, request.errorMessage());
        }
        String id = request.preselectedId() != null ? request.preselectedId() : request.certificates().get(0).id();
        return new ConsentDecision(id, pin == null ? null : pin.toCharArray());
    }
}
