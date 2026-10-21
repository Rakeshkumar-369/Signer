package in.signer.agent.token;

import in.signer.core.ErrorCode;
import in.signer.core.SignerException;

import java.util.Locale;

/** Translates PKCS#11 / CAPI exceptions into stable error codes with user-friendly messages. */
final class TokenErrors {

    private TokenErrors() {
    }

    static SignerException translate(Throwable t, String action) {
        if (t instanceof SignerException se) {
            return se;
        }
        String all = chain(t).toUpperCase(Locale.ROOT);
        if (all.contains("CKR_PIN_INCORRECT") || all.contains("FAILEDLOGIN") || all.contains("PIN INCORRECT")
                || all.contains("WRONG PIN") || all.contains("SCARD_W_WRONG_CHV")) {
            return new SignerException(ErrorCode.PIN_INCORRECT, "Incorrect token PIN", t);
        }
        if (all.contains("CKR_PIN_LOCKED") || all.contains("SCARD_W_CHV_BLOCKED") || all.contains("PIN IS BLOCKED")) {
            return new SignerException(ErrorCode.PIN_LOCKED, "The token PIN is locked; unblock it with the token utility", t);
        }
        if (all.contains("CKR_FUNCTION_CANCELED") || all.contains("SCARD_W_CANCELLED_BY_USER") || all.contains("CANCELLED BY THE USER")
                || all.contains("OPERATION WAS CANCELED")) {
            return new SignerException(ErrorCode.USER_CANCELLED, "Signing was cancelled by the user", t);
        }
        if (all.contains("CKR_TOKEN_NOT_PRESENT") || all.contains("CKR_DEVICE_REMOVED") || all.contains("SCARD_E_NO_SMARTCARD")
                || all.contains("SCARD_W_REMOVED_CARD") || all.contains("KEYSET DOES NOT EXIST") || all.contains("CKR_SESSION_HANDLE_INVALID")
                || all.contains("SMART CARD") && all.contains("NOT")) {
            return new SignerException(ErrorCode.TOKEN_NOT_PRESENT, "The USB token is not connected; insert it and try again", t);
        }
        return new SignerException(ErrorCode.SIGNING_FAILED, action + " failed: " + rootMessage(t), t);
    }

    static String chain(Throwable t) {
        StringBuilder sb = new StringBuilder();
        for (Throwable c = t; c != null; c = c.getCause() == c ? null : c.getCause()) {
            sb.append(c.getClass().getSimpleName()).append(':').append(c.getMessage()).append(' ');
        }
        return sb.toString();
    }

    static String rootMessage(Throwable t) {
        Throwable c = t;
        while (c.getCause() != null && c.getCause() != c) {
            c = c.getCause();
        }
        return c.getMessage() == null ? c.getClass().getSimpleName() : c.getMessage();
    }
}
