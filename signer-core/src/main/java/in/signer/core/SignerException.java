package in.signer.core;

/** Runtime exception carrying a stable {@link ErrorCode}. */
public class SignerException extends RuntimeException {

    private final ErrorCode code;

    public SignerException(ErrorCode code, String message) {
        super(message);
        this.code = code;
    }

    public SignerException(ErrorCode code, String message, Throwable cause) {
        super(message, cause);
        this.code = code;
    }

    public ErrorCode code() {
        return code;
    }

    public static SignerException badRequest(String message) {
        return new SignerException(ErrorCode.BAD_REQUEST, message);
    }
}
