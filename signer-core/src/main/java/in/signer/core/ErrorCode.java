package in.signer.core;

/**
 * Stable error codes shared by the agent, the server and the SDKs.
 * Integrators should branch on {@link #name()}, never on the message text.
 */
public enum ErrorCode {
    BAD_REQUEST(400),
    UNAUTHORIZED(401),
    TOKEN_INVALID(401),
    TOKEN_EXPIRED(401),
    TOKEN_REPLAYED(401),
    FORBIDDEN(403),
    ORIGIN_NOT_ALLOWED(403),
    LICENSE_INVALID(403),
    QUOTA_EXCEEDED(429),
    RATE_LIMITED(429),
    NOT_FOUND(404),
    CONFLICT(409),
    PAYLOAD_TOO_LARGE(413),
    TOKEN_NOT_PRESENT(424),
    CERTIFICATE_NOT_FOUND(424),
    CERTIFICATE_EXPIRED(424),
    PIN_INCORRECT(424),
    PIN_LOCKED(424),
    USER_CANCELLED(424),
    BUSY(409),
    PDF_INVALID(422),
    PDF_PASSWORD_REQUIRED(422),
    PDF_SIGNING_NOT_ALLOWED(422),
    SIGNATURE_TOO_LARGE(422),
    TIMESTAMP_FAILED(502),
    REVOCATION_FETCH_FAILED(502),
    SIGNING_FAILED(500),
    INTERNAL_ERROR(500);

    private final int httpStatus;

    ErrorCode(int httpStatus) {
        this.httpStatus = httpStatus;
    }

    public int httpStatus() {
        return httpStatus;
    }
}
