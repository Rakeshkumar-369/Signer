package in.signer.agent.http;

/** Marker for an HTTP-level failure that is not a signing error (e.g. 404, 405). */
final class ApiException extends RuntimeException {

    final int status;
    final String code;

    ApiException(int status, String code, String message) {
        super(message);
        this.status = status;
        this.code = code;
    }
}
