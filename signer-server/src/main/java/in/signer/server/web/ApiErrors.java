package in.signer.server.web;

import in.signer.core.ErrorCode;
import in.signer.core.SignerException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.http.converter.HttpMessageNotReadableException;
import org.springframework.web.HttpMediaTypeNotSupportedException;
import org.springframework.web.HttpRequestMethodNotSupportedException;
import org.springframework.web.bind.MissingServletRequestParameterException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;
import org.springframework.web.method.annotation.MethodArgumentTypeMismatchException;
import org.springframework.web.servlet.resource.NoResourceFoundException;

import java.util.Map;

/** Uniform JSON error body: {@code {"ok":false,"error":{"code":"...","message":"..."}}}. */
@RestControllerAdvice
public class ApiErrors {

    private static final Logger log = LoggerFactory.getLogger(ApiErrors.class);

    public static ResponseEntity<Map<String, Object>> body(int status, String code, String message) {
        return ResponseEntity.status(status).body(Map.of("ok", false, "error", Map.of("code", code, "message", message)));
    }

    @ExceptionHandler(SignerException.class)
    public ResponseEntity<Map<String, Object>> signer(SignerException e) {
        return body(e.code().httpStatus(), e.code().name(), e.getMessage());
    }

    @ExceptionHandler({HttpMessageNotReadableException.class, MissingServletRequestParameterException.class,
            MethodArgumentTypeMismatchException.class})
    public ResponseEntity<Map<String, Object>> badRequest(Exception e) {
        return body(400, ErrorCode.BAD_REQUEST.name(), "Malformed request: " + e.getMessage());
    }

    @ExceptionHandler(HttpMediaTypeNotSupportedException.class)
    public ResponseEntity<Map<String, Object>> mediaType(Exception e) {
        return body(415, ErrorCode.BAD_REQUEST.name(), "Use Content-Type: application/json");
    }

    @ExceptionHandler(HttpRequestMethodNotSupportedException.class)
    public ResponseEntity<Map<String, Object>> method(Exception e) {
        return body(405, "METHOD_NOT_ALLOWED", e.getMessage());
    }

    @ExceptionHandler(NoResourceFoundException.class)
    public ResponseEntity<Map<String, Object>> notFound(NoResourceFoundException e) {
        return body(404, ErrorCode.NOT_FOUND.name(), "Not found");
    }

    @ExceptionHandler(Exception.class)
    public ResponseEntity<Map<String, Object>> unexpected(Exception e) {
        log.error("Unexpected error", e);
        return body(HttpStatus.INTERNAL_SERVER_ERROR.value(), ErrorCode.INTERNAL_ERROR.name(), "Unexpected server error");
    }
}
