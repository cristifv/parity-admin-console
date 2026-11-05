package parity.adminconsole.web;

import java.net.URI;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.http.HttpStatusCode;
import org.springframework.http.ProblemDetail;
import org.springframework.http.ResponseEntity;
import org.springframework.http.converter.HttpMessageNotReadableException;
import org.springframework.web.HttpRequestMethodNotSupportedException;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.MissingServletRequestParameterException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;
import org.springframework.web.method.annotation.MethodArgumentTypeMismatchException;
import org.springframework.web.servlet.resource.NoResourceFoundException;
import parity.adminconsole.audit.AuditUnavailableException;
import parity.adminconsole.backend.BackendException;
import parity.adminconsole.identity.KeycloakException;
import parity.adminconsole.security.ForbiddenException;
import parity.adminconsole.security.TenantNotFoundException;

/**
 * Errors as RFC 9457 problem details with the console's or the backend's {@code code} (PLAN.md "Kafka
 * request/reply"). Multi-tenant rule 6: a backend's own message never reaches a caller (every caller
 * is a tenant's person: it may name another tenant); the caller gets the code (and the broken rule's
 * name). A tenant out of scope and a missing one get the same 404 body. A method a path doesn't take
 * (the staff routes removed by user decision D2, 2026-11-03, among them) is 405.
 */
@RestControllerAdvice
public class ApiErrors {

    private static final Logger log = LoggerFactory.getLogger(ApiErrors.class);

    @ExceptionHandler(TenantNotFoundException.class)
    ResponseEntity<ProblemDetail> notFound(TenantNotFoundException e) {
        return problem(HttpStatus.NOT_FOUND, "not_found", null);
    }

    @ExceptionHandler(ForbiddenException.class)
    ResponseEntity<ProblemDetail> forbidden(ForbiddenException e) {
        return problem(HttpStatus.FORBIDDEN, "forbidden", null);
    }

    @ExceptionHandler(ApiException.class)
    ResponseEntity<ProblemDetail> api(ApiException e) {
        ResponseEntity<ProblemDetail> r = problem(HttpStatusCode.valueOf(e.code().status()), e.code().code(), null);
        if (e.field() != null) {
            r.getBody().setProperty("field", e.field());
        }
        return r;
    }

    @ExceptionHandler(AuditUnavailableException.class)
    ResponseEntity<ProblemDetail> audit(AuditUnavailableException e) {
        return retryLater(problem(HttpStatus.SERVICE_UNAVAILABLE, "audit_unavailable", null));
    }

    /** Keycloak failed a call the request needed: 503, retry later (the apply job retries its own). */
    @ExceptionHandler(KeycloakException.class)
    ResponseEntity<ProblemDetail> keycloak(KeycloakException e) {
        log.atWarn().addKeyValue("code", e.kind().code()).addKeyValue("status", e.status())
                .addKeyValue("call", String.valueOf(e.call())).addKeyValue("event", "keycloak.call_failed").log("a Keycloak call failed");
        return retryLater(problem(HttpStatus.SERVICE_UNAVAILABLE, "identity_unavailable", null));
    }

    @ExceptionHandler(BackendException.class)
    ResponseEntity<ProblemDetail> backend(BackendException e) {
        BackendException.Kind kind = e.kind();
        if (kind == BackendException.Kind.NOT_FOUND) {
            // The same body as a tenant out of scope (rule 2).
            return problem(HttpStatus.NOT_FOUND, "not_found", null);
        }
        ResponseEntity<ProblemDetail> r = problem(HttpStatusCode.valueOf(kind.status()), kind.code(), null);
        if (e.rule() != null && (kind == BackendException.Kind.CONFLICT || kind == BackendException.Kind.BAD_REQUEST)) {
            r.getBody().setProperty("rule", e.rule());
        }
        if (kind == BackendException.Kind.INTERNAL || kind == BackendException.Kind.FORBIDDEN) {
            log.atWarn().addKeyValue("kind", kind).addKeyValue("event", "backend.request_failed").log("a backend refused or failed a request");
        }
        return kind.status() == 503 ? retryLater(r) : r;
    }

    @ExceptionHandler({MethodArgumentNotValidException.class, HttpMessageNotReadableException.class,
            MissingServletRequestParameterException.class, MethodArgumentTypeMismatchException.class})
    ResponseEntity<ProblemDetail> badInput(Exception e) {
        return problem(HttpStatus.BAD_REQUEST, "bad_request", null);
    }

    @ExceptionHandler(NoResourceFoundException.class)
    ResponseEntity<ProblemDetail> noRoute(NoResourceFoundException e) {
        return problem(HttpStatus.NOT_FOUND, "not_found", null);
    }

    @ExceptionHandler(HttpRequestMethodNotSupportedException.class)
    ResponseEntity<ProblemDetail> noMethod(HttpRequestMethodNotSupportedException e) {
        return problem(HttpStatus.METHOD_NOT_ALLOWED, "method_not_allowed", null);
    }

    @ExceptionHandler(Exception.class)
    ResponseEntity<ProblemDetail> other(Exception e) {
        log.atError().addKeyValue("cause", e.getClass().getName()).addKeyValue("event", "http.request_failed").log("a request failed");
        return problem(HttpStatus.INTERNAL_SERVER_ERROR, "internal", null);
    }

    static ResponseEntity<ProblemDetail> problem(HttpStatusCode status, String code, String detail) {
        ProblemDetail p = ProblemDetail.forStatus(status);
        p.setType(URI.create("about:blank"));
        p.setProperty("code", code);
        if (detail != null) {
            p.setDetail(detail);
        }
        return ResponseEntity.status(status).body(p);
    }

    private static ResponseEntity<ProblemDetail> retryLater(ResponseEntity<ProblemDetail> r) {
        return ResponseEntity.status(r.getStatusCode()).header("Retry-After", "1").body(r.getBody());
    }
}
