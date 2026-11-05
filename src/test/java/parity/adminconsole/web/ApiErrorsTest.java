package parity.adminconsole.web;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.List;
import java.util.Set;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.springframework.http.ProblemDetail;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.TestingAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import parity.adminconsole.backend.BackendError;
import parity.adminconsole.backend.BackendException;
import parity.adminconsole.security.Caller;
import parity.adminconsole.security.Role;
import parity.adminconsole.security.TenantNotFoundException;

/** Rule 6: a backend's own message reaches no caller (D2: every caller is a tenant's); 404s look alike. */
class ApiErrorsTest {

    private final ApiErrors errors = new ApiErrors();
    private static BackendException conflict() {
        return new BackendException(BackendException.Kind.CONFLICT,
                new BackendError("conflict", "+15550100101 is on tenant globex", "duplicate_number"));
    }

    @AfterEach
    void clear() {
        SecurityContextHolder.clearContext();
    }

    private static void as(Role role, String tenant) {
        Caller c = new Caller("s", "u", Set.of(role), tenant);
        SecurityContextHolder.getContext().setAuthentication(new TestingAuthenticationToken(c, null, List.of()));
    }

    @Test
    void aTenantAdminGetsTheCodeAndRuleButNotTheBackendsMessage() {
        as(Role.TENANT_ADMIN, "acme");
        ResponseEntity<ProblemDetail> r = errors.backend(conflict());
        assertThat(r.getStatusCode().value()).isEqualTo(409);
        assertThat(r.getBody().getProperties()).containsEntry("code", "conflict").containsEntry("rule", "duplicate_number");
        assertThat(r.getBody().getDetail()).isNull();
    }

    @Test
    void noRoleGetsTheBackendsMessage() {
        for (Role role : Role.values()) {
            as(role, "acme");
            assertThat(errors.backend(conflict()).getBody().getDetail()).as(role.claim()).isNull();
        }
        SecurityContextHolder.clearContext();
        assertThat(errors.backend(conflict()).getBody().getDetail()).isNull();
    }

    @Test
    void aMethodThePathDoesNotTakeIs405NotAnError() {
        ResponseEntity<ProblemDetail> r = errors.noMethod(new org.springframework.web.HttpRequestMethodNotSupportedException("DELETE"));
        assertThat(r.getStatusCode().value()).isEqualTo(405);
        assertThat(r.getBody().getProperties()).containsEntry("code", "method_not_allowed");
    }

    @Test
    void aBackendsNotFoundAndAnOutOfScopeTenantAreTheSameAnswer() {
        as(Role.TENANT_ADMIN, "acme");
        ResponseEntity<ProblemDetail> store = errors.backend(new BackendException(BackendException.Kind.NOT_FOUND,
                new BackendError("not_found", "no tenant globex", null)));
        ResponseEntity<ProblemDetail> scope = errors.notFound(new TenantNotFoundException());
        assertThat(store.getBody()).isEqualTo(scope.getBody());
        assertThat(store.getStatusCode()).isEqualTo(scope.getStatusCode());
    }

    @Test
    void noAnswerInTimeIsNotConfirmed() {
        as(Role.TENANT_ADMIN, "acme");
        ResponseEntity<ProblemDetail> r = errors.backend(new BackendException(BackendException.Kind.NOT_CONFIRMED, (BackendError) null));
        assertThat(r.getStatusCode().value()).isEqualTo(504);
        assertThat(r.getBody().getProperties()).containsEntry("code", "not_confirmed");
    }
}
