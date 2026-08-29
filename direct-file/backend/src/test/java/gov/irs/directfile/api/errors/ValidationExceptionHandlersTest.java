package gov.irs.directfile.api.errors;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.web.method.HandlerMethod;

import gov.irs.directfile.api.audit.AuditService;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;

/**
 * Guards M-4 on the path server.error.include-message does not reach: TaxReturnController's
 * unexpected failures are funnelled through `new RuntimeException(e)`, whose message becomes
 * `e.toString()` -- the wrapped exception's own class name and detail. This advice intercepts
 * that exception before any /error forward happens, so the include-message setting never
 * governs it; ErrorMessageExposureTest greps application.yaml and would stay green regardless
 * of whether this path leaks. This test exercises the actual code path instead.
 */
@ExtendWith(MockitoExtension.class)
class ValidationExceptionHandlersTest {

    @InjectMocks
    private ValidationExceptionHandlers handlers;

    @Mock
    private AuditService auditService;

    @Test
    void handleUnhandledException_doesNotLeakTheWrappedExceptionsMessage() {
        RuntimeException driverFailure = new RuntimeException(
                "org.postgresql.util.PSQLException: FATAL: password authentication failed for user \"df_app\"");
        RuntimeException wrapped = new RuntimeException(driverFailure);
        HandlerMethod handlerMethod = mock(HandlerMethod.class);

        ValidationExceptionHandlers.ErrorResponse response = handlers.handleUnhandledException(wrapped, handlerMethod);

        assertThat(response.message()).doesNotContain("PSQLException", "password authentication");
        assertThat(response.errors().values())
                .as("the errors map must not carry the wrapped exception's message")
                .noneMatch(value -> value.contains("PSQLException") || value.contains("password authentication"));
    }
}
