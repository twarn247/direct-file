package gov.irs.directfile.api.errors;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;

import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Guards M-4. server.error.include-message controls whether Spring copies the exception
 * message into the JSON error body. TaxReturnController funnels unexpected failures
 * through `throw new RuntimeException(e)`, so with `always` the underlying driver or
 * persistence message reaches the caller.
 */
class ErrorMessageExposureTest {

    @Test
    void applicationYamlDoesNotIncludeExceptionMessagesInErrorResponses() throws IOException {
        String applicationYaml =
                Files.readString(Path.of("src/main/resources/application.yaml"), StandardCharsets.UTF_8);

        assertThat(applicationYaml)
                .as("server.error.include-message must not be 'always' -- it leaks exception "
                        + "messages to API clients")
                .doesNotContain("include-message: always");
        assertThat(applicationYaml).contains("include-message: never");
    }
}
