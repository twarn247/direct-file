package gov.irs.directfile.models.autoconfigure;

import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

public class EncryptionContextPropertiesTest {

    @Test
    void defaultsToWarnAndValidatesClean() {
        EncryptionContextProperties properties = new EncryptionContextProperties();
        assertThatCode(properties::validate).doesNotThrowAnyException();
        org.assertj.core.api.Assertions.assertThat(properties.isEnforcing()).isFalse();
    }

    @Test
    void acceptsEnforceCaseInsensitively() {
        EncryptionContextProperties properties = new EncryptionContextProperties();
        properties.setContextVerification("ENFORCE");
        assertThatCode(properties::validate).doesNotThrowAnyException();
        org.assertj.core.api.Assertions.assertThat(properties.isEnforcing()).isTrue();
    }

    @Test
    void rejectsAnUnrecognizedValueAtStartup() {
        EncryptionContextProperties properties = new EncryptionContextProperties();
        properties.setContextVerification("enfoce");
        assertThatThrownBy(properties::validate)
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("enfoce");
    }
}
