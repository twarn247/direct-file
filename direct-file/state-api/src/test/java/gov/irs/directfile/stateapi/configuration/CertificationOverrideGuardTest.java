package gov.irs.directfile.stateapi.configuration;

import org.junit.jupiter.api.Test;
import org.springframework.mock.env.MockEnvironment;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertThrows;

public class CertificationOverrideGuardTest {

    private CertificationOverrideGuard guard(String override, String... activeProfiles) {
        MockEnvironment env = new MockEnvironment();
        env.setActiveProfiles(activeProfiles);
        return new CertificationOverrideGuard(new CertificationOverrideProperties(override), env);
    }

    @Test
    public void allowsOverrideInDevelopment() {
        assertDoesNotThrow(() -> guard("fakestate.cer", "development").verifyOverrideNotSetInProduction());
    }

    @Test
    public void allowsOverrideInIntegrationTest() {
        assertDoesNotThrow(
                () -> guard("fakestate.cer", "development", "integration-test").verifyOverrideNotSetInProduction());
    }

    @Test
    public void rejectsOverrideUnderAnUnrecognizedProfile() {
        assertThrows(IllegalStateException.class, () -> guard("fakestate.cer", "prod")
                .verifyOverrideNotSetInProduction());
    }

    @Test
    public void rejectsOverrideWithNoActiveProfile() {
        assertThrows(IllegalStateException.class, () -> guard("fakestate.cer").verifyOverrideNotSetInProduction());
    }

    @Test
    public void allowsBlankOverrideAnywhere() {
        assertDoesNotThrow(() -> guard("", "prod").verifyOverrideNotSetInProduction());
        assertDoesNotThrow(() -> guard(null, "prod").verifyOverrideNotSetInProduction());
    }
}
