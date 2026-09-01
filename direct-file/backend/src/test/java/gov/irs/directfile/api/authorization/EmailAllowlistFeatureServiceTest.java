package gov.irs.directfile.api.authorization;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import gov.irs.directfile.api.authorization.config.FeatureFlagConfigurationProperties;
import gov.irs.directfile.api.authorization.config.FeatureFlagConfigurationProperties.Allowlist;
import gov.irs.directfile.api.authorization.config.FeatureFlagConfigurationProperties.OpenEnrollment;
import gov.irs.directfile.api.featureflags.FeatureFlagService;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
public class EmailAllowlistFeatureServiceTest {

    @Mock
    FeatureFlagService featureFlagService;

    // Same key and fixtures as DataImportGatingEmailAllowlistServiceTest -- the two services
    // compute an identical HMAC-SHA256 over the lowercased address, so the digests transfer.
    private static final String HEX_KEY = "c6b27cc233024f50dd90a826dc7ae79936c29a599791b14cd0eb0e48e1d5cfff";

    // test@example.com
    // example2@example.com
    // EXAMPLE3@EXAMPLE.COM
    private static final String ALLOWLIST_EXPORT_CSV =
            """
			9bO/RaqAl1I4aeexSsadrHOkxKfiWNhpItXFc5KmIrs=
			Zq5rD40EW55DnI35KYdK7f+u16lblwn+8H3YUdrxWsw=
			9yO0gpET8JXfw45WC84bm4K2x7lXUo+CVmgTcv7/KzU=
			""";

    private static FeatureFlagConfigurationProperties props(boolean enabled, String hexKey) {
        return new FeatureFlagConfigurationProperties(
                new Allowlist(enabled, hexKey, "allowlist-export.csv"), new OpenEnrollment(true));
    }

    private EmailAllowlistFeatureService subject(boolean enabled, String hexKey) {
        return new EmailAllowlistFeatureService(props(enabled, hexKey), featureFlagService);
    }

    @Test
    public void emailOnAllowlist_contains_thenReturnsTrue() {
        when(featureFlagService.getFeatureObjectAsString(any())).thenReturn(ALLOWLIST_EXPORT_CSV);

        assertTrue(subject(true, HEX_KEY).emailOnAllowlist("test@example.com"));
    }

    @Test
    public void emailOnAllowlist_notContains_thenReturnsFalse() {
        when(featureFlagService.getFeatureObjectAsString(any())).thenReturn(ALLOWLIST_EXPORT_CSV);

        assertFalse(subject(true, HEX_KEY).emailOnAllowlist("xxx@example.com"));
    }

    @Test
    public void emailOnAllowlist_retrievalThrows_thenReturnsFalse() {
        when(featureFlagService.getFeatureObjectAsString(any())).thenThrow(new RuntimeException());

        assertFalse(subject(true, HEX_KEY).emailOnAllowlist("test@example.com"));
    }

    @Test
    public void allowlistDisabled_thenReturnsFalseAndNeedsNoKey() {
        assertFalse(subject(false, "").emailOnAllowlist("test@example.com"));
    }

    @Test
    public void allowlistEnabledWithNoKey_thenRefusesToStart() {
        IllegalStateException e = assertThrows(IllegalStateException.class, () -> subject(true, ""));
        assertTrue(e.getMessage().contains("DF_FEATURE_FLAGS_ALLOWLIST_HEX_KEY"));
    }

    @Test
    public void allowlistEnabledWithNonHexKey_thenRefusesToStart() {
        // "key" is the literal the hardcoded constructor used to supply. It is not hexadecimal.
        IllegalStateException e = assertThrows(IllegalStateException.class, () -> subject(true, "key"));
        assertTrue(e.getMessage().contains("hexadecimal"));
    }

    @Test
    public void allowlistEnabledWithShortKey_thenRefusesToStart() {
        IllegalStateException e = assertThrows(IllegalStateException.class, () -> subject(true, "abcd"));
        assertTrue(e.getMessage().contains("32"));
    }

    @Test
    public void configuredObjectKeyIsTheOneFetched() {
        when(featureFlagService.getFeatureObjectAsString("allowlist-export.csv"))
                .thenReturn(ALLOWLIST_EXPORT_CSV);

        assertTrue(subject(true, HEX_KEY).emailOnAllowlist("example2@example.com"));
    }

    @Test
    public void allowlistEnabledIsExposed() {
        assertEquals(true, subject(true, HEX_KEY).isAllowlistEnabled());
        assertEquals(false, subject(false, "").isAllowlistEnabled());
    }
}
