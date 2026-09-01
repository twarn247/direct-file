package gov.irs.directfile.api.dataimport.gating;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import gov.irs.directfile.api.config.DataImportGatingConfigurationProperties;
import gov.irs.directfile.api.config.DataImportGatingConfigurationProperties.Allowlist;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
public class DataImportGatingEmailAllowlistServiceTest {

    @Mock
    DataImportGatingConfigService dataImportGatingConfigService;

    // Same key and fixtures as EmailAllowlistFeatureServiceTest -- the two services compute
    // an identical HMAC-SHA256 over the lowercased address, so the digests transfer.
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

    private static DataImportGatingConfigurationProperties props(boolean enabled, String hexKey) {
        return new DataImportGatingConfigurationProperties(
                new Allowlist(enabled, hexKey, "data-import-allowlist-export.csv"));
    }

    private DataImportGatingEmailAllowlistService subject(boolean enabled, String hexKey) {
        return new DataImportGatingEmailAllowlistService(props(enabled, hexKey), dataImportGatingConfigService);
    }

    @Test
    public void testEmailOnAllowlist_contains_thenReturnsTrue() {
        when(dataImportGatingConfigService.getDataImportGatingObjectAsString(any()))
                .thenReturn(ALLOWLIST_EXPORT_CSV);

        assertTrue(subject(true, HEX_KEY).emailOnAllowlist("test@example.com"));
    }

    @Test
    public void testEmailOnAllowlist_notContains_thenReturnsFalse() {
        when(dataImportGatingConfigService.getDataImportGatingObjectAsString(any()))
                .thenReturn(ALLOWLIST_EXPORT_CSV);

        assertFalse(subject(true, HEX_KEY).emailOnAllowlist("xxx@example.com"));
    }

    @Test
    public void testEmailOnAllowlist_exception_thenReturnsFalse() {
        when(dataImportGatingConfigService.getDataImportGatingObjectAsString(any()))
                .thenThrow(new RuntimeException());

        assertFalse(subject(true, HEX_KEY).emailOnAllowlist("test@example.com"));
    }

    @Test
    public void allowlistDisabled_thenReturnsFalseAndNeedsNoKey() {
        assertFalse(subject(false, "").emailOnAllowlist("test@example.com"));
    }

    @Test
    public void allowlistEnabledWithNoKey_thenRefusesToStart() {
        IllegalStateException e = assertThrows(IllegalStateException.class, () -> subject(true, ""));
        assertTrue(e.getMessage().contains("DF_DATA_IMPORT_GATING_ALLOWLIST_HEX_KEY"));
    }

    @Test
    public void allowlistEnabledWithNonHexKey_thenRefusesToStart() {
        // Hex.decodeHex used to silently return a zero-length key for this input instead of
        // throwing -- see the constructor's history. It must now refuse to start.
        IllegalStateException e = assertThrows(IllegalStateException.class, () -> subject(true, "zz"));
        assertTrue(e.getMessage().contains("hexadecimal"));
    }

    @Test
    public void allowlistEnabledWithShortKey_thenRefusesToStart() {
        IllegalStateException e = assertThrows(IllegalStateException.class, () -> subject(true, "abcd"));
        assertTrue(e.getMessage().contains("32"));
    }

    @Test
    public void allowlistEnabledIsExposed() {
        assertEquals(true, subject(true, HEX_KEY).isAllowlistEnabled());
        assertEquals(false, subject(false, "").isAllowlistEnabled());
    }
}
