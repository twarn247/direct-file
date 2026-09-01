package gov.irs.directfile.api.dataimport.gating;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Base64;
import java.util.Collections;
import java.util.HexFormat;
import java.util.Set;
import java.util.stream.Collectors;

import lombok.Getter;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.StringUtils;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.macs.HMac;
import org.bouncycastle.crypto.params.KeyParameter;
import org.springframework.stereotype.Service;

import gov.irs.directfile.api.config.DataImportGatingConfigurationProperties;

@Slf4j
@Service
public class DataImportGatingEmailAllowlistService {
    private final DataImportGatingConfigService dataImportGatingConfigService;

    @Getter
    private final boolean allowlistEnabled;

    private Set<String> allowlist;
    private final String allowListObject;
    private final byte[] hexKey;

    // HMAC-SHA256; a key shorter than the digest adds no strength.
    private static final int MIN_HMAC_KEY_BYTES = 32;

    public DataImportGatingEmailAllowlistService(
            DataImportGatingConfigurationProperties configProps,
            DataImportGatingConfigService dataImportGatingConfigService) {
        this.dataImportGatingConfigService = dataImportGatingConfigService;
        this.allowlistEnabled = configProps.getAllowlist().enabled();
        this.allowListObject = configProps.getAllowlist().objectKey();
        this.hexKey = decodeKeyIfEnabled(
                this.allowlistEnabled, configProps.getAllowlist().hexKey());
    }

    // byte[] is not a Collection, but PMD's ReturnEmptyCollectionRatherThanNull rule flags it anyway.
    // An empty array is not a meaningful stand-in for "no key" here, since this value's only
    // consumer (emailMac) is unreachable while the allowlist is disabled -- see below.
    @SuppressWarnings("PMD.ReturnEmptyCollectionRatherThanNull")
    private static byte[] decodeKeyIfEnabled(boolean allowlistEnabled, String configuredHexKey) {
        if (!allowlistEnabled) {
            // emailMac() is unreachable while the allowlist is disabled -- emailOnAllowlist returns
            // early. Requiring a key that is never used would block startup for no benefit.
            return null;
        }
        if (StringUtils.isBlank(configuredHexKey)) {
            throw new IllegalStateException("direct-file.data-import-gating.allowlist.enabled is true but"
                    + " direct-file.data-import-gating.allowlist.hex-key is not set."
                    + " Set DF_DATA_IMPORT_GATING_ALLOWLIST_HEX_KEY.");
        }
        byte[] decoded;
        try {
            decoded = HexFormat.of().parseHex(configuredHexKey);
        } catch (IllegalArgumentException e) {
            throw new IllegalStateException(
                    "direct-file.data-import-gating.allowlist.hex-key is not valid hexadecimal.", e);
        }
        if (decoded.length < MIN_HMAC_KEY_BYTES) {
            throw new IllegalStateException("direct-file.data-import-gating.allowlist.hex-key must decode to at least "
                    + MIN_HMAC_KEY_BYTES + " bytes for HMAC-SHA256.");
        }
        return decoded;
    }

    // determines whether the identity provider-supplied email address is on our allowlist
    public boolean emailOnAllowlist(String email) {
        if (allowlistEnabled) {
            loadAllowlist(); // trigger cache reload if needed
            String base64Mac = emailMac(email);
            return allowlist.contains(base64Mac);
        }

        // allowlist disabled
        log.info("Allowlist is disabled, so emailOnAllowlist is false");
        return false;
    }

    private String emailMac(String email) {
        HMac hMac = new HMac(new SHA256Digest());
        hMac.init(new KeyParameter(hexKey));
        byte[] in = StringUtils.lowerCase(email).getBytes(StandardCharsets.UTF_8);
        hMac.update(in, 0, in.length);
        byte[] hMacOut = new byte[hMac.getMacSize()];
        hMac.doFinal(hMacOut, 0);
        return Base64.getEncoder().encodeToString(hMacOut);
    }

    private void loadAllowlist() {
        try {
            this.allowlist = Arrays.stream(dataImportGatingConfigService
                            .getDataImportGatingObjectAsString(allowListObject)
                            .split("\n"))
                    .collect(Collectors.toSet());
            log.info("Allowlist checked, total items: {}", allowlist.size());
        } catch (Exception e) {
            // should we set up an alert on this error?
            log.error("Error during allowlist retrieval: {}", e.getMessage());
            this.allowlist = Collections.emptySet();
        }
    }
}
