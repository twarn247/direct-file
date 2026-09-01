package gov.irs.directfile.api.authorization;

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

import gov.irs.directfile.api.authorization.config.FeatureFlagConfigurationProperties;
import gov.irs.directfile.api.featureflags.FeatureFlagService;

@Slf4j
@Service
public class EmailAllowlistFeatureService {
    private final FeatureFlagService featureFlagService;

    @Getter
    private final boolean allowlistEnabled;

    private Set<String> allowlist;
    private final String allowListObject;
    private final byte[] hexKey;

    // HMAC-SHA256; a key shorter than the digest adds no strength.
    private static final int MIN_HMAC_KEY_BYTES = 32;

    public EmailAllowlistFeatureService(
            FeatureFlagConfigurationProperties configProps, FeatureFlagService featureFlagService) {
        this.featureFlagService = featureFlagService;
        this.allowlistEnabled = configProps.getAllowlist().enabled();
        this.allowListObject = configProps.getAllowlist().objectKey();
        this.hexKey = decodeKeyIfEnabled(
                this.allowlistEnabled, configProps.getAllowlist().hexKey());
        if (this.allowlistEnabled) {
            // The object key was previously hardcoded and unreachable from configuration. Log the
            // resolved value so an operator can see which object is actually being read. It is an
            // S3 object name, not a secret, and FeatureFlagService already logs it on every fetch.
            log.info("Allowlist is enabled, reading feature object {}", this.allowListObject);
        }
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
            throw new IllegalStateException("direct-file.feature-flags.allowlist.enabled is true but"
                    + " direct-file.feature-flags.allowlist.hex-key is not set."
                    + " Set DF_FEATURE_FLAGS_ALLOWLIST_HEX_KEY.");
        }
        byte[] decoded;
        try {
            decoded = HexFormat.of().parseHex(configuredHexKey);
        } catch (IllegalArgumentException e) {
            throw new IllegalStateException("direct-file.feature-flags.allowlist.hex-key is not valid hexadecimal.", e);
        }
        if (decoded.length < MIN_HMAC_KEY_BYTES) {
            throw new IllegalStateException("direct-file.feature-flags.allowlist.hex-key must decode to at least "
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
        if (!allowlistEnabled) {
            return;
        }
        try {
            this.allowlist = Arrays.stream(featureFlagService
                            .getFeatureObjectAsString(allowListObject)
                            .split("\n"))
                    .collect(Collectors.toSet());
            log.info("Allowlist checked, total items: {}", allowlist.size());
        } catch (Exception e) {
            log.error("Error during allowlist retrieval: {}", e.getMessage());
            this.allowlist = Collections.emptySet();
        }
    }
}
