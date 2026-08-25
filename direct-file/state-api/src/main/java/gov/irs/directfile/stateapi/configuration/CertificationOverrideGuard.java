package gov.irs.directfile.stateapi.configuration;

import java.util.Arrays;
import java.util.List;

import jakarta.annotation.PostConstruct;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.StringUtils;
import org.springframework.core.env.Environment;
import org.springframework.stereotype.Component;

/**
 * direct-file.cert-location-override replaces the certificate for EVERY state at once
 * and synthesizes an expiration of now + 1 year, bypassing both the certificate's own
 * notAfter and the IRS-enforced cert_expiration_date. It is a lower-environment
 * convenience. This guard refuses to start the application if it is set anywhere the
 * profile is not recognizably non-production.
 */
@Component
@Slf4j
public class CertificationOverrideGuard {

    private static final List<String> NON_PRODUCTION_PROFILES =
            List.of("development", "docker", "debug", "test", "integration-test");

    private final CertificationOverrideProperties properties;
    private final Environment environment;

    public CertificationOverrideGuard(CertificationOverrideProperties properties, Environment environment) {
        this.properties = properties;
        this.environment = environment;
    }

    @PostConstruct
    public void verifyOverrideNotSetInProduction() {
        String override = properties.getCertLocationOverride();
        if (StringUtils.isBlank(override)) {
            return;
        }

        String[] activeProfiles = environment.getActiveProfiles();
        boolean recognisedNonProduction = Arrays.stream(activeProfiles).anyMatch(NON_PRODUCTION_PROFILES::contains);

        if (!recognisedNonProduction) {
            throw new IllegalStateException(
                    "direct-file.cert-location-override is set (" + override
                            + ") but no non-production profile is active (active: " + Arrays.toString(activeProfiles)
                            + "). This override replaces every state's certificate and bypasses expiration. Refusing to start.");
        }

        log.warn(
                "direct-file.cert-location-override is set to {}. Every state's certificate is overridden and expiration is bypassed. This must never be set in production.",
                override);
    }
}
