package gov.irs.directfile.api.authorization.config;

import jakarta.validation.constraints.NotNull;
import lombok.AllArgsConstructor;
import lombok.Getter;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.validation.annotation.Validated;

// Mirrors gov.irs.directfile.api.config.DataImportGatingConfigurationProperties. This class
// previously carried @Component and a no-arg constructor that hardcoded
// new Allowlist(false, "key", "allowlist.csv") -- all three values stubs left over from the
// key-loading code being stripped for public release, and none of them read from YAML.
// Note: gov.irs.directfile.api.featureflags.FeatureFlagConfigurationProperties is a different
// class with the same simple name, bound to direct-file.aws.s3.
@Validated
@ConfigurationProperties(prefix = "direct-file.feature-flags")
@Getter
@AllArgsConstructor
public class FeatureFlagConfigurationProperties {
    @NotNull private final Allowlist allowlist;

    @NotNull private final OpenEnrollment openEnrollment;

    public record OpenEnrollment(@NotNull boolean enabled) {}

    public record Allowlist(@NotNull boolean enabled, @NotNull String hexKey, @NotNull String objectKey) {}
}
