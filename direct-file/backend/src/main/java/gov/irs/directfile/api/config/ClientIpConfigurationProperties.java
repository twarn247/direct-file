package gov.irs.directfile.api.config;

import java.util.List;

import jakarta.validation.constraints.NotNull;
import lombok.AllArgsConstructor;
import lombok.Getter;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.validation.annotation.Validated;

/**
 * Which upstream hops are allowed to speak for a client's address. Empty by default: with no
 * trusted proxies configured, X-Forwarded-For and True-Client-IP are ignored entirely and the
 * direct peer address is used. A deployment opts in to header trust; it does not opt out.
 */
@Validated
@ConfigurationProperties(prefix = "direct-file.client-ip")
@Getter
@AllArgsConstructor
public class ClientIpConfigurationProperties {
    @NotNull private final List<String> trustedProxies;
}
