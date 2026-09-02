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
 *
 * <p>trustedProxies alone does not make True-Client-IP safe to trust. X-Forwarded-For is
 * append-only -- each hop appends the address it observed, so a client-injected prefix is
 * superseded by real hops to its right, and the right-to-left walk in {@link ClientIpResolver}
 * finds the genuine address regardless. True-Client-IP has no such structure: it is a single
 * value with no accumulation, so nothing distinguishes an edge-set copy from a client-set one
 * the edge simply passed through. trustTrueClientIp is therefore a separate, false-by-default
 * assertion that the configured edge strips or overwrites any inbound client-supplied
 * True-Client-IP header before setting its own -- not something trustedProxies implies.
 */
@Validated
@ConfigurationProperties(prefix = "direct-file.client-ip")
@Getter
@AllArgsConstructor
public class ClientIpConfigurationProperties {
    @NotNull private final List<String> trustedProxies;

    private final boolean trustTrueClientIp;
}
