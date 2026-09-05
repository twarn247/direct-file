package gov.irs.directfile.api.config;

import java.util.List;

import com.google.common.net.InetAddresses;
import jakarta.servlet.http.HttpServletRequest;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.StringUtils;
import org.springframework.security.web.util.matcher.IpAddressMatcher;
import org.springframework.stereotype.Component;

/**
 * Resolves the client address for a request, trusting X-Forwarded-For and True-Client-IP only
 * when the request's immediate peer is a configured trusted proxy.
 *
 * <p>True-Client-IP is additionally gated by trustTrueClientIp, off by default. Unlike
 * X-Forwarded-For -- append-only, so a client-injected prefix is superseded by real hops to its
 * right -- True-Client-IP is a single value with no accumulation. A trusted peer alone does not
 * establish that the peer stripped an inbound, client-supplied copy of the header before setting
 * its own; that is a separate assertion an operator makes explicitly. See {@link
 * ClientIpConfigurationProperties}.
 */
@Slf4j
@Component
public class ClientIpResolver {

    private final List<IpAddressMatcher> trustedProxies;
    private final boolean trustTrueClientIp;

    public ClientIpResolver(ClientIpConfigurationProperties properties) {
        this.trustedProxies = properties.getTrustedProxies().stream()
                .map(String::strip)
                .filter(StringUtils::isNotBlank)
                .map(ClientIpResolver::matcherFor)
                .toList();
        this.trustTrueClientIp = properties.isTrustTrueClientIp();
        if (this.trustedProxies.isEmpty()) {
            log.warn("direct-file.client-ip.trusted-proxies is empty. X-Forwarded-For and True-Client-IP"
                    + " will be ignored and the direct peer address used instead.");
        }
    }

    public String resolve(HttpServletRequest request) {
        String peer = request.getRemoteAddr();

        // Nothing downstream of an untrusted peer may speak for the client.
        if (!isTrustedProxy(peer)) {
            return peer;
        }

        if (trustTrueClientIp) {
            String trueClientIp = request.getHeader(RequestHeaderNames.TRUE_CLIENT_IP);
            if (isIpLiteral(trueClientIp)) {
                return trueClientIp.strip();
            }
        }

        String forwardedFor = request.getHeader(RequestHeaderNames.X_FORWARDED_FOR);
        if (StringUtils.isBlank(forwardedFor)) {
            return peer;
        }

        // Right to left: the rightmost entries were appended by infrastructure we control.
        // Everything left of the first hop we did not append is unverifiable client input.
        String[] hops = forwardedFor.split(",");
        for (int i = hops.length - 1; i >= 0; i--) {
            String hop = hops[i].strip();
            if (!isIpLiteral(hop)) {
                // Cannot evaluate this hop, so cannot trust anything further left either.
                return peer;
            }
            if (!isTrustedProxy(hop)) {
                return hop;
            }
        }

        // Every hop was one of ours.
        return peer;
    }

    private boolean isTrustedProxy(String address) {
        return isIpLiteral(address) && trustedProxies.stream().anyMatch(matcher -> matcher.matches(address.strip()));
    }

    /**
     * Literal-only. Deliberately not InetAddress.getByName, which resolves hostnames via DNS --
     * these values come from request headers, so that would let a crafted header trigger an
     * attacker-chosen outbound DNS query. As of Spring Security 6.5.11, IpAddressMatcher.matches()
     * itself rejects non-IP-literal input via assertNotHostName() before it would ever resolve one,
     * so this guard is now defence-in-depth rather than the sole protection -- kept so the
     * resolver's behavior does not depend on that library internal. Removing it today would
     * surface as an IllegalArgumentException from matches(), not a silent DNS lookup.
     */
    private static boolean isIpLiteral(String value) {
        return StringUtils.isNotBlank(value) && InetAddresses.isInetAddress(value.strip());
    }

    private static IpAddressMatcher matcherFor(String entry) {
        String address = entry.contains("/") ? entry.substring(0, entry.indexOf('/')) : entry;
        if (!InetAddresses.isInetAddress(address)) {
            throw new IllegalStateException("direct-file.client-ip.trusted-proxies contains an entry that is not"
                    + " an IP address or CIDR block: " + entry);
        }
        try {
            return new IpAddressMatcher(entry);
        } catch (IllegalArgumentException e) {
            throw new IllegalStateException(
                    "direct-file.client-ip.trusted-proxies contains an entry that is not"
                            + " an IP address or CIDR block: " + entry,
                    e);
        }
    }
}
