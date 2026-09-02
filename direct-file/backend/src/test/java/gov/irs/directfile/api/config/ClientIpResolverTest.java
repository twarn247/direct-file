package gov.irs.directfile.api.config;

import java.util.List;

import jakarta.servlet.http.HttpServletRequest;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

public class ClientIpResolverTest {

    private static final String EDGE_CIDR = "203.0.113.0/24";
    private static final String INTERNAL_CIDR = "10.0.0.0/8";

    private static ClientIpResolver resolver(String... trustedProxies) {
        return new ClientIpResolver(new ClientIpConfigurationProperties(List.of(trustedProxies)));
    }

    private static HttpServletRequest request(String peer, String trueClientIp, String forwardedFor) {
        HttpServletRequest request = mock(HttpServletRequest.class);
        when(request.getRemoteAddr()).thenReturn(peer);
        when(request.getHeader(RequestHeaderNames.TRUE_CLIENT_IP)).thenReturn(trueClientIp);
        when(request.getHeader(RequestHeaderNames.X_FORWARDED_FOR)).thenReturn(forwardedFor);
        return request;
    }

    @Test
    void withNoTrustedProxiesConfigured_ignoresBothHeaders() {
        // The default posture. A deployment opts in to header trust; it does not opt out.
        ClientIpResolver subject = resolver();

        assertThat(subject.resolve(request("198.51.100.7", "1.2.3.4", "5.6.7.8, 9.10.11.12")))
                .isEqualTo("198.51.100.7");
    }

    @Test
    void whenPeerIsNotATrustedProxy_ignoresBothHeaders() {
        ClientIpResolver subject = resolver(EDGE_CIDR);

        assertThat(subject.resolve(request("198.51.100.7", "1.2.3.4", "5.6.7.8")))
                .isEqualTo("198.51.100.7");
    }

    @Test
    void whenPeerIsTrusted_prefersTrueClientIp() {
        ClientIpResolver subject = resolver(EDGE_CIDR);

        assertThat(subject.resolve(request("203.0.113.5", "1.2.3.4", "5.6.7.8")))
                .isEqualTo("1.2.3.4");
    }

    @Test
    void whenPeerIsTrusted_walksForwardedForRightToLeft() {
        ClientIpResolver subject = resolver(EDGE_CIDR, INTERNAL_CIDR);

        // client, then two hops we appended ourselves.
        assertThat(subject.resolve(request("203.0.113.5", null, "198.51.100.7, 10.1.1.1, 203.0.113.9")))
                .isEqualTo("198.51.100.7");
    }

    @Test
    void whenPeerIsTrusted_aSpoofedPrefixIsNotReturned() {
        // The defect this task exists to fix. A client sending
        //   X-Forwarded-For: 1.2.3.4
        // has that value appended to, not replaced -- so the header the backend sees is
        // "1.2.3.4, <real client>, <our proxy>". Reading left-to-right returns the spoof.
        ClientIpResolver subject = resolver(EDGE_CIDR, INTERNAL_CIDR);

        assertThat(subject.resolve(request("203.0.113.5", null, "1.2.3.4, 198.51.100.7, 10.1.1.1")))
                .isEqualTo("198.51.100.7");
    }

    @Test
    void whenEveryForwardedForHopIsTrusted_fallsBackToPeer() {
        ClientIpResolver subject = resolver(EDGE_CIDR, INTERNAL_CIDR);

        assertThat(subject.resolve(request("203.0.113.5", null, "10.1.1.1, 203.0.113.9")))
                .isEqualTo("203.0.113.5");
    }

    @Test
    void whenAForwardedForHopIsMalformed_stopsAndFallsBackToPeer() {
        // Everything left of an unparseable hop is unverifiable.
        ClientIpResolver subject = resolver(EDGE_CIDR, INTERNAL_CIDR);

        assertThat(subject.resolve(request("203.0.113.5", null, "198.51.100.7, not-an-ip, 10.1.1.1")))
                .isEqualTo("203.0.113.5");
    }

    @Test
    void aHostnameInAHeaderIsNeverResolved() {
        // IpAddressMatcher.matches() would DNS-resolve this on Spring Security 6.3.
        // The literal guard must reject it before it reaches the matcher.
        ClientIpResolver subject = resolver(EDGE_CIDR);

        assertThat(subject.resolve(request("203.0.113.5", "attacker.example.com", null)))
                .isEqualTo("203.0.113.5");
    }

    @Test
    void whenPeerIsTrustedAndNoHeadersArePresent_returnsPeer() {
        ClientIpResolver subject = resolver(EDGE_CIDR);

        assertThat(subject.resolve(request("203.0.113.5", null, null))).isEqualTo("203.0.113.5");
    }

    @Test
    void supportsIpv6TrustedProxies() {
        ClientIpResolver subject = resolver("2001:db8::/32");

        assertThat(subject.resolve(request("2001:db8::1", "198.51.100.7", null)))
                .isEqualTo("198.51.100.7");
    }

    @Test
    void aBareAddressIsAValidTrustedProxyEntry() {
        ClientIpResolver subject = resolver("203.0.113.5");

        assertThat(subject.resolve(request("203.0.113.5", "198.51.100.7", null)))
                .isEqualTo("198.51.100.7");
    }

    @Test
    void aMalformedTrustedProxyEntryRefusesToStart() {
        assertThatThrownBy(() -> resolver("not-a-cidr"))
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("direct-file.client-ip.trusted-proxies");
    }

    @Test
    void aHostnameTrustedProxyEntryRefusesToStart() {
        // Configuration is not a place for names that resolve differently over time.
        assertThatThrownBy(() -> resolver("edge.example.com"))
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("direct-file.client-ip.trusted-proxies");
    }
}
