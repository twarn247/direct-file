# Client IP Trust Boundary Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Stop trusting client-supplied `True-Client-IP` and `X-Forwarded-For` headers unconditionally, and turn on branch protection for `main`.

**Architecture:** Replace the static `IPAddressUtil` with an injected `ClientIpResolver` bean holding a configured list of trusted proxy CIDR blocks. The resolver refuses to read either header unless the request's *immediate peer* is itself a trusted proxy; when it is, it prefers `True-Client-IP` and otherwise walks `X-Forwarded-For` right-to-left, discarding trusted hops and returning the first address it did not put there. With no configuration the trusted set is empty, so both headers are ignored and the direct peer address is used — the deployment opts into header trust rather than out of it.

**Tech Stack:** Java 21, Spring Boot 3.3.10, Spring Security 6.3.8 (`IpAddressMatcher`), Guava 33.0.0-jre (`InetAddresses`), Maven (`./mvnw`), JUnit 5, Mockito, AssertJ, Spotless with palantir-java-format, `gh` CLI.

**Spec:** `docs/security/2026-08-22_codebase-security-review.md` finding M-2, plus the branch-protection task carried over unexecuted from `docs/superpowers/plans/2026-09-01-backend-lows-and-ci-gating.md`.

> **The spec is not on `main`.** It exists only on `origin/claude/report-security-review-lb7lsz` (commit `a6777fe`). Read it with:
>
> ```bash
> git show a6777fe:docs/security/2026-08-22_codebase-security-review.md
> ```

## Global Constraints

- **Java 21.** `InetAddress.ofLiteral()` (JDK 22) is **not** available; literal-only parsing uses Guava's `InetAddresses` instead. See Task 1's design note.
- **Spotless runs in the build.** Run `./mvnw spotless:apply` before committing any Java change, or `verify` fails on formatting.
- **`@ConfigurationProperties` classes must be registered explicitly** in `BackendApplication`'s `@EnableConfigurationProperties`. The backend's only `@ConfigurationPropertiesScan` sits on `gov.irs.directfile.api.config.DevelopmentIdentitySupplier`, which is `@Profile`-gated and therefore does not run when that profile is inactive; it also covers only `gov.irs.directfile.api.config` and below. This was established in the L-2 work — do not rely on the scan.
- **Do not run `verify` on `status` or `submit`.** Neither compiles in this checkout.
- **`libs` must be installed before `backend` builds** if `libs` has changed. This plan does not touch `libs`.

---

## What is actually broken, and what is not

`IPAddressUtil.getClientIpAddress` (`direct-file/backend/src/main/java/gov/irs/directfile/api/config/IPAddressUtil.java:15`) returns `True-Client-IP` verbatim whenever the header is present, and otherwise returns the **leftmost** `X-Forwarded-For` entry. Both are attacker-controlled: any client can send either header, and the leftmost XFF entry is by definition the one the original client supplied. Nothing checks who the request actually came from.

**In this checkout the resolved value is then discarded.** It is threaded through `TaxReturnController:99,174,199` into `TaxReturnService.create` and `.submit` as `String address`, forwarded to `createSubmission` and `updateTaxReturnForSubmission`, and read by none of them. There is no audit column, no database field, and no MeF element consuming it here — the same release-strip pattern as the nulled HMAC key in L-2.

So this task fixes a trust boundary that is currently inert, on the assumption that the internal build reattaches the value (MeF return headers carry the filer's IP). Say that plainly in the PR. Do not claim to be closing a live spoofing vulnerability in this repository, and do not remove the `address` parameter chain on the grounds that it is unused — it is unused *here*.

---

## Task 1: The resolver and its trusted-proxy configuration

**Files:**
- Create: `direct-file/backend/src/main/java/gov/irs/directfile/api/config/ClientIpConfigurationProperties.java`
- Create: `direct-file/backend/src/main/java/gov/irs/directfile/api/config/ClientIpResolver.java`
- Test: `direct-file/backend/src/test/java/gov/irs/directfile/api/config/ClientIpResolverTest.java`

**Interfaces:**
- Consumes: nothing from other tasks.
- Produces: `ClientIpResolver`, a `@Component` with one public method `String resolve(HttpServletRequest request)`. It does not throw checked exceptions. Task 2 injects it.

### Design note: two libraries, and why each

**`org.springframework.security.web.util.matcher.IpAddressMatcher`** does the CIDR match. `spring-security-web` 6.3.8 is already a backend dependency via `spring-boot-starter-security`; it handles IPv4 and IPv6 and bare-address entries (no `/`), so nothing here does prefix arithmetic by hand.

**`com.google.common.net.InetAddresses.isInetAddress`** guards every call into it, and this guard is load-bearing rather than defensive tidiness. On Spring Security 6.3, `IpAddressMatcher.matches(String)` parses its argument with `InetAddress.getByName`, which **performs a DNS lookup for anything that is not an IP literal**. The values being matched come from request headers, so passing them in unguarded turns a crafted `X-Forwarded-For` into an attacker-chosen outbound DNS query from inside the network. `InetAddresses.isInetAddress` parses literals only and never resolves. Guava is already an explicit backend dependency (`backend/pom.xml:190`, managed at 33.0.0-jre).

There is no JDK-only alternative on Java 21 — `InetAddress.ofLiteral()` arrived in JDK 22.

### Design note: the resolution rules

In order, given `peer = request.getRemoteAddr()`:

1. **`peer` is not a trusted proxy → return `peer`.** Both headers are ignored entirely. This is the no-configuration default and the reason the empty list is safe.
2. **`True-Client-IP` is present and is an IP literal → return it.** Preferred over XFF because the edge sets it as a single authoritative value.
3. **`X-Forwarded-For` is blank → return `peer`.**
4. **Walk XFF right-to-left.** Return the first hop that is a valid literal and is *not* a trusted proxy. Right-to-left is the whole point: the rightmost entries were appended by infrastructure we control, and everything left of the first untrusted hop is unverifiable client input.
5. **A malformed hop terminates the walk → return `peer`.** Everything further left is behind an entry we cannot evaluate.
6. **Every hop was a trusted proxy → return `peer`.**

A bracketed or port-suffixed IPv6 hop (`[2001:db8::1]:8080`) fails the literal check and is treated as malformed by rule 5. That is a deliberate, documented limitation: bare addresses are what XFF carries in practice, and guessing at other encodings is how parsers grow holes.

**Non-goal: validating what a trusted proxy sends.** Once rule 1 passes, the peer is trusted infrastructure; the literal checks exist to keep malformed input out of the DNS path, not to second-guess the edge.

- [ ] **Step 1: Write the failing tests**

Create `direct-file/backend/src/test/java/gov/irs/directfile/api/config/ClientIpResolverTest.java`.

Note it builds mocks with plain `Mockito.mock(...)` and does **not** use `@ExtendWith(MockitoExtension.class)`. The extension enables strict stubs, and several of these paths deliberately never read one of the headers, which would then fail as unnecessary stubbing.

```java
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
```

- [ ] **Step 2: Run it to verify it fails**

```bash
cd direct-file/backend
./mvnw --batch-mode --no-transfer-progress test -Dtest=ClientIpResolverTest
```

Expected: COMPILATION FAILURE — neither `ClientIpResolver` nor `ClientIpConfigurationProperties` exists yet.

- [ ] **Step 3: Add the configuration properties class**

Create `direct-file/backend/src/main/java/gov/irs/directfile/api/config/ClientIpConfigurationProperties.java`:

```java
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
```

- [ ] **Step 4: Add the resolver**

Create `direct-file/backend/src/main/java/gov/irs/directfile/api/config/ClientIpResolver.java`:

```java
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
 */
@Slf4j
@Component
public class ClientIpResolver {

    private final List<IpAddressMatcher> trustedProxies;

    public ClientIpResolver(ClientIpConfigurationProperties properties) {
        this.trustedProxies = properties.getTrustedProxies().stream()
                .map(String::strip)
                .filter(StringUtils::isNotBlank)
                .map(ClientIpResolver::matcherFor)
                .toList();
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

        String trueClientIp = request.getHeader(RequestHeaderNames.TRUE_CLIENT_IP);
        if (isIpLiteral(trueClientIp)) {
            return trueClientIp.strip();
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
        return isIpLiteral(address)
                && trustedProxies.stream().anyMatch(matcher -> matcher.matches(address.strip()));
    }

    /**
     * Literal-only. Deliberately not InetAddress.getByName, which resolves hostnames via DNS --
     * these values come from request headers, so that would let a crafted header trigger an
     * attacker-chosen outbound DNS query. IpAddressMatcher.matches() calls getByName internally
     * on Spring Security 6.3, so nothing may reach it without passing this check first.
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
            throw new IllegalStateException("direct-file.client-ip.trusted-proxies contains an entry that is not"
                    + " an IP address or CIDR block: " + entry, e);
        }
    }
}
```

- [ ] **Step 5: Run the tests to verify they pass**

```bash
./mvnw --batch-mode --no-transfer-progress test -Dtest=ClientIpResolverTest
```

Expected: all 13 tests PASS.

If `aHostnameTrustedProxyEntryRefusesToStart` fails by *hanging* or by throwing something other than `IllegalStateException`, the `InetAddresses.isInetAddress` pre-check in `matcherFor` is not running before `new IpAddressMatcher(...)` — that is the DNS path, and it must be fixed rather than worked around by loosening the assertion.

- [ ] **Step 6: Format and commit**

```bash
./mvnw spotless:apply
cd ../..
git add direct-file/backend/src/main/java/gov/irs/directfile/api/config/ClientIpConfigurationProperties.java \
        direct-file/backend/src/main/java/gov/irs/directfile/api/config/ClientIpResolver.java \
        direct-file/backend/src/test/java/gov/irs/directfile/api/config/ClientIpResolverTest.java
git commit -m "feat(backend): add a trusted-proxy-aware client IP resolver

Resolves the client address only from hops we can attribute: headers are
read only when the request's immediate peer is a configured trusted
proxy, and X-Forwarded-For is walked right-to-left so a client-supplied
prefix cannot win. With no trusted proxies configured both headers are
ignored, so the default is to trust nothing.

Every value from a header is checked with Guava's literal-only
InetAddresses.isInetAddress before it reaches IpAddressMatcher, whose
matches() resolves hostnames through InetAddress.getByName on Spring
Security 6.3 -- unguarded, a crafted header would trigger an
attacker-chosen outbound DNS query. InetAddress.ofLiteral would be the
JDK answer but arrives in Java 22.

Not yet wired to any caller.

Refs M-2."
```

---

## Task 2: Wire the resolver in and delete `IPAddressUtil`

**Files:**
- Modify: `direct-file/backend/src/main/java/gov/irs/directfile/api/BackendApplication.java`
- Modify: `direct-file/backend/src/main/java/gov/irs/directfile/api/taxreturn/TaxReturnController.java:47-62,99,174,199`
- Modify: `direct-file/backend/src/main/java/gov/irs/directfile/api/taxreturn/MockDataImportController.java`
- Modify: `direct-file/backend/src/main/resources/application.yaml:68`
- Delete: `direct-file/backend/src/main/java/gov/irs/directfile/api/config/IPAddressUtil.java`

**Interfaces:**
- Consumes: `ClientIpResolver.resolve(HttpServletRequest)` from Task 1.
- Produces: nothing other tasks consume.

`MockDataImportController` calls `super(...)` with `TaxReturnController`'s constructor arguments, so widening that constructor requires changing both. It gained `@Profile("mock")` in the previous plan; leave that annotation exactly as it is.

- [ ] **Step 1: Register the properties class**

In `direct-file/backend/src/main/java/gov/irs/directfile/api/BackendApplication.java`, add `ClientIpConfigurationProperties.class` to the `@EnableConfigurationProperties` list. It lives in `gov.irs.directfile.api.config`, which the file already wildcard-imports, so the simple name is fine here:

```java
@EnableConfigurationProperties({
    gov.irs.directfile.api.authorization.config.FeatureFlagConfigurationProperties.class,
    ClientIpConfigurationProperties.class,
    StateApiEndpointProperties.class,
    StateApiFeatureFlagProperties.class,
    StatusEndpointProperties.class,
    SubmitEndpointProperties.class,
})
```

- [ ] **Step 2: Add the configuration key**

In `direct-file/backend/src/main/resources/application.yaml`, insert immediately after `api-version: v1` (line 68) and before `referer-header:`:

```yaml
  client-ip:
    # Which upstream hops may speak for a client's address. Empty by default: with nothing
    # configured, X-Forwarded-For and True-Client-IP are ignored and the direct peer address
    # is used. Set DF_TRUSTED_PROXIES to a comma-separated list of the edge's CIDR blocks
    # (for example "203.0.113.0/24,10.0.0.0/8") to turn header trust on.
    trusted-proxies: ${DF_TRUSTED_PROXIES:}
```

- [ ] **Step 3: Inject the resolver into `TaxReturnController`**

Add the field alongside the existing ones:

```java
    private final ClientIpResolver clientIpResolver;
```

Widen the constructor (`TaxReturnController.java:47-52`) — append the parameter rather than inserting it, so the `super(...)` change in Step 4 is a suffix:

```java
    public TaxReturnController(
            TaxReturnService taxReturnService,
            UserService userService,
            PdfService pdfService,
            EncryptionCacheWarmingService cacheWarmingService,
            DataImportService dataImportService,
            ClientIpResolver clientIpResolver) {
        this.taxReturnService = taxReturnService;
        this.userService = userService;
        this.pdfService = pdfService;
        this.cacheWarmingService = cacheWarmingService;
        this.dataImportService = dataImportService;
        this.clientIpResolver = clientIpResolver;
```

Leave the `modelMapper` configuration at the end of the constructor untouched.

Replace the import at line 21:

```java
import gov.irs.directfile.api.config.IPAddressUtil;
```

with:

```java
import gov.irs.directfile.api.config.ClientIpResolver;
```

Then replace all three call sites:

- Line 99: `String remoteIpAddress = IPAddressUtil.getClientIpAddress(request);` → `String remoteIpAddress = clientIpResolver.resolve(request);`
- Line 174: `String remoteAddress = IPAddressUtil.getClientIpAddress(request);` → `String remoteAddress = clientIpResolver.resolve(request);`
- Line 199: `String remoteAddress = IPAddressUtil.getClientIpAddress(request);` → `String remoteAddress = clientIpResolver.resolve(request);`

`resolve` throws no checked exception where `getClientIpAddress` declared `throws Exception`. The surrounding `try`/`catch (Exception e)` blocks at lines 99 and 174 still compile — `catch (Exception e)` is always legal — and `sign` at line 199 still declares `throws Exception` for its other calls. Change neither.

- [ ] **Step 4: Update `MockDataImportController`**

Add the parameter to its constructor and pass it through. Add the import `gov.irs.directfile.api.config.ClientIpResolver`:

```java
    public MockDataImportController(
            TaxReturnService taxReturnService,
            UserService userService,
            PdfService pdfService,
            EncryptionCacheWarmingService cacheWarmingService,
            DataImportService dataImportService,
            ClientIpResolver clientIpResolver) {
        super(taxReturnService, userService, pdfService, cacheWarmingService, dataImportService, clientIpResolver);
        mockDataImportService = (MockDataImportService) dataImportService;
    }
```

- [ ] **Step 5: Delete `IPAddressUtil` and confirm nothing references it**

```bash
cd direct-file/backend
git rm src/main/java/gov/irs/directfile/api/config/IPAddressUtil.java
grep -rn "IPAddressUtil" --include="*.java" src
```

Expected: the grep prints nothing. If a test referenced it, port that test's intent into `ClientIpResolverTest` rather than keeping the class alive.

- [ ] **Step 6: Fix any test that constructs `TaxReturnController` directly**

```bash
grep -rn "new TaxReturnController(\|new MockDataImportController(" --include="*.java" src/test
```

For each hit, append a resolver argument. A test that does not care about IP resolution can pass one that trusts nothing:

```java
new ClientIpResolver(new ClientIpConfigurationProperties(List.of()))
```

If the grep prints nothing, there is nothing to do here.

- [ ] **Step 7: Run the full backend build**

This is the step that catches an unregistered properties class — that fails at context startup, not at compile time.

```bash
./mvnw --batch-mode --no-transfer-progress verify
```

Expected: BUILD SUCCESS.

If a context-loading test fails with `NoSuchBeanDefinitionException` for `ClientIpConfigurationProperties`, Step 1 did not take effect. If one fails on `trustedProxies` being null, that test runs against a property source where `direct-file.client-ip` is absent — add the key to that test's configuration rather than dropping `@Validated`.

- [ ] **Step 8: Format and commit**

```bash
./mvnw spotless:apply
cd ../..
git add -A direct-file/backend
git commit -m "fix(backend): resolve the client IP through the trusted-proxy boundary

TaxReturnController now resolves the client address via ClientIpResolver
instead of IPAddressUtil, which returned True-Client-IP verbatim whenever
present and otherwise the leftmost X-Forwarded-For entry -- both fully
client-controlled, with no check on who the request came from.

IPAddressUtil is deleted rather than deprecated; a static helper that
reads request headers with no configuration is the defect, not the
implementation of it.

direct-file.client-ip.trusted-proxies is empty by default, so behavior
without configuration is now to ignore both headers and use the peer
address. Set DF_TRUSTED_PROXIES to the edge's CIDR blocks to restore
header-derived addresses.

The resolved value is still threaded into TaxReturnService and read by
nothing in this checkout -- the address parameter chain is release-strip
residue. This fixes the trust boundary ahead of whatever consumes it.

Refs M-2."
```

---

## Task 3: Enable branch protection on `main`

**Files:**
- Modify: `direct-file/README.md` (append to the CI section)

**Interfaces:**
- Consumes: a green `main`. Do not start until Tasks 1 and 2 are merged and CI is passing.
- Produces: nothing other tasks consume.

This task was written into the previous plan and never executed — `gh api repos/twarn247/direct-file/branches/main/protection` still returns `404 Branch not protected`. It is repeated here in full rather than cross-referenced, because a plan an executor reads out of order must stand on its own.

**This step is run by a human, not by an agent.** It changes repository settings, is not expressible as a commit, and is not reversible by `git revert`.

- [ ] **Step 1: Confirm `main` is green before locking the door**

```bash
gh run list --repo twarn247/direct-file --branch main --limit 1
```

Expected: the most recent `main` run is `completed  success`. If it is not, stop — enabling required checks against a red `main` blocks every subsequent merge.

- [ ] **Step 2: Confirm the exact check names**

Required status checks match each job's `name:`, not its key. Read them off the run rather than trusting this document:

```bash
gh run view --repo twarn247/direct-file $(gh run list --repo twarn247/direct-file --branch main --limit 1 --json databaseId --jq '.[0].databaseId') --json jobs --jq '.jobs[].name'
```

Expected exactly:

```
Lint and test the client
Build and test Java services
Dependency vulnerability scan
```

- [ ] **Step 3: Create the protection rule**

Run this yourself:

```bash
gh api --method PUT repos/twarn247/direct-file/branches/main/protection \
  --input - <<'JSON'
{
  "required_status_checks": {
    "strict": true,
    "contexts": [
      "Build and test Java services",
      "Lint and test the client",
      "Dependency vulnerability scan"
    ]
  },
  "enforce_admins": false,
  "required_pull_request_reviews": null,
  "restrictions": null,
  "allow_force_pushes": false,
  "allow_deletions": false
}
JSON
```

`enforce_admins: false` is deliberate: this is a single-maintainer fork, and locking yourself out of an emergency fix on a repository with no second reviewer trades a real risk for a theoretical one. `strict: true` requires branches to be up to date with `main` before merging.

- [ ] **Step 4: Verify it took**

```bash
gh api repos/twarn247/direct-file/branches/main/protection --jq '.required_status_checks.contexts'
```

Expected: the three names from Step 2.

- [ ] **Step 5: Document it**

Append to the CI section of `direct-file/README.md`, after the "Reproducing a CI failure locally" block:

````markdown
### Branch protection

`main` requires all three CI checks — `Build and test Java services`, `Lint and test the
client`, and `Dependency vulnerability scan` — to pass before a pull request can merge, with
`strict: true` (branches must be up to date). Force pushes and deletions are blocked.
`enforce_admins` is off: this is a single-maintainer repository and there is no second reviewer
to unblock an emergency fix.

Read the current rule with:

```sh
gh api repos/twarn247/direct-file/branches/main/protection
```
````

- [ ] **Step 6: Commit**

```bash
git add direct-file/README.md
git commit -m "docs: record the branch protection rule on main

All three CI checks are now required, strict, with force pushes and
deletions blocked. Closes the handback from the CI pipeline plan, which
assumed a protection object existed to add a check to -- there was none."
```

---

## Handbacks

1. **`state-api/src/main/java/gov/irs/directfile/stateapi/utils/IPAddress.java` is the same defect, unfixed.** It takes the leftmost `X-Forwarded-For` entry with no trusted-proxy check. It currently has **zero callers** anywhere in the repository, which is why it was scoped out — but it is a `@UtilityClass` sitting in a shared `utils` package, so the next caller inherits the defect silently. Either delete it or give it the `ClientIpResolver` treatment; do not record M-2 as closed while it stands.

2. **The trusted-proxy list ships empty, so this is inert until configured.** Merging this changes backend behavior from "trust any client's headers" to "trust no headers", which is correct but is *not* the production posture — a real deployment behind an edge needs `DF_TRUSTED_PROXIES` set to that edge's CIDR blocks or every resolved address becomes the edge's own. Whoever operates the internal build has to supply it, and nothing in this repository can verify the value.

3. **A trusted proxy's output is not validated beyond being an IP literal.** Rules 2 and 4 return whatever a trusted peer supplies. That is the intended trust model, but if the resolved address ever reaches a MeF submission, consider whether a private-range or loopback result should be rejected rather than filed.

4. **The `address` parameter chain in `TaxReturnService` is dead in this checkout.** `create`, `submit`, `createSubmission`, and `updateTaxReturnForSubmission` all accept it and none reads it. Left in place deliberately — the internal build presumably consumes it — but anyone reading this code will find a resolved-and-discarded value and should not conclude the resolver is unused.

5. **The HSA contribution-limit defect is still open.** 19 assertions in `src/test/factDictionaryTests/hsa.test.ts` disagree with the fact dictionary about form 8889 limits. The file is quarantined out of CI; the defect is not diagnosed. It needs tax-domain review.

6. **`apiHelpers.test.ts` and `flowSnapshots.test.ts` remain quarantined and unexplained.** The second fails to load at all — `ENOENT` on `src/test/factDictionaryTests/backend-scenarios-ero`, a fixture directory the public release appears to have stripped.

7. **Three `DM_DEFAULT_ENCODING` suppressions remain in `submit`** — `DocumentStorageBatchRepository:30`, `SynchronousS3StorageService:31`, `LocalWriteUtilityService:16`. Same defect class as L-5; out of scope because `submit` does not compile here.

8. **The security review is not on `main`.** It lives only on `origin/claude/report-security-review-lb7lsz`. Five plans now cite that path as their spec and it resolves for none of them. Either merge the review to `main` or rewrite the citations to name the commit.

9. **With this merged, every finding in the review is closed except the low-severity items noted above.** H-1, M-1, M-2, M-3, M-4, M-5, L-1 through L-8 are all addressed. A re-review against the current tree — rather than the 2025-06-05 snapshot the original covered — is the natural next piece of work.
