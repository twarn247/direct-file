# Backend Low-Severity Findings and CI Gating Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Close the three remaining backend low-severity findings (L-1, L-2, L-5), then make CI's client job produce a signal that can gate merges and turn on branch protection for `main`.

**Architecture:** Five independent tasks in two groups. The backend group is three unrelated one-file fixes, each with its own unit test: a missing `@Profile` on a mock controller, a configuration-properties class that never binds plus a service that discards its HMAC key, and two classes that encode taxpayer strings with the platform-default charset. The CI group quarantines the three known-failing client test files inside the `test:ci` npm script — one source of truth, with a guard test that the list cannot grow silently — and then enables branch protection on `main`, which has none today.

**Tech Stack:** Java 21, Spring Boot 3.3.10, Maven (`./mvnw`), JUnit 5, Mockito, AssertJ, Spotless with palantir-java-format 2.39.0, AWS Encryption SDK, Bouncy Castle, Vitest 1.6.1, GitHub Actions, `gh` CLI.

**Spec:** `docs/security/2026-08-22_codebase-security-review.md` findings L-1, L-2, and L-5, plus the client-gating decision recorded at https://github.com/twarn247/direct-file/pull/6#issuecomment-5494900442 and the branch-protection handback from `docs/superpowers/plans/2026-08-29-ci-pipeline-and-dependency-scanning.md`.

> **The spec is not on `main`.** `docs/security/2026-08-22_codebase-security-review.md` exists only on `origin/claude/report-security-review-lb7lsz` (commit `a6777fe`). Read it with:
>
> ```bash
> git show a6777fe:docs/security/2026-08-22_codebase-security-review.md
> ```
>
> Every prior plan cites this path as though it were on `main`. It is not. See the handbacks.

## Global Constraints

- **Java 21.** Set by `.github/workflows/ci.yml` and the parent POM. `java.util.HexFormat` (JDK 17+) and JEP 400 default-UTF-8 behavior are both available and both are relied on below.
- **Spotless runs in the build.** `spotless-maven-plugin` 2.43.0 with palantir-java-format 2.39.0 is configured in `boms/irs-spring-boot-starter-parent/pom.xml`. Run `./mvnw spotless:apply` before committing any Java change, or `verify` fails on formatting.
- **Backtick string literals in TypeScript.** ESLint enforces it repo-wide (`const x = \`value\`;`).
- **`npm run lint` must pass with `--max-warnings=0`** — both client lint scripts are configured that way.
- **Do not run `verify` on `status` or `submit`.** Neither compiles in this checkout; they import an IRS-internal MeF SOAP client library that is not present. CI excludes them deliberately.
- **`libs` must be installed before `backend` builds.** `cd direct-file/libs && ./mvnw --batch-mode clean install`, and before that `cd direct-file/fact-graph-scala && sbt compile package publishM2`. Task 3 touches `libs/data-models`, so Task 3's changes must be `install`ed before Task 2's backend tests will see them.

---

## Task ordering and why

Tasks 1, 2, and 3 are mutually independent and touch disjoint files. Task 4 is independent of all three. **Task 5 must run last** — it makes CI checks required, so it should only land once the client job is capable of passing, which is Task 4's deliverable.

---

## Task 1: L-1 — profile-gate `MockDataImportController`

**Files:**
- Modify: `direct-file/backend/src/main/java/gov/irs/directfile/api/taxreturn/MockDataImportController.java`
- Test: `direct-file/backend/src/test/java/gov/irs/directfile/api/taxreturn/MockDataImportControllerProfileTest.java`

**Interfaces:**
- Consumes: nothing from other tasks.
- Produces: nothing other tasks consume.

**Why this is worth doing even though it is currently fail-closed.** `MockDataImportController` overrides `getPopulatedData` to read the import profile and date of birth straight from the `x-data-import-profile` and `x-data-import-dob` request headers. It extends `TaxReturnController`, which carries `@Profile("!mock")` at line 34, but declares no `@Profile` of its own. Outside the `mock` profile the application still refuses to start — the constructor's unchecked `(MockDataImportService) dataImportService` cast raises `ClassCastException`, and the duplicate inherited `@RequestMapping` would be an ambiguous mapping. So this is not a live exposure. The defect is that the gate is a side effect of a cast rather than a declaration: any refactor that widens `MockDataImportService`'s type, or makes the mock service the default implementation, silently removes it.

The test is a reflection assertion rather than a Spring context test on purpose. A `@SpringBootTest` for the backend brings up the full application context including datasource and AWS clients; that is minutes of runtime to assert a single annotation. The reflection test encodes exactly the requirement, runs in milliseconds, and cannot pass accidentally.

- [ ] **Step 1: Write the failing test**

`MockDataImportController` is package-private, so the test must live in the same package.

Create `direct-file/backend/src/test/java/gov/irs/directfile/api/taxreturn/MockDataImportControllerProfileTest.java`:

```java
package gov.irs.directfile.api.taxreturn;

import org.junit.jupiter.api.Test;
import org.springframework.context.annotation.Profile;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

public class MockDataImportControllerProfileTest {

    @Test
    public void mockDataImportControllerIsGatedToTheMockProfile() {
        Profile profile = MockDataImportController.class.getAnnotation(Profile.class);
        assertNotNull(
                profile,
                "MockDataImportController reads x-data-import-profile and x-data-import-dob straight from"
                        + " request headers. It must declare @Profile(\"mock\") rather than relying on the"
                        + " constructor's ClassCastException to keep it out of other profiles.");
        assertArrayEquals(new String[] {"mock"}, profile.value());
    }

    @Test
    public void taxReturnControllerIsExcludedFromTheMockProfile() {
        // The two are complements. If this one loses !mock, both controllers load under the
        // mock profile and the duplicate @RequestMapping becomes an ambiguous mapping again.
        Profile profile = TaxReturnController.class.getAnnotation(Profile.class);
        assertNotNull(profile, "TaxReturnController must declare @Profile(\"!mock\").");
        assertArrayEquals(new String[] {"!mock"}, profile.value());
    }
}
```

- [ ] **Step 2: Run it to verify the first test fails**

```bash
cd direct-file/backend
./mvnw --batch-mode --no-transfer-progress test -Dtest=MockDataImportControllerProfileTest
```

Expected: `mockDataImportControllerIsGatedToTheMockProfile` FAILS on the `assertNotNull` — the annotation is absent. `taxReturnControllerIsExcludedFromTheMockProfile` PASSES already.

- [ ] **Step 3: Add the annotation**

In `MockDataImportController.java`, add the import alongside the existing Spring imports:

```java
import org.springframework.context.annotation.Profile;
```

and annotate the class, above `@RestController`:

```java
@Slf4j
@Profile("mock")
@RestController
class MockDataImportController extends TaxReturnController {
```

- [ ] **Step 4: Run the test to verify it passes**

```bash
./mvnw --batch-mode --no-transfer-progress test -Dtest=MockDataImportControllerProfileTest
```

Expected: both tests PASS.

- [ ] **Step 5: Verify nothing else broke**

```bash
./mvnw --batch-mode --no-transfer-progress verify
```

Expected: BUILD SUCCESS. If a test that was relying on the mock controller loading under a non-`mock` profile now fails, that test was depending on the defect — report it rather than reverting the annotation.

- [ ] **Step 6: Format and commit**

```bash
./mvnw spotless:apply
cd ../..
git add direct-file/backend/src/main/java/gov/irs/directfile/api/taxreturn/MockDataImportController.java \
        direct-file/backend/src/test/java/gov/irs/directfile/api/taxreturn/MockDataImportControllerProfileTest.java
git commit -m "fix(backend): declare @Profile(\"mock\") on MockDataImportController

The controller reads x-data-import-profile and x-data-import-dob straight
from request headers. It was kept out of other profiles only by its
constructor's unchecked cast to MockDataImportService raising
ClassCastException, and by the inherited @RequestMapping being ambiguous
-- fail-closed, but by accident rather than by declaration.

Refs L-1."
```

---

## Task 2: L-2 — bind and validate the allowlist HMAC key

**Files:**
- Modify: `direct-file/backend/src/main/java/gov/irs/directfile/api/authorization/config/FeatureFlagConfigurationProperties.java`
- Modify: `direct-file/backend/src/main/java/gov/irs/directfile/api/authorization/EmailAllowlistFeatureService.java`
- Modify: `direct-file/backend/src/main/java/gov/irs/directfile/api/BackendApplication.java`
- Modify: `direct-file/backend/src/main/resources/application.yaml:476-480`
- Test: `direct-file/backend/src/test/java/gov/irs/directfile/api/authorization/EmailAllowlistFeatureServiceTest.java`

**Interfaces:**
- Consumes: nothing from other tasks.
- Produces: nothing other tasks consume.

**This finding is two defects, not one.**

1. `EmailAllowlistFeatureService:38` sets `this.hexKey = null` and `emailMac` passes it to `new KeyParameter(hexKey)` — an NPE on every allowlist check when the allowlist is enabled. This is residue from the key-loading code being stripped for public release.
2. `authorization/config/FeatureFlagConfigurationProperties` is a plain `@Component` whose no-arg constructor hardcodes `new Allowlist(false, "key", "allowlist.csv")`. It carries no `@ConfigurationProperties`, so it **never binds from YAML at all**. Fixing only defect 1 would read the literal `"key"`, which is not valid hexadecimal.

The correct shape is already in this repository. `gov.irs.directfile.api.config.DataImportGatingConfigurationProperties` is `@Validated @ConfigurationProperties(prefix = "direct-file.data-import-gating")` with `@AllArgsConstructor`, and `DataImportGatingEmailAllowlistService:39` decodes its key. This task makes the feature-flags pair match. `AuthorizationTokenService:41-57` (from M-5) is the precedent for refusing to start on a missing or unusable key.

**Behavior change to call out in the PR.** Today the hardcoded constructor yields `objectKey = "allowlist.csv"`. `application.yaml:480` says `object-key: "allowlist-export.csv"`. Making the class bind switches which S3 object `loadAllowlist()` fetches. `enabled` is `false` in every configuration in this repository, so nothing fetches today and this cannot regress a running deployment here — but it is a live change, not a no-op refactor, and the PR body must say so. The evidence that `allowlist-export.csv` is the intended value: all three arguments in that constructor are stubs (`hexKey = "key"` is not valid hex, `hexKey` is then discarded as `null` anyway), the file's entire history is `e0d5c84 initial commit`, and `allowlist-export.csv` matches the `-export.csv` convention of the sibling `data-import-allowlist-export.csv`, which is bound and live.

**Two classes share the simple name `FeatureFlagConfigurationProperties`.** `gov.irs.directfile.api.featureflags.FeatureFlagConfigurationProperties` is bound to `direct-file.aws.s3`. The one this task changes is `gov.irs.directfile.api.authorization.config.FeatureFlagConfigurationProperties`. Do not confuse them; Step 4 needs the fully-qualified name.

**Why explicit registration rather than the existing scan.** `@ConfigurationPropertiesScan` appears exactly once in the backend, on `gov.irs.directfile.api.config.DevelopmentIdentitySupplier` — which is annotated `@Profile(BeanProfiles.ENABLE_DEVELOPMENT_IDENTITY_SUPPLIER)`. A `@Profile` on a `@Configuration` class suppresses the whole class including its `@Import`-driven registrar, so that scan does not run when the profile is inactive, and it only covers `gov.irs.directfile.api.config` and below in any case — not `api.authorization.config`. Relying on it would leave the bean unregistered in production and the context would fail to start. Registering explicitly in `BackendApplication` is profile-independent.

- [ ] **Step 1: Write the failing tests**

Create `direct-file/backend/src/test/java/gov/irs/directfile/api/authorization/EmailAllowlistFeatureServiceTest.java`:

```java
package gov.irs.directfile.api.authorization;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import gov.irs.directfile.api.authorization.config.FeatureFlagConfigurationProperties;
import gov.irs.directfile.api.authorization.config.FeatureFlagConfigurationProperties.Allowlist;
import gov.irs.directfile.api.authorization.config.FeatureFlagConfigurationProperties.OpenEnrollment;
import gov.irs.directfile.api.featureflags.FeatureFlagService;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
public class EmailAllowlistFeatureServiceTest {

    @Mock
    FeatureFlagService featureFlagService;

    // Same key and fixtures as DataImportGatingEmailAllowlistServiceTest -- the two services
    // compute an identical HMAC-SHA256 over the lowercased address, so the digests transfer.
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

    private static FeatureFlagConfigurationProperties props(boolean enabled, String hexKey) {
        return new FeatureFlagConfigurationProperties(
                new Allowlist(enabled, hexKey, "allowlist-export.csv"), new OpenEnrollment(true));
    }

    private EmailAllowlistFeatureService subject(boolean enabled, String hexKey) {
        return new EmailAllowlistFeatureService(props(enabled, hexKey), featureFlagService);
    }

    @Test
    public void emailOnAllowlist_contains_thenReturnsTrue() {
        when(featureFlagService.getFeatureObjectAsString(any())).thenReturn(ALLOWLIST_EXPORT_CSV);

        assertTrue(subject(true, HEX_KEY).emailOnAllowlist("test@example.com"));
    }

    @Test
    public void emailOnAllowlist_notContains_thenReturnsFalse() {
        when(featureFlagService.getFeatureObjectAsString(any())).thenReturn(ALLOWLIST_EXPORT_CSV);

        assertFalse(subject(true, HEX_KEY).emailOnAllowlist("xxx@example.com"));
    }

    @Test
    public void emailOnAllowlist_retrievalThrows_thenReturnsFalse() {
        when(featureFlagService.getFeatureObjectAsString(any())).thenThrow(new RuntimeException());

        assertFalse(subject(true, HEX_KEY).emailOnAllowlist("test@example.com"));
    }

    @Test
    public void allowlistDisabled_thenReturnsFalseAndNeedsNoKey() {
        assertFalse(subject(false, "").emailOnAllowlist("test@example.com"));
    }

    @Test
    public void allowlistEnabledWithNoKey_thenRefusesToStart() {
        IllegalStateException e = assertThrows(IllegalStateException.class, () -> subject(true, ""));
        assertTrue(e.getMessage().contains("DF_FEATURE_FLAGS_ALLOWLIST_HEX_KEY"));
    }

    @Test
    public void allowlistEnabledWithNonHexKey_thenRefusesToStart() {
        // "key" is the literal the hardcoded constructor used to supply. It is not hexadecimal.
        IllegalStateException e = assertThrows(IllegalStateException.class, () -> subject(true, "key"));
        assertTrue(e.getMessage().contains("hexadecimal"));
    }

    @Test
    public void allowlistEnabledWithShortKey_thenRefusesToStart() {
        IllegalStateException e = assertThrows(IllegalStateException.class, () -> subject(true, "abcd"));
        assertTrue(e.getMessage().contains("32"));
    }

    @Test
    public void configuredObjectKeyIsTheOneFetched() {
        when(featureFlagService.getFeatureObjectAsString("allowlist-export.csv"))
                .thenReturn(ALLOWLIST_EXPORT_CSV);

        assertTrue(subject(true, HEX_KEY).emailOnAllowlist("example2@example.com"));
    }

    @Test
    public void allowlistEnabledIsExposed() {
        assertEquals(true, subject(true, HEX_KEY).isAllowlistEnabled());
        assertEquals(false, subject(false, "").isAllowlistEnabled());
    }
}
```

- [ ] **Step 2: Run it to verify it fails**

```bash
cd direct-file/backend
./mvnw --batch-mode --no-transfer-progress test -Dtest=EmailAllowlistFeatureServiceTest
```

Expected: COMPILATION FAILURE — `FeatureFlagConfigurationProperties` has no two-argument constructor and no accessible `OpenEnrollment` constructor yet. That is the correct starting state.

- [ ] **Step 3: Make the properties class bind**

Replace the whole of `direct-file/backend/src/main/java/gov/irs/directfile/api/authorization/config/FeatureFlagConfigurationProperties.java` with:

```java
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
```

Note that `OpenEnrollment` becomes a `record` (it was a `@Getter @AllArgsConstructor` static class). Constructor binding needs it, and it matches `Allowlist`.

- [ ] **Step 4: Register the properties class explicitly**

In `direct-file/backend/src/main/java/gov/irs/directfile/api/BackendApplication.java`, extend the `@EnableConfigurationProperties` list. Use the fully-qualified name — the file does a wildcard import of `gov.irs.directfile.api.config.*`, and the simple name is ambiguous:

```java
@EnableConfigurationProperties({
    gov.irs.directfile.api.authorization.config.FeatureFlagConfigurationProperties.class,
    StateApiEndpointProperties.class,
    StateApiFeatureFlagProperties.class,
    StatusEndpointProperties.class,
    SubmitEndpointProperties.class,
})
```

- [ ] **Step 5: Confirm the consumer set is what this plan assumes**

Turning the nested `OpenEnrollment` into a record changes `isEnabled()` to `enabled()`, and dropping `@Component` changes how the class is registered. Both were checked while writing this plan, and the expected answer is "nothing else to change" — this step exists to catch it if the tree has moved since.

```bash
cd direct-file/backend
grep -rn "authorization.config.FeatureFlagConfigurationProperties" --include="*.java" src
grep -rn "getOpenEnrollment" --include="*.java" src
```

Expected: the first prints exactly one line, the import in `EmailAllowlistFeatureService.java:18`. The second prints nothing — the nested `OpenEnrollment` has no consumers at all.

**Ignore the unrelated `OpenEnrollment` hits** a broader grep produces. `gov.irs.directfile.api.featureflags.OpenEnrollment` is a different, unrelated class used by `FeatureFlags` and `OpenEnrollmentFeatureService`; it is not the nested record and must not be touched.

If either grep returns more than that, stop and report — a second consumer changes the blast radius of dropping `@Component`.

- [ ] **Step 6: Decode the key and fail closed at startup**

In `EmailAllowlistFeatureService.java`, add these imports:

```java
import java.util.HexFormat;
```

`java.util.HexFormat` rather than the `org.apache.pdfbox.util.Hex` the sibling service uses: `HexFormat.parseHex` has a documented contract of throwing `IllegalArgumentException` on odd length or non-hex characters, which is what makes the fail-closed branch reliable. PDFBox's helper does not specify its behavior on malformed input. Migrating the sibling is a handback item, not part of this task.

Add the constant next to the fields:

```java
    // HMAC-SHA256; a key shorter than the digest adds no strength.
    private static final int MIN_HMAC_KEY_BYTES = 32;
```

Replace the constructor:

```java
    public EmailAllowlistFeatureService(
            FeatureFlagConfigurationProperties configProps, FeatureFlagService featureFlagService) {
        this.featureFlagService = featureFlagService;
        this.allowlistEnabled = configProps.getAllowlist().enabled();
        this.allowListObject = configProps.getAllowlist().objectKey();
        this.hexKey = decodeKeyIfEnabled(this.allowlistEnabled, configProps.getAllowlist().hexKey());
        if (this.allowlistEnabled) {
            // The object key was previously hardcoded and unreachable from configuration. Log the
            // resolved value so an operator can see which object is actually being read. It is an
            // S3 object name, not a secret, and FeatureFlagService already logs it on every fetch.
            log.info("Allowlist is enabled, reading feature object {}", this.allowListObject);
        }
    }

    private static byte[] decodeKeyIfEnabled(boolean allowlistEnabled, String configuredHexKey) {
        if (!allowlistEnabled) {
            // emailMac() is unreachable while the allowlist is disabled -- emailOnAllowlist returns
            // early. Requiring a key that is never used would block startup for no benefit.
            return null;
        }
        if (StringUtils.isBlank(configuredHexKey)) {
            throw new IllegalStateException(
                    "direct-file.feature-flags.allowlist.enabled is true but"
                            + " direct-file.feature-flags.allowlist.hex-key is not set."
                            + " Set DF_FEATURE_FLAGS_ALLOWLIST_HEX_KEY.");
        }
        byte[] decoded;
        try {
            decoded = HexFormat.of().parseHex(configuredHexKey);
        } catch (IllegalArgumentException e) {
            throw new IllegalStateException(
                    "direct-file.feature-flags.allowlist.hex-key is not valid hexadecimal.", e);
        }
        if (decoded.length < MIN_HMAC_KEY_BYTES) {
            throw new IllegalStateException("direct-file.feature-flags.allowlist.hex-key must decode to at least "
                    + MIN_HMAC_KEY_BYTES + " bytes for HMAC-SHA256.");
        }
        return decoded;
    }
```

`StringUtils` and `log` are already imported and available on the class.

- [ ] **Step 7: Remove the committed placeholder key**

In `direct-file/backend/src/main/resources/application.yaml`, replace lines 476-480 with:

```yaml
  feature-flags:
    allowlist:
      enabled: false
      # No committed default. Set DF_FEATURE_FLAGS_ALLOWLIST_HEX_KEY (>= 32 bytes, hex-encoded)
      # when enabling. EmailAllowlistFeatureService refuses to start without it.
      hex-key: ${DF_FEATURE_FLAGS_ALLOWLIST_HEX_KEY:}
      object-key: "allowlist-export.csv"
```

Leave the `data-import-gating` block above it untouched.

- [ ] **Step 8: Run the tests to verify they pass**

```bash
./mvnw --batch-mode --no-transfer-progress test -Dtest=EmailAllowlistFeatureServiceTest
```

Expected: all nine tests PASS.

- [ ] **Step 9: Verify the application context still starts**

This is the step that catches a registration mistake — a `@ConfigurationProperties` class that is not registered fails at context startup, not at compile time.

```bash
./mvnw --batch-mode --no-transfer-progress verify
```

Expected: BUILD SUCCESS. Two distinct failures are possible here and they have different fixes:

- **`NoSuchBeanDefinitionException` for `FeatureFlagConfigurationProperties`** — Step 4 did not take effect. Check that the fully-qualified name is in the `@EnableConfigurationProperties` list and that the class no longer carries `@Component`.
- **A binding or validation failure naming `openEnrollment` or `allowlist` as null** — a test is running against a property source where `direct-file.feature-flags.open-enrollment` or `.allowlist` is absent. Constructor binding leaves a missing nested object null, and `@Validated` + `@NotNull` then rejects it. The class previously could not fail this way because it never bound at all. Fix by supplying the property in that test's configuration, not by dropping `@Validated` — the whole point of this task is that the values come from configuration.

- [ ] **Step 10: Format and commit**

```bash
./mvnw spotless:apply
cd ../..
git add direct-file/backend/src/main/java/gov/irs/directfile/api/authorization/config/FeatureFlagConfigurationProperties.java \
        direct-file/backend/src/main/java/gov/irs/directfile/api/authorization/EmailAllowlistFeatureService.java \
        direct-file/backend/src/main/java/gov/irs/directfile/api/BackendApplication.java \
        direct-file/backend/src/main/resources/application.yaml \
        direct-file/backend/src/test/java/gov/irs/directfile/api/authorization/EmailAllowlistFeatureServiceTest.java
git commit -m "fix(backend): bind the allowlist HMAC key instead of discarding it

EmailAllowlistFeatureService set hexKey = null and passed it to
KeyParameter, an NPE on every check once the allowlist was enabled. Its
FeatureFlagConfigurationProperties was also a plain @Component whose
no-arg constructor hardcoded stub values, so it never bound from YAML --
fixing the service alone would have read the literal \"key\", which is
not hexadecimal.

Both now mirror the working DataImportGating pair. The service refuses to
start when the allowlist is enabled and the key is missing, non-hex, or
under 32 bytes, following AuthorizationTokenService's precedent.

Binding changes the resolved object key from the hardcoded allowlist.csv
to the configured allowlist-export.csv. enabled is false in every
configuration here so nothing fetches today, but it is a live change.

Refs L-2."
```

---

## Task 3: L-5 — pin UTF-8 for taxpayer strings

**Files:**
- Modify: `direct-file/libs/data-models/src/main/java/gov/irs/directfile/models/encryption/GenericStringEncryptor.java`
- Modify: `direct-file/libs/data-models/src/main/java/gov/irs/directfile/models/encryption/DataEncryptDecrypt.java:20,157`
- Test: `direct-file/libs/data-models/src/test/java/gov/irs/directfile/models/encryption/GenericStringEncryptorTest.java`

**Interfaces:**
- Consumes: nothing from other tasks.
- Produces: nothing other tasks consume. (Task 2's backend build resolves `data-models` from `~/.m2`; if both tasks are in flight, re-run `cd direct-file/libs && ./mvnw clean install` before Task 2's `verify`.)

**No backfill is required, and here is the argument.** H-1 needed a ciphertext migration; this does not. `GenericStringEncryptor` calls `attribute.getBytes()` and `new String(decrypted)` with no charset, so the bytes committed to `facts_cipher_text` depend on the JVM's default charset. But every JVM in this repository is Java 21, and JEP 400 (Java 18+) made the default charset UTF-8 regardless of the host locale. A search of every `pom.xml`, `Dockerfile`, `*.sh`, and `*.yaml` in the tree finds no `-Dfile.encoding` override — the only `file.encoding` hits are inside generated `target/surefire-reports/*.xml`, which record `UTF-8`. So the plaintext bytes already in the database are UTF-8, and pinning the charset is a change of guarantee, not of value. Record this reasoning in the PR; do not add a migration.

**Do not touch `submit`.** `DocumentStorageBatchRepository`, `SynchronousS3StorageService`, and `LocalWriteUtilityService` also suppress `DM_DEFAULT_ENCODING`, but `submit` does not compile in this checkout and none of them encrypts taxpayer strings. They are a handback item.

- [ ] **Step 1: Write the failing test**

Create `direct-file/libs/data-models/src/test/java/gov/irs/directfile/models/encryption/GenericStringEncryptorTest.java`. The key setup mirrors `DataEncryptDecryptTest` so it needs no AWS access:

```java
package gov.irs.directfile.models.encryption;

import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.concurrent.TimeUnit;
import javax.crypto.spec.SecretKeySpec;

import com.amazonaws.encryptionsdk.AwsCrypto;
import com.amazonaws.encryptionsdk.CryptoMaterialsManager;
import com.amazonaws.encryptionsdk.caching.CachingCryptoMaterialsManager;
import com.amazonaws.encryptionsdk.caching.LocalCryptoMaterialsCache;
import com.amazonaws.encryptionsdk.jce.JceMasterKey;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import gov.irs.directfile.models.autoconfigure.EncryptionContextProperties;

import static org.assertj.core.api.Assertions.assertThat;

public class GenericStringEncryptorTest {

    // A taxpayer name with a diacritic, a CJK name, and an astral-plane code point.
    // All three encode differently under UTF-8 than under any single-byte default charset.
    private static final String NON_ASCII = "José 李雷 👋";

    private GenericStringEncryptor subject;
    private DataEncryptDecrypt dataEncryptDecrypt;

    @BeforeEach
    void setUp() {
        byte[] rawKey = new byte[32];
        new SecureRandom().nextBytes(rawKey);
        JceMasterKey masterKey =
                JceMasterKey.getInstance(new SecretKeySpec(rawKey, "AES"), "local", "local", "AES/GCM/NoPadding");
        CryptoMaterialsManager cmm = CachingCryptoMaterialsManager.newBuilder()
                .withMasterKeyProvider(masterKey)
                .withCache(new LocalCryptoMaterialsCache(10))
                .withMaxAge(60, TimeUnit.SECONDS)
                .withMessageUseLimit(1000)
                .build();
        EncryptionContextProperties properties = new EncryptionContextProperties();
        properties.setContextVerification("warn");
        dataEncryptDecrypt = new DataEncryptDecrypt(AwsCrypto.standard(), cmm, properties);
        subject = new GenericStringEncryptor(dataEncryptDecrypt);
    }

    @Test
    void roundTripsNonAsciiUnchanged() {
        String stored = subject.convertToDatabaseColumn(NON_ASCII, EncryptionPurpose.TAX_RETURN_FACTS, null);

        assertThat(subject.convertToEntityAttribute(stored, EncryptionPurpose.TAX_RETURN_FACTS))
                .isEqualTo(NON_ASCII);
    }

    @Test
    void encryptsExactlyTheUtf8Bytes() {
        // The guarantee, not just the round trip: what goes into the ciphertext is UTF-8,
        // independent of the JVM's default charset.
        String stored = subject.convertToDatabaseColumn(NON_ASCII, EncryptionPurpose.TAX_RETURN_FACTS, null);
        byte[] plaintext = dataEncryptDecrypt.decrypt(
                Base64.getDecoder().decode(stored), EncryptionPurpose.TAX_RETURN_FACTS);

        assertThat(plaintext).isEqualTo(NON_ASCII.getBytes(StandardCharsets.UTF_8));
    }

    @Test
    void decryptsUtf8BytesWrittenDirectly() {
        byte[] ciphertext = dataEncryptDecrypt.encrypt(
                NON_ASCII.getBytes(StandardCharsets.UTF_8), EncryptionPurpose.TAX_RETURN_FACTS, null);
        String stored = Base64.getEncoder().encodeToString(ciphertext);

        assertThat(subject.convertToEntityAttribute(stored, EncryptionPurpose.TAX_RETURN_FACTS))
                .isEqualTo(NON_ASCII);
    }

    @Test
    void passesNullAndEmptyThrough() {
        assertThat(subject.convertToDatabaseColumn(null, EncryptionPurpose.TAX_RETURN_FACTS, null))
                .isNull();
        assertThat(subject.convertToDatabaseColumn("", EncryptionPurpose.TAX_RETURN_FACTS, null))
                .isEmpty();
        assertThat(subject.convertToEntityAttribute(null, EncryptionPurpose.TAX_RETURN_FACTS))
                .isNull();
        assertThat(subject.convertToEntityAttribute("", EncryptionPurpose.TAX_RETURN_FACTS))
                .isEmpty();
    }
}
```

- [ ] **Step 2: Run it to see the current state**

```bash
cd direct-file/libs/data-models
./mvnw --batch-mode --no-transfer-progress test -Dtest=GenericStringEncryptorTest
```

Expected: all four PASS, because the CI runner's default charset is already UTF-8.

**This is the point of the task and it must be recorded, not glossed.** The test cannot be made to fail here without launching a second JVM under `-Dfile.encoding=ISO-8859-1`, which JEP 400 makes a no-op for `String.getBytes()` on Java 18+ anyway. What the test locks in is the *guarantee*: after Step 3, `encryptsExactlyTheUtf8Bytes` fails if anyone reintroduces a default-charset call, because the assertion names UTF-8 explicitly rather than comparing two default-charset round trips. Say exactly this in the PR rather than claiming a red-to-green cycle that did not happen.

- [ ] **Step 3: Pin the charset in `GenericStringEncryptor`**

Replace the whole of `GenericStringEncryptor.java` with:

```java
package gov.irs.directfile.models.encryption;

import java.nio.charset.StandardCharsets;
import java.util.Base64;

import lombok.AllArgsConstructor;

@AllArgsConstructor
public class GenericStringEncryptor {
    private final DataEncryptDecrypt dataEncryptDecrypt;

    public String convertToDatabaseColumn(String attribute, EncryptionPurpose purpose, String actorId) {
        if (attribute == null || attribute.isEmpty()) {
            return attribute;
        }
        byte[] ciphertext =
                dataEncryptDecrypt.encrypt(attribute.getBytes(StandardCharsets.UTF_8), purpose, actorId);
        return Base64.getEncoder().encodeToString(ciphertext);
    }

    public String convertToEntityAttribute(String dbData, EncryptionPurpose expected) {
        if (dbData == null || dbData.isEmpty()) {
            return dbData;
        }
        byte[] ciphertext = Base64.getDecoder().decode(dbData);
        return new String(dataEncryptDecrypt.decrypt(ciphertext, expected), StandardCharsets.UTF_8);
    }

    /** See {@link DataEncryptDecrypt#decryptLegacyTolerant} — data-import populations only. */
    public String convertToEntityAttributeLegacyTolerant(String dbData, EncryptionPurpose expected) {
        if (dbData == null || dbData.isEmpty()) {
            return dbData;
        }
        byte[] ciphertext = Base64.getDecoder().decode(dbData);
        return new String(dataEncryptDecrypt.decryptLegacyTolerant(ciphertext, expected), StandardCharsets.UTF_8);
    }
}
```

Both the `@SuppressFBWarnings` annotation and its `edu.umd.cs.findbugs.annotations.SuppressFBWarnings` import are gone — the warning they suppressed no longer fires.

- [ ] **Step 4: Pin the charset in `DataEncryptDecrypt`**

In `DataEncryptDecrypt.java`, add to the imports:

```java
import java.nio.charset.StandardCharsets;
```

Delete line 20 entirely:

```java
@SuppressFBWarnings(value = "DM_DEFAULT_ENCODING", justification = "Initial Spotbugs Setup")
```

and its now-unused import `edu.umd.cs.findbugs.annotations.SuppressFBWarnings`. Then in `checkKmsConnection()` change:

```java
        byte[] testBytes = "something".getBytes();
```

to:

```java
        byte[] testBytes = "something".getBytes(StandardCharsets.UTF_8);
```

- [ ] **Step 5: Run the full module build**

SpotBugs runs in `verify`, so this is what proves the suppressions were genuinely removable rather than merely deleted.

```bash
./mvnw --batch-mode --no-transfer-progress verify
```

Expected: BUILD SUCCESS with no `DM_DEFAULT_ENCODING` finding. If SpotBugs now reports one, a default-encoding call was missed — find it and pin it rather than restoring the suppression.

- [ ] **Step 6: Reinstall the library and confirm downstream still builds**

```bash
cd ..
./mvnw --batch-mode --no-transfer-progress clean install
cd ../backend
./mvnw --batch-mode --no-transfer-progress verify
```

Expected: BUILD SUCCESS for both.

- [ ] **Step 7: Format and commit**

```bash
cd ../libs && ./mvnw spotless:apply
cd ../..
git add direct-file/libs/data-models/src/main/java/gov/irs/directfile/models/encryption/GenericStringEncryptor.java \
        direct-file/libs/data-models/src/main/java/gov/irs/directfile/models/encryption/DataEncryptDecrypt.java \
        direct-file/libs/data-models/src/test/java/gov/irs/directfile/models/encryption/GenericStringEncryptorTest.java
git commit -m "fix(data-models): encrypt and decrypt taxpayer strings as UTF-8

GenericStringEncryptor used attribute.getBytes() and new String(...) with
no charset, so the bytes committed to facts_cipher_text depended on the
JVM default. Non-ASCII names would round-trip incorrectly across JVMs
that disagreed.

No backfill: every service here is Java 21, JEP 400 makes the default
UTF-8, and there is no -Dfile.encoding override anywhere in the poms,
Dockerfiles, or scripts -- so stored plaintext is already UTF-8. This
changes the guarantee, not the value.

Both DM_DEFAULT_ENCODING suppressions are removed rather than
re-justified; SpotBugs passes without them.

Refs L-5."
```

---

## Task 4: Quarantine the three failing client test files

**Files:**
- Modify: `direct-file/df-client/df-client-app/package.json:71`
- Modify: `direct-file/README.md:218-223`
- Test: `direct-file/df-client/df-client-app/src/test/quarantineList.test.ts`

**Interfaces:**
- Consumes: nothing from other tasks.
- Produces: a green `Lint and test the client` job, which Task 5 requires.

**What is being quarantined and why here.** Run `33514754676` on `main` fails the `Test` step with 21 assertion failures across three files: 19 in `src/test/factDictionaryTests/hsa.test.ts` (form 8889 contribution limits — wrong dollar amounts), 1 in `src/misc/apiHelpers.test.ts` (`SM_UNIVERSALID` not overridden from `localStorage`), and 1 suite-level failure in `src/test/scenarioTests/flowSnapshots.test.ts` (`ENOENT` on `./src/test/factDictionaryTests/backend-scenarios-ero`). All three predate CI; the same 21 failures reproduce on `main` before the client job existed.

The `test:ci` script already carries an `--exclude` glob, so the quarantine goes in the same place rather than in `vitest.config.mts`. One source of truth, and it stays visible to anyone running the command by hand. The guard test is what keeps the list from growing quietly.

> **Quarantining `hsa.test.ts` hides a real defect.** Wrong dollar amounts in contribution-limit logic mean either the fact dictionary or the expectations are wrong, and one of those is a tax-calculation bug in a tax-filing application. The exclusion is a CI-signal decision, not a verdict that the failures are benign. It is carried as the first handback below and must appear in the PR body.

- [ ] **Step 1: Confirm the current failure set locally**

```bash
cd direct-file/df-client && npm ci
cd df-client-app && npm run test:ci
```

Expected: `Test Files 3 failed | 170 passed | 4 skipped (177)` and `Tests 21 failed`. If the counts differ from 3/170/4/177, stop and report — the backlog has changed since run `33514754676` and the quarantine list below may be wrong.

- [ ] **Step 2: Write the failing guard test**

Create `direct-file/df-client/df-client-app/src/test/quarantineList.test.ts`:

```ts
import { readFileSync } from 'fs';
import { resolve } from 'path';

// Kept in lockstep with the --exclude flags in package.json's test:ci script and with the
// table in direct-file/README.md. Adding a fourth file must be a deliberate edit in all
// three places, not something that drifts in with an unrelated change.
const QUARANTINED = [
  `src/misc/apiHelpers.test.ts`,
  `src/test/factDictionaryTests/hsa.test.ts`,
  `src/test/scenarioTests/flowSnapshots.test.ts`,
];

describe(`the test:ci quarantine list`, () => {
  it(`excludes exactly the files documented in direct-file/README.md`, () => {
    const pkg = JSON.parse(readFileSync(resolve(__dirname, `../../package.json`), `utf8`));
    const script: string = pkg.scripts[`test:ci`];

    // The first --exclude is the directory glob separating test:ci from test:ci:2 and :3.
    // Only single-file exclusions are quarantine entries.
    const excluded = [...script.matchAll(/--exclude '([^']+)'/g)].map((match) => match[1]);
    const quarantined = excluded.filter((path) => path.endsWith(`.test.ts`) || path.endsWith(`.test.tsx`));

    expect([...quarantined].sort()).toEqual([...QUARANTINED].sort());
  });
});
```

- [ ] **Step 3: Run it to verify it fails**

```bash
npx vitest --run src/test/quarantineList.test.ts
```

Expected: FAIL — `test:ci` has no single-file exclusions yet, so `quarantined` is `[]` against three expected entries.

- [ ] **Step 4: Add the exclusions**

In `direct-file/df-client/df-client-app/package.json`, replace line 71 with:

```json
    "test:ci": "VITEST_MAX_THREADS=4 VITEST_MIN_THREADS=4 vitest --exclude 'src/{test/completenessTests,test/functionalFlowTests,all-screens}/*' --exclude 'src/misc/apiHelpers.test.ts' --exclude 'src/test/factDictionaryTests/hsa.test.ts' --exclude 'src/test/scenarioTests/flowSnapshots.test.ts' --run --silent",
```

- [ ] **Step 5: Verify the exclusions take effect and the suite is green**

`--exclude` being repeatable in Vitest 1.6.1 is the one mechanical assumption here, so check the file count rather than just the exit code:

```bash
npm run test:ci
```

Expected: `Test Files 174 passed | 4 skipped (178)` — 177 files minus the 3 quarantined, plus the new guard test. Zero failures, exit code 0.

If the count is still 177, repeated `--exclude` did not apply. Fall back to a single brace-expanded glob combining all four patterns into one `--exclude` flag, and adjust the guard test's regex to match whatever form you land on.

- [ ] **Step 6: Confirm the other two suites are unaffected**

```bash
npm run test:ci:2 && npm run test:ci:3
```

Expected: both PASS, as they do in CI today.

- [ ] **Step 7: Update the README**

In `direct-file/README.md`, replace the paragraph at lines 218-223 (beginning "The `Test` step (`npm run test:ci`) currently fails") with:

```markdown
The `Test` step (`npm run test:ci`) excludes three files that fail on a pre-existing backlog,
so the remaining ~174 test files genuinely gate merges. The exclusions are `--exclude` flags on
the `test:ci` script in `df-client-app/package.json`, and `src/test/quarantineList.test.ts`
fails if that list stops matching this table:

| File | Failure |
| --- | --- |
| `src/test/factDictionaryTests/hsa.test.ts` | 19 wrong dollar amounts in form 8889 contribution limits |
| `src/misc/apiHelpers.test.ts` | `SM_UNIVERSALID` not overridden from `localStorage` when `preauthUuid` is set |
| `src/test/scenarioTests/flowSnapshots.test.ts` | suite fails to load: `ENOENT` on `src/test/factDictionaryTests/backend-scenarios-ero` |

All three reproduce on a checkout of `main` from before the client job existed — see
https://github.com/twarn247/direct-file/pull/6#issuecomment-5494900442 for the baseline run.

**The `hsa.test.ts` failures are not cosmetic.** Wrong dollar amounts in contribution-limit
logic mean either the fact dictionary or the test expectations are wrong, and one of those is a
tax-calculation defect. Excluding the file is a decision about CI signal, not a judgement that
the failures are harmless. It needs review by someone with tax-domain knowledge.
```

- [ ] **Step 8: Lint and commit**

```bash
npm run lint
cd ../../..
git add direct-file/df-client/df-client-app/package.json \
        direct-file/df-client/df-client-app/src/test/quarantineList.test.ts \
        direct-file/README.md
git commit -m "ci: quarantine the three failing client test files so the rest gate

test:ci failed on 21 pre-existing assertions across hsa.test.ts,
apiHelpers.test.ts, and flowSnapshots.test.ts, all reproducible on main
before the client job existed. A permanently-red check is one people stop
reading, and it blocks client from becoming a required status check.

Excluding those three files leaves ~174 test files actually gating.
quarantineList.test.ts fails if the exclude list stops matching the table
in direct-file/README.md, so a fourth entry cannot drift in silently.

The hsa.test.ts failures are wrong dollar amounts in form 8889
contribution limits -- a tax-calculation defect, not a CI problem.
Excluding the file is a signal decision and is recorded as such."
```

---

## Task 5: Enable branch protection on `main`

**Files:**
- Modify: `direct-file/README.md` (append to the CI section)

**Interfaces:**
- Consumes: Task 4's green client job. Do not start this task until Task 4 is merged and `main` is green.
- Produces: nothing other tasks consume.

**`main` has no protection at all today** — `gh api repos/twarn247/direct-file/branches/main/protection` returns `404 Branch not protected`. The handback from `docs/superpowers/plans/2026-08-29-ci-pipeline-and-dependency-scanning.md` describes this as making `build-and-test` a required check, but there is no protection object to add a check to; it has to be created.

**This step is run by a human, not by an agent.** It changes repository settings, is not expressible as a commit, and is not reversible by `git revert`.

- [ ] **Step 1: Confirm `main` is green before locking the door**

```bash
gh run list --repo twarn247/direct-file --branch main --limit 1
```

Expected: the most recent `main` run is `completed  success`. If it is not, stop — enabling required checks against a red `main` blocks every subsequent merge.

- [ ] **Step 2: Confirm the exact check names**

Required status checks match the job's `name:`, not its key. Read them off the run rather than trusting this document:

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

1. **The HSA contribution-limit failures are an open tax-calculation defect.** 19 assertions in `src/test/factDictionaryTests/hsa.test.ts` disagree with the fact dictionary about form 8889 limits — the 55+ catch-up addition, the line 8 total, and the line 6 allocation. Task 4 excluded the file to recover a usable CI signal; it did not diagnose which side is wrong. This needs someone with tax-domain knowledge and should not be closed as "CI backlog."

2. **`apiHelpers.test.ts` and `flowSnapshots.test.ts` are separately unexplained.** The first expects `SM_UNIVERSALID` to be overridden from `localStorage.preauthUuid` and receives the nil UUID. The second fails to load at all — `ENOENT` on `src/test/factDictionaryTests/backend-scenarios-ero`, a fixture directory that is not in this checkout, which suggests the public release stripped it. Both are quarantined, neither is fixed.

3. **`DataImportGatingEmailAllowlistService` still decodes its key with `org.apache.pdfbox.util.Hex`** and performs no validation — the same class of defect L-2 fixes, one directory over. It has a real key in configuration so it does not NPE, but a malformed key would produce a silently wrong HMAC and deny every user. Migrate it to the `HexFormat` + fail-closed pattern from Task 2.

4. **Three `DM_DEFAULT_ENCODING` suppressions remain in `submit`** — `DocumentStorageBatchRepository:30`, `SynchronousS3StorageService:31`, `LocalWriteUtilityService:16`. Out of scope because `submit` does not compile in this checkout and none of them handles taxpayer strings, but they are the same defect as L-5.

5. **The security review is not on `main`.** `docs/security/2026-08-22_codebase-security-review.md` lives only on `origin/claude/report-security-review-lb7lsz`. Four plans now cite that path as their spec and it resolves for none of them. Either merge the review to `main` or rewrite the citations to name the commit.

6. **M-2 and M-3 are still open.** M-2 — `IPAddressUtil:16` returns `True-Client-IP` unconditionally and reads `X-Forwarded-For` left-to-right, so a client-supplied header lands in audit records verbatim. It needs a trusted-proxy topology decision before it can be fixed. M-3 (state-API authorization codes are not single-use) was not re-verified during this plan.

7. **`enforce_admins` is off on the branch protection rule.** Revisit if the repository ever gains a second maintainer.
