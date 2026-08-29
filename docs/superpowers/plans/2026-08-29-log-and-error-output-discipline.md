# Log and Error Output Discipline Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Stop taxpayer identifiers reaching log output and exception messages reaching HTTP clients, and give the one operationally-significant log line that lacks a stable marker constant one.

**Architecture:** Four independent changes in the backend, defence-in-depth in two layers. At the *encoder* layer, every `LogstashEncoder` gets an explicit field allowlist, so a key-value pair or MDC entry has to be named to be emitted. At the *source* layer, the raw TIN stops entering the audit event map at all, so no encoder configuration can leak it. Separately, Spring stops returning exception messages in error bodies, and the Phase B advisory-lock warning gains a marker constant matching the two that already exist.

**Tech Stack:** Java 21, Spring Boot 3.3.10, Logback + logstash-logback-encoder, JUnit 5, Maven (`./mvnw`), Spotless with palantir-java-format.

**Spec:** `docs/security/2026-08-22_codebase-security-review.md` findings M-1 and M-4 (on branch `origin/claude/report-security-review-lb7lsz`), plus the unaddressed review feedback on PR #3.

## Global Constraints

- **Java 21.** Do not use preview features.
- **Format before every commit:** `./mvnw spotless:apply` from `direct-file/backend/`.
- **Backend tests run from `direct-file/backend/`** with `./mvnw test`.
- **No new dependencies.**
- **Do not change `logback-minimal.xml`'s allowlist contents.** It is the deployed default (`application.yaml:52` sets `logging.config: classpath:logback-minimal.xml`) and is already correct. It is the *model* the other files are brought up to, not a file to edit.
- **Audit field names are a downstream interface.** SIEM parsers may key on them. Task 3 renames one; see its handback note.

## Two corrections to the source review

The 2026-08-22 review's M-1 analysis has two factual errors about which files are exposed. They invert the actual risk, so the plan is written against what the files really contain. Verified on `origin/main`:

| File | Review said | Actually |
|---|---|---|
| `logback.xml` | "Spring Boot's default pattern appenders, which do not render fluent key-value pairs" — safe | **`LogstashEncoder` with no `includeKeyValueKeyName` and no `includeMdcKeyName` at all.** Emits every key-value pair and every MDC entry. |
| `logback-debug.xml` | "`LogstashEncoder` with no `includeKeyValueKeyName`" — the main exposure | Includes Spring's `defaults.xml` / `console-appender.xml` / `file-appender.xml`. Pattern encoders, which do not render fluent key-value pairs. Not a key-value leak. |

This matters beyond bookkeeping. `logback.xml` is the filename **Logback discovers automatically** from the classpath when no `logging.config` is set. The deployed default is safe only because `application.yaml` explicitly points at `logback-minimal.xml`; unset or override that property and the fully-open configuration is what loads. That is a worse failure mode than the review described, and it is why Task 2 covers `logback.xml` first.

The review's *recommendation* was right even though its file analysis was wrong: allowlist every encoder, and stop putting a raw TIN in the audit map. Both are implemented here.

## Scope note

**M-2 is not in this plan.** Fixing the spoofable `True-Client-IP` / `X-Forwarded-For` handling in `IPAddressUtil` requires knowing the edge topology — which proxies are trusted, and whether the edge strips inbound copies of both headers. Neither is determinable from this repository, and a wrong trusted-proxy list is worse than the current state because it looks correct. It needs an owner answer first.

**The low-severity findings are not in this plan** (L-1, L-2, L-5, L-6, L-7, L-8). L-7 in particular — no dependency scanning — is worth its own plan, because `origin/main` has no `.github/` directory and no CI pipeline of any kind, so it is "build a pipeline" rather than "add a scanner".

---

## Task 1: Close out the PR #3 review feedback

Two items the reviewer raised on the Phase B backfill that did not block merge.

**Files:**
- Modify: `direct-file/backend/src/main/java/gov/irs/directfile/api/taxreturn/EncryptionBackfillWorker.java:118`
- Modify: `direct-file/backend/README.md`
- Test: `direct-file/backend/src/test/java/gov/irs/directfile/api/taxreturn/EncryptionBackfillWorkerTest.java`

**Interfaces:**
- Consumes: nothing from other tasks.
- Produces: `EncryptionBackfillWorker.LOCK_RELEASE_FAILURE_MARKER = "ENCRYPTION_BACKFILL_LOCK_RELEASE_FAILED"`, public so a test can assert on it.

**Why this matters.** The feature has two stable marker constants — `EncryptionBackfillRowService.FAILURE_MARKER` and `EncryptionBackfillWorker.PROGRESS_MARKER` — but the lock-release warning is prose inside the message string. The README then tells operators to watch for the substring `Encryption backfill advisory lock ... failed to release`. That is the single signal that the connection-pinning mechanism has regressed, and the README itself says no unit test can catch that regression. A signal that important should not be a prose substring that a reworded log line silently breaks.

- [ ] **Step 1: Write the failing test**

Add to `EncryptionBackfillWorkerTest`:

```java
    @Test
    void lockReleaseFailureMarkerIsStable() {
        // This constant is what the README tells operators to alert on, and it is the only
        // signal that the connection-pinning regression the README describes has occurred.
        // Changing it is a breaking change to an operational interface.
        assertThat(EncryptionBackfillWorker.LOCK_RELEASE_FAILURE_MARKER)
                .isEqualTo("ENCRYPTION_BACKFILL_LOCK_RELEASE_FAILED");
    }
```

Add `import static org.assertj.core.api.Assertions.assertThat;` if the class lacks it.

- [ ] **Step 2: Run the test to verify it fails**

From `direct-file/backend/`:

```bash
./mvnw test -Dtest=EncryptionBackfillWorkerTest
```

Expected: FAIL to compile — `LOCK_RELEASE_FAILURE_MARKER` does not exist.

- [ ] **Step 3: Add the marker constant and use it**

In `EncryptionBackfillWorker.java`, alongside the existing `PROGRESS_MARKER` at `:44`:

```java
    /**
     * Stable marker for a failed advisory-lock release. Operators alert on this: it is the
     * only signal that the tick stopped being pinned to one connection, which no unit test
     * can detect (see the backfill section of README.md).
     */
    public static final String LOCK_RELEASE_FAILURE_MARKER = "ENCRYPTION_BACKFILL_LOCK_RELEASE_FAILED";
```

Then rewrite the warning at `:118` to lead with it, matching how `PROGRESS_MARKER` and `FAILURE_MARKER` are used:

```java
                log.warn(
                        "{}: advisory lock (id={}) failed to release -- it will remain held "
                                + "until this connection is returned to the pool and reset",
                        LOCK_RELEASE_FAILURE_MARKER,
                        lockId);
```

Read the existing statement before editing — preserve whatever trailing detail and arguments it already passes, and keep the placeholder count matching the argument count. `PROGRESS_MARKER` is currently `private`; leave it as it is rather than widening it for symmetry, since nothing needs it.

- [ ] **Step 4: Run the test to verify it passes**

```bash
./mvnw test -Dtest=EncryptionBackfillWorkerTest
```

Expected: PASS.

- [ ] **Step 5: Update the README's alert instruction**

In `direct-file/backend/README.md`, in the "Running it" paragraph of the H-1 Phase B section, replace the prose-substring instruction:

```
watch for `Encryption backfill advisory lock ... failed to
release` in the logs, which would indicate exactly that regression.
```

with:

```
alert on the marker `ENCRYPTION_BACKFILL_LOCK_RELEASE_FAILED`, which indicates exactly
that regression.
```

- [ ] **Step 6: Add the batch-size runbook note**

The reviewer's second point. In the same README section, immediately after the properties table, add:

```markdown
**Raising `batch-size` lengthens how long a snapshot is held.** `tick()` is
`@Transactional` for the whole batch — that is what pins the advisory lock to one
connection — so the outer transaction stays open until the batch finishes. A longer
transaction holds its snapshot longer, which delays `VACUUM` reclaiming the dead tuples
this sweep itself generates (every row it touches is an update). At the default of 100
this is irrelevant. If you raise it into five figures to finish the sweep faster, watch
table bloat on `taxreturns` and `taxreturn_submissions`, and prefer a shorter
`fixed-delay-millis` over a larger `batch-size` — more, smaller transactions get through
the same rows without holding a snapshot open.
```

- [ ] **Step 7: Format and commit**

```bash
./mvnw spotless:apply
git add direct-file/backend/
git commit -m "fix(backend): give the lock-release warning a stable marker constant

It was the only operationally-significant log line in the backfill without
one, and the README told operators to grep a prose substring for the single
signal that the connection-pinning mechanism has regressed.

Also documents that raising batch-size lengthens the snapshot hold and
delays VACUUM reclaiming the sweep's own dead tuples.

Addresses review feedback on #3."
```

---

## Task 2: Allowlist fields on every Logstash encoder

Defence at the encoder layer.

**Files:**
- Modify: `direct-file/backend/src/main/resources/logback.xml`
- Modify: `direct-file/backend/src/main/resources/logback-local.xml`
- Test: `direct-file/backend/src/test/java/gov/irs/directfile/api/audit/LogbackEncoderAllowlistTest.java`

**Interfaces:**
- Consumes: nothing from other tasks.
- Produces: a guard test asserting every logback configuration using `LogstashEncoder` also declares at least one `includeKeyValueKeyName` and one `includeMdcKeyName`.

**Design note.** The guard test reads the configuration files as text and checks for co-occurrence rather than parsing them as XML. These files carry a `<!DOCTYPE configuration>` declaration, and this repository's `XmlProcessor` deliberately sets `disallow-doctype-decl=true` — so an XML-parsing test would either have to contradict that convention or special-case around it, for no gain. A substring check is sufficient to answer the only question being asked: does this encoder have an allowlist at all?

- [ ] **Step 1: Write the failing test**

Create `direct-file/backend/src/test/java/gov/irs/directfile/api/audit/LogbackEncoderAllowlistTest.java`:

```java
package gov.irs.directfile.api.audit;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.stream.Stream;

import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Guards the M-1 fix: the audit event map is serialized by LogstashEncoder as fluent
 * key-value pairs, and an encoder with no includeKeyValueKeyName entries emits every one
 * of them. The same applies to MDC entries and includeMdcKeyName.
 *
 * <p>Any new logback configuration that uses LogstashEncoder must declare an allowlist,
 * or taxpayer identifiers reach log output the moment someone adds one to the audit map.
 */
class LogbackEncoderAllowlistTest {

    private static final Path RESOURCES = Path.of("src/main/resources");

    static Stream<Path> logbackConfigurations() throws IOException {
        try (Stream<Path> files = Files.list(RESOURCES)) {
            return files.filter(p -> p.getFileName().toString().startsWith("logback"))
                    .filter(p -> p.getFileName().toString().endsWith(".xml"))
                    .toList()
                    .stream();
        }
    }

    @ParameterizedTest
    @MethodSource("logbackConfigurations")
    void everyLogstashEncoderDeclaresAnAllowlist(Path config) throws IOException {
        String contents = Files.readString(config, StandardCharsets.UTF_8);

        if (!contents.contains("LogstashEncoder")) {
            // Pattern-based configurations do not render fluent key-value pairs at all.
            return;
        }

        assertThat(contents)
                .as(
                        "%s uses LogstashEncoder but declares no includeKeyValueKeyName, so it emits "
                                + "every audit event property including any taxpayer identifier",
                        config.getFileName())
                .contains("includeKeyValueKeyName");

        assertThat(contents)
                .as(
                        "%s uses LogstashEncoder but declares no includeMdcKeyName, so it emits every "
                                + "MDC entry",
                        config.getFileName())
                .contains("includeMdcKeyName");
    }

    @ParameterizedTest
    @MethodSource("logbackConfigurations")
    void noConfigurationAllowlistsATaxpayerIdentifier(Path config) throws IOException {
        String contents = Files.readString(config, StandardCharsets.UTF_8);

        // If someone ever adds these to an allowlist, that is a deliberate act that should
        // fail here rather than pass silently.
        List<String> forbidden = List.of(
                "<includeKeyValueKeyName>userTin</includeKeyValueKeyName>",
                "<includeMdcKeyName>email</includeMdcKeyName>");

        assertThat(forbidden).allSatisfy(entry -> assertThat(contents)
                .as("%s allowlists a taxpayer identifier: %s", config.getFileName(), entry)
                .doesNotContain(entry));
    }
}
```

- [ ] **Step 2: Run the test to verify it fails**

```bash
./mvnw test -Dtest=LogbackEncoderAllowlistTest
```

Expected: FAIL on `logback.xml` and `logback-local.xml` for `everyLogstashEncoderDeclaresAnAllowlist` — both use `LogstashEncoder` with no allowlist of either kind. `logback-minimal.xml` passes (it has three `includeKeyValueKeyName` and three `includeMdcKeyName`). `logback-debug.xml` short-circuits at the `LogstashEncoder` check.

If the test errors on the working directory instead, the surefire working directory is not the module root — resolve `RESOURCES` from the classpath instead, or make the path absolute from `System.getProperty("user.dir")`.

- [ ] **Step 3: Add the allowlist to `logback.xml`**

In `direct-file/backend/src/main/resources/logback.xml`, inside the `<encoder>` element, after `<customFields>`, add the same allowlist `logback-minimal.xml` uses:

```xml
      <!-- Only include the following fields from the Mapped Diagnostic Context (MDC). -->
      <!-- Other MDC fields will be excluded. -->
      <includeMdcKeyName>requestUri</includeMdcKeyName>
      <includeMdcKeyName>requestMethod</includeMdcKeyName>
      <includeMdcKeyName>responseStatusCode</includeMdcKeyName>

      <!-- Only include the following fluent API key value pairs. -->
      <!-- Other key value pairs will be excluded. Without this, every audit event -->
      <!-- property is emitted, including taxpayer identifiers. -->
      <includeKeyValueKeyName>eventTimestamp</includeKeyValueKeyName>
      <includeKeyValueKeyName>eventStatus</includeKeyValueKeyName>
      <includeKeyValueKeyName>eventId</includeKeyValueKeyName>
```

This file matters more than its usage suggests: `logback.xml` is the name Logback discovers automatically from the classpath, so it is what loads if `logging.config` is ever unset or overridden.

- [ ] **Step 4: Add the allowlist to `logback-local.xml`**

Add the identical block to `direct-file/backend/src/main/resources/logback-local.xml`, in the same position inside its `<encoder>`.

Local development is only partly insulated today: `FakePIIService` supplies a fixed fake TIN, so a developer sees `123001234` rather than a real one — but that is a property of the fake identity provider, not of the logging configuration, and it does not hold for anyone running locally against real data.

- [ ] **Step 5: Run the test to verify it passes**

```bash
./mvnw test -Dtest=LogbackEncoderAllowlistTest
```

Expected: PASS for all four configurations.

- [ ] **Step 6: Confirm nothing depended on the wider output**

```bash
grep -rn "userTin\|sadiUserUuid\|googleAnalyticsId" direct-file/backend/src/test --include="*.java" | head
```

If a test asserts on log output containing a now-excluded field, it was asserting on the leak. Update the test to match the allowlist rather than widening the allowlist.

- [ ] **Step 7: Run the whole suite, format, and commit**

```bash
./mvnw test
./mvnw spotless:apply
git add direct-file/backend/
git commit -m "fix(backend): allowlist emitted fields on every Logstash encoder

logback.xml and logback-local.xml used LogstashEncoder with no
includeKeyValueKeyName or includeMdcKeyName, so both emitted every audit
event property and every MDC entry. logback.xml is the name Logback
discovers automatically, so it is what loads if logging.config is unset.

Adds a guard test so a new configuration cannot reintroduce this.

Refs M-1."
```

---

## Task 3: Stop the raw TIN entering the audit event map

Defence at the source. Task 2 means no *current* encoder emits the TIN; this means no *future* one can.

**Files:**
- Modify: `direct-file/backend/src/main/java/gov/irs/directfile/api/audit/AuditLogElement.java`
- Modify: `direct-file/backend/src/main/java/gov/irs/directfile/api/user/UserService.java:32`
- Test: `direct-file/backend/src/test/java/gov/irs/directfile/api/user/UserServiceTest.java`

**Interfaces:**
- Consumes: nothing from other tasks.
- Produces:
  - `AuditLogElement.USER_TIN_LAST4` — renders as `userTinLast4` through the enum's `CaseUtils` `toString`.
  - `AuditLogElement.USER_TIN` is **removed**.
  - `UserService.getCurrentUserInfo()` adds the last four digits instead of the full TIN. `UserInfo` still carries the full TIN — that is a return value to application code, not a log field, and is unchanged.

**Design note — why last-4 rather than a hash or nothing.** Three options were considered:

- *Remove the field entirely.* Cleanest disclosure-wise, but the audit trail supports fraud investigation and removing the only tax-identifier correlate is a capability loss this plan should not impose unilaterally.
- *Keyed HMAC.* Preserves full correlation with no disclosure, but introduces a new secret to manage — and this codebase just spent Tranche 1 removing a committed signing key (M-5). `EmailAllowlistFeatureService` shows the shape and also shows the failure mode: its `hexKey` is `null` in this repository (L-2). Adding a second key with the same lifecycle problem is a poor trade for an audit field.
- *Last four digits.* No key management, preserves the correlation an investigator actually performs against a support ticket or an IRS record, and reduces a full identifier to a fragment. Chosen.

`USER_TIN_TYPE` is untouched — it carries no identifier.

**Handback — this renames a field in a downstream interface.** Audit logs are consumed outside this repository, and a SIEM parser or saved query keyed on `userTin` will stop matching. Confirm with the audit-log consumers before merging, and give them the new name. That confirmation is the reason the enum constant is *removed* rather than left in place unused: a rename that silently leaves the old key available is a rename that never finishes.

- [ ] **Step 1: Write the failing test**

Add to `direct-file/backend/src/test/java/gov/irs/directfile/api/user/UserServiceTest.java`, matching the Mockito setup already in that class:

```java
    @Test
    void getCurrentUserInfo_recordsOnlyTheLastFourTinDigits() {
        IdentityAttributes attributes = new IdentityAttributes(
                UUID.randomUUID(), UUID.randomUUID(), "taxpayer@example.com", "123456789");
        when(identitySupplier.get()).thenReturn(attributes);

        userService.getCurrentUserInfo();

        verify(auditService).addEventProperty(AuditLogElement.USER_TIN_LAST4, "6789");
        verify(auditService, never()).addEventProperty(eq(AuditLogElement.USER_TIN_LAST4), eq("123456789"));
    }

    @Test
    void getCurrentUserInfo_stillReturnsTheFullTinToCallers() {
        IdentityAttributes attributes = new IdentityAttributes(
                UUID.randomUUID(), UUID.randomUUID(), "taxpayer@example.com", "123456789");
        when(identitySupplier.get()).thenReturn(attributes);

        UserInfo info = userService.getCurrentUserInfo();

        // The TIN is still needed by application code; this change is about what is logged.
        assertThat(info.tin()).isEqualTo("123456789");
    }

    @Test
    void getCurrentUserInfo_handlesAShortOrMissingTinWithoutThrowing() {
        IdentityAttributes shortTin = new IdentityAttributes(
                UUID.randomUUID(), UUID.randomUUID(), "taxpayer@example.com", "12");
        when(identitySupplier.get()).thenReturn(shortTin);

        userService.getCurrentUserInfo();

        // Never pad, never substring past the end, never log more than four characters.
        verify(auditService).addEventProperty(AuditLogElement.USER_TIN_LAST4, "12");
    }
```

`IdentityAttributes` is `record IdentityAttributes(UUID id, UUID externalId, String email, String tin)` — the argument order above matches it. Note the compiler cannot catch a swap between `email` and `tin`, so keep them in that order.

- [ ] **Step 2: Run the test to verify it fails**

```bash
./mvnw test -Dtest=UserServiceTest
```

Expected: FAIL to compile — `AuditLogElement.USER_TIN_LAST4` does not exist.

- [ ] **Step 3: Replace the enum constant**

In `AuditLogElement.java`, remove `USER_TIN` and add `USER_TIN_LAST4`, keeping the alphabetical ordering the enum already follows:

```java
    USER_TIN_LAST4,
    USER_TIN_TYPE,
```

Removing `USER_TIN` is deliberate — leaving it in place would let a future caller reintroduce the raw value. The compiler now finds every use.

- [ ] **Step 4: Change the call site**

In `UserService.java`, replace line 32:

```java
        auditService.addEventProperty(AuditLogElement.USER_TIN, attributes.tin());
```

with:

```java
        auditService.addEventProperty(AuditLogElement.USER_TIN_LAST4, lastFour(attributes.tin()));
```

and add the helper to the class:

```java
    /**
     * The last four digits of a TIN, for audit correlation.
     *
     * <p>The full TIN must not enter the audit event map: AuditService serializes every
     * property in that map as a fluent key-value pair, so whether it reaches log output
     * depends entirely on each encoder's allowlist. Four digits support the correlation an
     * investigator actually performs without putting the identifier itself one
     * configuration mistake away from being logged.
     *
     * <p>Returns null for a null TIN — AuditService.addEventProperty already ignores null
     * values — and returns the input unchanged if it is shorter than four characters,
     * rather than throwing.
     */
    private static String lastFour(String tin) {
        if (tin == null) {
            return null;
        }
        return tin.length() <= 4 ? tin : tin.substring(tin.length() - 4);
    }
```

- [ ] **Step 5: Fix every other reference the compiler finds**

```bash
./mvnw -q compile 2>&1 | grep -i "USER_TIN" | head
grep -rn "USER_TIN\b" direct-file/backend/src --include="*.java" | grep -v USER_TIN_TYPE | grep -v USER_TIN_LAST4
```

Update each hit. If any is a *test* asserting the full TIN was recorded, that test was pinning the behavior being removed — change the assertion, do not restore the constant.

- [ ] **Step 6: Run the tests to verify they pass**

```bash
./mvnw test -Dtest=UserServiceTest
```

Expected: PASS.

- [ ] **Step 7: Run the whole suite, format, and commit**

```bash
./mvnw test
./mvnw spotless:apply
git add direct-file/backend/
git commit -m "fix(backend): record only the last four TIN digits in the audit map

AuditService serializes every property in the event map as a fluent
key-value pair, so a raw TIN in that map is one encoder allowlist away from
log output. Four digits preserve investigative correlation without putting
the identifier there in the first place.

USER_TIN is removed rather than deprecated so the compiler finds every use.
This renames userTin to userTinLast4 in audit output -- downstream consumers
need the new name.

Refs M-1."
```

---

## Task 4: Stop returning exception messages to clients

**Files:**
- Modify: `direct-file/backend/src/main/resources/application.yaml:58`
- Test: `direct-file/backend/src/test/java/gov/irs/directfile/api/errors/ErrorMessageExposureTest.java`

**Interfaces:**
- Consumes: nothing from other tasks.
- Produces: no code interface. `server.error.include-message` becomes `never`.

**Why.** `include-message: always` puts the exception message into Spring's JSON error body. `TaxReturnController:123` funnels unexpected failures through `throw new RuntimeException(e)`, so driver-level, persistence-level, and third-party messages can surface to callers. The application already defines curated error codes (`ApiErrorResponse`, `ErrorResponse`, `StateApiErrorCode`); those are what callers should get.

- [ ] **Step 1: Write the failing test**

Create `direct-file/backend/src/test/java/gov/irs/directfile/api/errors/ErrorMessageExposureTest.java`:

```java
package gov.irs.directfile.api.errors;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;

import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Guards M-4. server.error.include-message controls whether Spring copies the exception
 * message into the JSON error body. TaxReturnController funnels unexpected failures
 * through `throw new RuntimeException(e)`, so with `always` the underlying driver or
 * persistence message reaches the caller.
 */
class ErrorMessageExposureTest {

    @Test
    void applicationYamlDoesNotIncludeExceptionMessagesInErrorResponses() throws IOException {
        String applicationYaml =
                Files.readString(Path.of("src/main/resources/application.yaml"), StandardCharsets.UTF_8);

        assertThat(applicationYaml)
                .as("server.error.include-message must not be 'always' -- it leaks exception "
                        + "messages to API clients")
                .doesNotContain("include-message: always");
        assertThat(applicationYaml).contains("include-message: never");
    }
}
```

- [ ] **Step 2: Run the test to verify it fails**

```bash
./mvnw test -Dtest=ErrorMessageExposureTest
```

Expected: FAIL — `application.yaml` currently contains `include-message: always`.

- [ ] **Step 3: Change the setting**

In `direct-file/backend/src/main/resources/application.yaml`, change line 58:

```yaml
  error:
    # never: exception messages must not reach API clients. Unexpected failures are
    # funnelled through RuntimeException in places (e.g. TaxReturnController), so 'always'
    # surfaces driver and persistence messages. Callers get the curated codes in
    # gov.irs.directfile.api.errors instead.
    include-message: never
```

- [ ] **Step 4: Run the test to verify it passes**

```bash
./mvnw test -Dtest=ErrorMessageExposureTest
```

Expected: PASS.

- [ ] **Step 5: Check the other services for the same setting**

```bash
grep -rn "include-message" direct-file/*/src/main/resources/*.yaml
```

`state-api`, `status`, `submit`, and `email-service` each have their own configuration. If any sets `always`, change it the same way and extend the commit. If a service has no setting, Spring's default is `never` — leave it alone.

- [ ] **Step 6: Confirm no test depended on the message being returned**

```bash
./mvnw test
```

Expected: PASS. A test asserting on an exception message in a response body was asserting on the leak — assert on the status code and error code instead.

- [ ] **Step 7: Commit**

```bash
git add direct-file/
git commit -m "fix(backend): stop returning exception messages to API clients

include-message: always put the underlying exception message in the JSON
error body, and unexpected failures are funnelled through RuntimeException,
so driver and persistence messages reached callers.

Refs M-4."
```

---

## Verification

- [ ] **Full backend suite**

```bash
cd /Users/thomaswarn/repo/direct-file/direct-file/backend
./mvnw clean test
```

Expected: PASS, zero failures.

- [ ] **Prove the TIN is gone from log output**

The guard tests check configuration; this checks behavior. Run the backend locally against each configuration and exercise an authenticated request that reaches `getCurrentUserInfo`:

```bash
for cfg in logback-minimal logback logback-local; do
  echo "=== $cfg ==="
  # start the app with -Dlogging.config=classpath:$cfg.xml, hit an authenticated endpoint,
  # then grep the captured output
done
```

**Expected: no `userTin` key in any output, and a `userTinLast4` of at most four characters where the audit event is emitted.** Under `logback-minimal.xml`, `userTinLast4` should be absent too — it is not on that file's allowlist, which is correct: the deployed default emits only the three event fields.

- [ ] **Prove exception messages no longer reach clients**

Trigger the `TaxReturnController:123` path (or any handler that funnels to `RuntimeException`) and confirm the JSON error body carries a status and the application's own error code, with no `message` field echoing the underlying exception.

- [ ] **Confirm the change surface**

```bash
git diff --stat origin/main
```

Expected: changes only under `direct-file/backend/` — plus other services' `application.yaml` if Step 5 of Task 4 found any. No changes to `libs/data-models`, `df-client`, or the encryption layer.

## Handback to the milestone owner

1. **Tell the audit-log consumers that `userTin` is now `userTinLast4`.** A SIEM parser or saved query keyed on the old name stops matching silently. This is the only downstream-visible change in the plan.
2. **Decide whether `userTinLast4` belongs on `logback-minimal.xml`'s allowlist.** This plan does not add it, so the deployed default emits only `eventTimestamp`, `eventStatus`, `eventId` — as it does today. If investigators need the fragment in production logs, adding it is a one-line change, but it is a disclosure decision rather than an engineering one.
3. **M-2 still needs the edge topology.** Which proxies are trusted, and does the edge strip inbound `True-Client-IP` and `X-Forwarded-For`? Until that is answered, the audit trail's client IP remains caller-controlled.
4. **L-7 needs its own plan.** There is no `.github/` directory and no CI pipeline on `origin/main`, so dependency scanning is "stand up CI" rather than "add a scanner".
