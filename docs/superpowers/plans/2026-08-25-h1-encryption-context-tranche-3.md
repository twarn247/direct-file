# H-1 — Encryption Context Verification (Tranche 3, Phase A) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make every ciphertext this repository writes carry a verified statement of what kind of plaintext it holds, and make every decrypt path reject a blob whose statement disagrees with what the caller asked for — so a tax-return facts blob, a store blob, and a state-export token stop being mutually substitutable under the shared CMK.

**Architecture:** The change centres on `libs/data-models`, which owns the only encrypt and decrypt primitives in the codebase. A new closed vocabulary (`EncryptionPurpose`) and a context builder (`EncryptionContexts`) are added there; `DataEncryptDecrypt` gains purpose-aware `encrypt`/`decrypt`; `FactsEncryptor` and `GenericStringEncryptor` thread the purpose through. The two downstream services then adopt it: `backend`'s `TaxReturnEntityListener` (which today writes facts and store under one identical context) and `state-api`'s `AuthorizationTokenService`. Nothing about the wire protocol, the JWT exchange, or the KMS key configuration changes, so no state partner integration is affected.

This is **Phase A only** — normalize writes, verify reads, ship in `warn`. Phase B (backfilling existing rows) and Phase C (flipping to `enforce`) are deliberately not in this plan; §6 of the spec says why.

**Tech Stack:** Java 21, Spring Boot 3.3.10, AWS Encryption SDK for Java 3.0.1 (`aws-encryption-sdk.version` in `direct-file/boms/irs-spring-boot-starter-parent/pom.xml:23`), Lombok, Maven (`./mvnw`), JUnit 5 + Mockito + AssertJ, `reactor-test` StepVerifier for state-api. Spotless with palantir-java-format.

**Spec:** `docs/security/2026-08-25_h1-encryption-context-spec.md`

## Global Constraints

- **Java 21.** Do not use preview features.
- **Format before every commit.** Run `./mvnw spotless:apply` from whichever module you touched (`libs/`, `backend/`, `state-api/`). CI enforces palantir-java-format 2.39.0; an unformatted commit fails the build.
- **Three separate Maven modules.** `libs/data-models` is consumed by `backend` and `state-api` as a dependency. After changing `libs/`, run `cd direct-file/libs && ./mvnw install -DskipTests` before the downstream modules will see the change.
- **Additive first, delete last.** Tasks 1–5 only *add* API surface; the old `encrypt(byte[], Map)` and `decrypt(byte[])` are removed in Task 6. This is deliberate: it keeps every intermediate commit compiling and green, which a signature change in a shared library otherwise makes impossible. Do not "tidy up" by deleting early.
- **Never log plaintext, and never log a context value.** The `id` key carries a user external ID. Log the *expected purpose* and the *found purpose*, nothing else.
- **No new dependencies.** In particular, do not add Micrometer to `libs/data-models` to get a counter — it is not on that module's classpath (`libs/data-models/pom.xml` pulls `spring-boot-starter`, not `-actuator`), the repository has no metrics convention, and a log marker serves the Phase C gate equally well.

## Scope note

Out of scope, per spec §5, and **do not extend the plan to cover them**:

- `PopulatedData.dataCipherText` / `rawDataCipherText` — written outside this repository. Their read paths are pinned legacy-tolerant in Task 4 and must stay that way.
- `User.emailCipherText` / `User.tinCipherText` — no reader or writer in this repository.
- Any change to the CMK, its policy, or key separation.

---

## Task 1: Add the encryption context vocabulary

Spec §3.1. Pure addition — a new enum and a new builder, plus their tests. Nothing calls them yet.

**Files:**
- Create: `direct-file/libs/data-models/src/main/java/gov/irs/directfile/models/encryption/EncryptionPurpose.java`
- Create: `direct-file/libs/data-models/src/main/java/gov/irs/directfile/models/encryption/EncryptionContexts.java`
- Create: `direct-file/libs/data-models/src/test/java/gov/irs/directfile/models/encryption/EncryptionContextsTest.java`

**Interfaces:**
- Produces: `EncryptionPurpose` (closed enum, `wireValue()` accessor, `fromWireValue(String)` returning `Optional`), and `EncryptionContexts.forPurpose(...)` returning an immutable `Map<String,String>`.
- Consumes: nothing.

**Design note.** The wire value is a string constant separate from the Java enum name, because the enum name is refactorable and the wire value is baked into every ciphertext ever written and can never change. Keeping them separate makes that constraint visible at the point where someone would otherwise rename an enum constant and silently invalidate the corpus.

- [ ] **Step 1: Write the failing tests**

Create `EncryptionContextsTest.java`:

```java
package gov.irs.directfile.models.encryption;

import java.util.Map;

import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

public class EncryptionContextsTest {

    @Test
    void forPurpose_setsPurposeAndSystem() {
        Map<String, String> context = EncryptionContexts.forPurpose(EncryptionPurpose.TAX_RETURN_FACTS);
        assertThat(context)
                .containsEntry("purpose", "tax-return-facts")
                .containsEntry("system", "DIRECT-FILE")
                .doesNotContainKey("id");
    }

    @Test
    void forPurpose_withActorId_addsIdWithoutDisturbingVerifiedKeys() {
        Map<String, String> context =
                EncryptionContexts.forPurpose(EncryptionPurpose.TAX_RETURN_STORE, "abc-123");
        assertThat(context)
                .containsEntry("purpose", "tax-return-store")
                .containsEntry("system", "DIRECT-FILE")
                .containsEntry("id", "abc-123");
    }

    @Test
    void forPurpose_withNullOrBlankActorId_omitsIdRatherThanWritingEmpty() {
        assertThat(EncryptionContexts.forPurpose(EncryptionPurpose.TAX_RETURN_STORE, null))
                .doesNotContainKey("id");
        assertThat(EncryptionContexts.forPurpose(EncryptionPurpose.TAX_RETURN_STORE, "   "))
                .doesNotContainKey("id");
    }

    @Test
    void forPurpose_returnsAnImmutableMap() {
        Map<String, String> context = EncryptionContexts.forPurpose(EncryptionPurpose.STATE_EXPORT_TOKEN);
        assertThatThrownBy(() -> context.put("purpose", "something-else"))
                .isInstanceOf(UnsupportedOperationException.class);
    }

    @Test
    void everyPurposeHasADistinctWireValue() {
        long distinct = java.util.Arrays.stream(EncryptionPurpose.values())
                .map(EncryptionPurpose::wireValue)
                .distinct()
                .count();
        assertThat(distinct).isEqualTo(EncryptionPurpose.values().length);
    }

    @Test
    void factsAndStoreAreDistinguishable() {
        // The whole point of the finding: these two were identical before this change.
        assertThat(EncryptionContexts.forPurpose(EncryptionPurpose.TAX_RETURN_FACTS))
                .isNotEqualTo(EncryptionContexts.forPurpose(EncryptionPurpose.TAX_RETURN_STORE));
    }

    @Test
    void fromWireValue_roundTripsAndRejectsUnknown() {
        assertThat(EncryptionPurpose.fromWireValue("tax-return-facts"))
                .contains(EncryptionPurpose.TAX_RETURN_FACTS);
        assertThat(EncryptionPurpose.fromWireValue("not-a-purpose")).isEmpty();
        assertThat(EncryptionPurpose.fromWireValue(null)).isEmpty();
    }
}
```

- [ ] **Step 2: Run the tests to verify they fail**

```bash
cd /Users/thomaswarn/repo/direct-file/direct-file/libs
./mvnw -pl data-models test -Dtest=EncryptionContextsTest
```

Expected: compilation failure — `EncryptionContexts` and `EncryptionPurpose` do not exist.

- [ ] **Step 3: Implement `EncryptionPurpose`**

```java
package gov.irs.directfile.models.encryption;

import java.util.Optional;

/**
 * What kind of plaintext a ciphertext holds. Bound into the AWS Encryption SDK
 * encryption context under the "purpose" key and verified on decrypt, so that a
 * blob of one kind cannot be substituted for a blob of another under the shared CMK.
 *
 * <p>The wire value is deliberately separate from the enum constant name. The enum
 * name can be refactored; the wire value is baked into every ciphertext ever written
 * and can never change.
 */
public enum EncryptionPurpose {
    TAX_RETURN_FACTS("tax-return-facts"),
    TAX_RETURN_STORE("tax-return-store"),
    STATE_EXPORT_TOKEN("state-export-token"),

    /**
     * Read-only in this repository: the writers of these two populations live outside it,
     * so nothing here ever encrypts under them. See the spec, §2.3.
     */
    DATA_IMPORT_POPULATED_DATA("data-import-populated-data"),
    DATA_IMPORT_RAW_RESPONSE("data-import-raw-response");

    private final String wireValue;

    EncryptionPurpose(String wireValue) {
        this.wireValue = wireValue;
    }

    public String wireValue() {
        return wireValue;
    }

    public static Optional<EncryptionPurpose> fromWireValue(String wireValue) {
        if (wireValue == null) {
            return Optional.empty();
        }
        for (EncryptionPurpose purpose : values()) {
            if (purpose.wireValue.equals(wireValue)) {
                return Optional.of(purpose);
            }
        }
        return Optional.empty();
    }
}
```

- [ ] **Step 4: Implement `EncryptionContexts`**

```java
package gov.irs.directfile.models.encryption;

import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Builds AWS Encryption SDK encryption contexts. Every context this codebase writes
 * comes from here, so that no call site can produce an untagged one by hand.
 *
 * <p>{@code purpose} is verified on decrypt. {@code system} and {@code id} are not:
 * {@code id} records who wrote the blob, which is useful for KMS CloudTrail attribution
 * and cannot be checked at read time, because the reader is not necessarily the writer
 * and, at {@code @PostLoad}, there may be no authenticated principal at all.
 */
public final class EncryptionContexts {
    public static final String PURPOSE_KEY = "purpose";
    public static final String SYSTEM_KEY = "system";
    public static final String ID_KEY = "id";

    public static final String SYSTEM_VALUE = "DIRECT-FILE";

    private EncryptionContexts() {}

    public static Map<String, String> forPurpose(EncryptionPurpose purpose) {
        return forPurpose(purpose, null);
    }

    public static Map<String, String> forPurpose(EncryptionPurpose purpose, String actorId) {
        if (purpose == null) {
            throw new IllegalArgumentException("encryption purpose is required");
        }
        Map<String, String> context = new LinkedHashMap<>();
        context.put(PURPOSE_KEY, purpose.wireValue());
        context.put(SYSTEM_KEY, SYSTEM_VALUE);
        if (actorId != null && !actorId.isBlank()) {
            context.put(ID_KEY, actorId);
        }
        return Map.copyOf(context);
    }
}
```

- [ ] **Step 5: Run the tests to verify they pass**

```bash
cd /Users/thomaswarn/repo/direct-file/direct-file/libs
./mvnw -pl data-models test -Dtest=EncryptionContextsTest
```

Expected: PASS.

- [ ] **Step 6: Format and commit**

```bash
cd /Users/thomaswarn/repo/direct-file/direct-file/libs
./mvnw spotless:apply
cd /Users/thomaswarn/repo/direct-file
git add -A && git commit -m "feat(data-models): add encryption purpose vocabulary and context builder"
```

---

## Task 2: Verify the purpose on decrypt

Spec §3.2 and §3.3. This is the finding's actual fix. Additive: new overloads alongside the existing methods.

**Files:**
- Modify: `direct-file/libs/data-models/src/main/java/gov/irs/directfile/models/encryption/DataEncryptDecrypt.java`
- Create: `direct-file/libs/data-models/src/main/java/gov/irs/directfile/models/encryption/EncryptionContextMismatchException.java`
- Create: `direct-file/libs/data-models/src/main/java/gov/irs/directfile/models/autoconfigure/EncryptionContextProperties.java`
- Modify: `direct-file/libs/data-models/src/main/java/gov/irs/directfile/models/autoconfigure/EncryptionAutoConfiguration.java`
- Create: `direct-file/libs/data-models/src/test/java/gov/irs/directfile/models/encryption/DataEncryptDecryptTest.java`

**Interfaces:**
- Produces: `encrypt(byte[], EncryptionPurpose, String actorId)`, `decrypt(byte[], EncryptionPurpose expected)`, `decryptLegacyTolerant(byte[], EncryptionPurpose expected)`, and a new property `direct-file.encryption.context-verification` (`warn` | `enforce`, default `warn`).
- Consumes: `EncryptionPurpose`, `EncryptionContexts` from Task 1.

**Design notes.**

*Three-branch rule, and why the middle branch is unconditional.* A `purpose` that is present and wrong is rejected in **both** modes; only a *missing* `purpose` is governed by the mode. That is what makes the dual-read window safe: substitution is closed for every blob written after deploy, and the mode only decides how long previously written blobs are tolerated.

*Why a separate `decryptLegacyTolerant`.* The data-import read paths must stay legacy-tolerant permanently, because this plan cannot migrate their writers (spec §2.3). Expressing that as a distinct method rather than a config exemption means the permanent exception is visible in the code at the call site and cannot be widened by a config change.

*Zero the plaintext before throwing.* On a mismatch we hold decrypted plaintext we have decided not to return. Overwrite the array before throwing so it is not left in a heap dump.

*Rate-limit the legacy log.* A large read of untouched rows would otherwise flood logs. Log the first occurrence per purpose per JVM at WARN, then every 1000th, always including the running count. The stable marker `ENCRYPTION_CONTEXT_LEGACY` is the Phase C gate: when a log query for it returns zero across the observation window, the mode can flip.

*Do not use Lombok's `@AllArgsConstructor` for the new field.* Write the constructor explicitly — the class is registered via `@Import(DataEncryptDecrypt.class)` and the third argument needs to resolve as a bean, which is clearer spelled out.

- [ ] **Step 1: Write the failing tests**

Create `DataEncryptDecryptTest.java`. These use **real** crypto via a `JceMasterKey`, not a mock — the point is to prove the ESDK actually round-trips the context, which a mock would assume rather than test. The `JceMasterKey` construction mirrors `EncryptionAutoConfiguration.LocalEncryptionConfiguration.wrappingKeyProvider()`.

```java
package gov.irs.directfile.models.encryption;

import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import javax.crypto.spec.SecretKeySpec;

import java.util.concurrent.TimeUnit;

import com.amazonaws.encryptionsdk.AwsCrypto;
import com.amazonaws.encryptionsdk.CryptoMaterialsManager;
import com.amazonaws.encryptionsdk.caching.CachingCryptoMaterialsManager;
import com.amazonaws.encryptionsdk.caching.LocalCryptoMaterialsCache;
import com.amazonaws.encryptionsdk.jce.JceMasterKey;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import gov.irs.directfile.models.autoconfigure.EncryptionContextProperties;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

public class DataEncryptDecryptTest {
    private static final byte[] PLAINTEXT = "some plaintext".getBytes(StandardCharsets.UTF_8);

    private CryptoMaterialsManager cmm;
    private AwsCrypto awsCrypto;

    @BeforeEach
    void setUp() {
        byte[] rawKey = new byte[32];
        new SecureRandom().nextBytes(rawKey);
        JceMasterKey masterKey = JceMasterKey.getInstance(
                new SecretKeySpec(rawKey, "AES"), "local", "local", "AES/GCM/NoPadding");
        cmm = CachingCryptoMaterialsManager.newBuilder()
                .withMasterKeyProvider(masterKey)
                .withCache(new LocalCryptoMaterialsCache(10))
                .withMaxAge(60, TimeUnit.SECONDS)
                .withMessageUseLimit(1000)
                .build();
        awsCrypto = AwsCrypto.standard();
    }

    private DataEncryptDecrypt subject(String mode) {
        EncryptionContextProperties properties = new EncryptionContextProperties();
        properties.setContextVerification(mode);
        return new DataEncryptDecrypt(awsCrypto, cmm, properties);
    }

    @Test
    void roundTripsUnderMatchingPurpose() {
        DataEncryptDecrypt subject = subject("warn");
        byte[] ciphertext = subject.encrypt(PLAINTEXT, EncryptionPurpose.TAX_RETURN_FACTS, null);
        assertThat(subject.decrypt(ciphertext, EncryptionPurpose.TAX_RETURN_FACTS)).isEqualTo(PLAINTEXT);
    }

    @Test
    void rejectsAStoreBlobPresentedAsFacts_inWarnMode() {
        // The substitution the finding is about. Rejected regardless of mode.
        DataEncryptDecrypt subject = subject("warn");
        byte[] ciphertext = subject.encrypt(PLAINTEXT, EncryptionPurpose.TAX_RETURN_STORE, null);
        assertThatThrownBy(() -> subject.decrypt(ciphertext, EncryptionPurpose.TAX_RETURN_FACTS))
                .isInstanceOf(EncryptionContextMismatchException.class);
    }

    @Test
    void rejectsAStateExportTokenPresentedAsFacts() {
        DataEncryptDecrypt subject = subject("warn");
        byte[] ciphertext = subject.encrypt(PLAINTEXT, EncryptionPurpose.STATE_EXPORT_TOKEN, null);
        assertThatThrownBy(() -> subject.decrypt(ciphertext, EncryptionPurpose.TAX_RETURN_FACTS))
                .isInstanceOf(EncryptionContextMismatchException.class);
    }

    @Test
    void acceptsLegacyUntaggedCiphertext_inWarnMode() {
        DataEncryptDecrypt subject = subject("warn");
        byte[] legacy = awsCrypto
                .encryptData(cmm, PLAINTEXT, java.util.Map.of("system", "DIRECTFILE", "type", "API"))
                .getResult();
        assertThat(subject.decrypt(legacy, EncryptionPurpose.TAX_RETURN_FACTS)).isEqualTo(PLAINTEXT);
    }

    @Test
    void rejectsLegacyUntaggedCiphertext_inEnforceMode() {
        DataEncryptDecrypt subject = subject("enforce");
        byte[] legacy = awsCrypto
                .encryptData(cmm, PLAINTEXT, java.util.Map.of("system", "DIRECTFILE", "type", "API"))
                .getResult();
        assertThatThrownBy(() -> subject.decrypt(legacy, EncryptionPurpose.TAX_RETURN_FACTS))
                .isInstanceOf(EncryptionContextMismatchException.class);
    }

    @Test
    void rejectsWrongPurpose_inEnforceMode_too() {
        DataEncryptDecrypt subject = subject("enforce");
        byte[] ciphertext = subject.encrypt(PLAINTEXT, EncryptionPurpose.TAX_RETURN_STORE, null);
        assertThatThrownBy(() -> subject.decrypt(ciphertext, EncryptionPurpose.TAX_RETURN_FACTS))
                .isInstanceOf(EncryptionContextMismatchException.class);
    }

    @Test
    void legacyTolerantDecryptAcceptsUntaggedEvenInEnforceMode() {
        // The data-import read paths, whose writers are outside this repository.
        DataEncryptDecrypt subject = subject("enforce");
        byte[] legacy = awsCrypto.encryptData(cmm, PLAINTEXT, java.util.Map.of()).getResult();
        assertThat(subject.decryptLegacyTolerant(legacy, EncryptionPurpose.DATA_IMPORT_POPULATED_DATA))
                .isEqualTo(PLAINTEXT);
    }

    @Test
    void legacyTolerantDecryptStillRejectsAWrongPurpose() {
        // Permanent legacy tolerance is not permission to accept a mislabelled blob.
        DataEncryptDecrypt subject = subject("enforce");
        byte[] ciphertext = subject.encrypt(PLAINTEXT, EncryptionPurpose.TAX_RETURN_FACTS, null);
        assertThatThrownBy(
                        () -> subject.decryptLegacyTolerant(ciphertext, EncryptionPurpose.DATA_IMPORT_POPULATED_DATA))
                .isInstanceOf(EncryptionContextMismatchException.class);
    }

    @Test
    void encryptBindsTheActorIdWithoutMakingItVerified() {
        DataEncryptDecrypt subject = subject("enforce");
        byte[] ciphertext = subject.encrypt(PLAINTEXT, EncryptionPurpose.TAX_RETURN_FACTS, "actor-1");
        // A different reader, with no actor of its own, still reads it.
        assertThat(subject.decrypt(ciphertext, EncryptionPurpose.TAX_RETURN_FACTS)).isEqualTo(PLAINTEXT);
    }

    @Test
    void mismatchMessageNamesPurposesAndNothingElse() {
        DataEncryptDecrypt subject = subject("warn");
        byte[] ciphertext = subject.encrypt(PLAINTEXT, EncryptionPurpose.TAX_RETURN_STORE, "actor-1");
        assertThatThrownBy(() -> subject.decrypt(ciphertext, EncryptionPurpose.TAX_RETURN_FACTS))
                .hasMessageContaining("tax-return-facts")
                .hasMessageContaining("tax-return-store")
                .hasMessageNotContaining("actor-1");
    }
}
```

The CMM here is built exactly as `EncryptionAutoConfiguration.awsCryptoMaterialsManager` builds it, over the `JceMasterKey` that `LocalEncryptionConfiguration.wrappingKeyProvider()` uses — every class involved is already on this module's classpath, so no new import can turn out to be unavailable. The test's requirement is only "a real CMM over a local JCE key"; the caching wrapper is incidental, and `withMessageUseLimit(1000)` is set simply so a test class with many encrypts never trips the limit.

- [ ] **Step 2: Run the tests to verify they fail**

```bash
cd /Users/thomaswarn/repo/direct-file/direct-file/libs
./mvnw -pl data-models test -Dtest=DataEncryptDecryptTest
```

Expected: compilation failure.

- [ ] **Step 3: Add the exception and the properties class**

`EncryptionContextMismatchException.java`:

```java
package gov.irs.directfile.models.encryption;

/**
 * Thrown when a ciphertext's bound encryption context does not carry the purpose the
 * caller expected. Carries no plaintext and no context values — only purpose names.
 */
public class EncryptionContextMismatchException extends RuntimeException {
    public EncryptionContextMismatchException(String message) {
        super(message);
    }
}
```

`EncryptionContextProperties.java` (mirrors the mutable-with-defaults style of `AWSCryptoCacheProperties`, so consumers that do not set it still start):

```java
package gov.irs.directfile.models.autoconfigure;

import lombok.Getter;
import lombok.Setter;
import org.springframework.boot.context.properties.ConfigurationProperties;

@Getter
@Setter
@ConfigurationProperties("direct-file.encryption")
public class EncryptionContextProperties {
    public static final String WARN = "warn";
    public static final String ENFORCE = "enforce";

    /**
     * How to treat ciphertext written before encryption contexts carried a purpose:
     * "warn" accepts and reports it, "enforce" rejects it. A ciphertext carrying the
     * <em>wrong</em> purpose is rejected under both.
     */
    private String contextVerification = WARN;

    public boolean isEnforcing() {
        return ENFORCE.equalsIgnoreCase(contextVerification);
    }
}
```

- [ ] **Step 4: Rewrite `DataEncryptDecrypt`**

Keep the existing `encrypt(byte[], Map)` and `decrypt(byte[])` untouched for now — Tasks 3–5 still call them. Remove `@AllArgsConstructor` in favour of an explicit constructor.

```java
package gov.irs.directfile.models.encryption;

import java.util.Arrays;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicLong;

import com.amazonaws.encryptionsdk.AwsCrypto;
import com.amazonaws.encryptionsdk.CryptoMaterialsManager;
import com.amazonaws.encryptionsdk.CryptoResult;
import edu.umd.cs.findbugs.annotations.SuppressFBWarnings;
import jakarta.annotation.PostConstruct;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;

import gov.irs.directfile.models.autoconfigure.EncryptionContextProperties;

@Component
@Slf4j
@SuppressFBWarnings(value = "DM_DEFAULT_ENCODING", justification = "Initial Spotbugs Setup")
@SuppressWarnings("PMD.UnusedPrivateMethod")
public class DataEncryptDecrypt {
    /** Stable log marker. The Phase C gate is a log query for this string returning zero. */
    private static final String LEGACY_MARKER = "ENCRYPTION_CONTEXT_LEGACY";

    private static final long LEGACY_LOG_EVERY = 1000L;

    private final AwsCrypto awsCrypto;
    private final CryptoMaterialsManager cryptoMaterialsManager;
    private final EncryptionContextProperties encryptionContextProperties;
    private final ConcurrentHashMap<EncryptionPurpose, AtomicLong> legacyCounts = new ConcurrentHashMap<>();

    public DataEncryptDecrypt(
            AwsCrypto awsCrypto,
            CryptoMaterialsManager cryptoMaterialsManager,
            EncryptionContextProperties encryptionContextProperties) {
        this.awsCrypto = awsCrypto;
        this.cryptoMaterialsManager = cryptoMaterialsManager;
        this.encryptionContextProperties = encryptionContextProperties;
    }

    /** @deprecated use {@link #encrypt(byte[], EncryptionPurpose, String)}; removed in Task 6. */
    @Deprecated
    public byte[] encrypt(byte[] bytes, Map<String, String> context) {
        CryptoResult<byte[], ?> encryptResult = awsCrypto.encryptData(cryptoMaterialsManager, bytes, context);
        return encryptResult.getResult();
    }

    /** @deprecated use {@link #decrypt(byte[], EncryptionPurpose)}; removed in Task 6. */
    @Deprecated
    public byte[] decrypt(byte[] ciphertext) {
        CryptoResult<byte[], ?> decryptResult = awsCrypto.decryptData(cryptoMaterialsManager, ciphertext);
        return decryptResult.getResult();
    }

    public byte[] encrypt(byte[] bytes, EncryptionPurpose purpose, String actorId) {
        CryptoResult<byte[], ?> encryptResult = awsCrypto.encryptData(
                cryptoMaterialsManager, bytes, EncryptionContexts.forPurpose(purpose, actorId));
        return encryptResult.getResult();
    }

    /**
     * Decrypts and verifies that the bound purpose is {@code expected}. Ciphertext written
     * before purposes existed is accepted or rejected according to
     * {@code direct-file.encryption.context-verification}.
     */
    public byte[] decrypt(byte[] ciphertext, EncryptionPurpose expected) {
        return decryptAndVerify(ciphertext, expected, encryptionContextProperties.isEnforcing());
    }

    /**
     * As {@link #decrypt}, but always tolerates untagged ciphertext regardless of mode.
     *
     * <p>For the data-import populations only: their writers live outside this repository,
     * so this codebase cannot migrate them and the tolerance is permanent. It is a distinct
     * method rather than a config exemption so the exception is visible at the call site.
     * Remove it when those writers adopt the purpose schema.
     */
    public byte[] decryptLegacyTolerant(byte[] ciphertext, EncryptionPurpose expected) {
        return decryptAndVerify(ciphertext, expected, false);
    }

    private byte[] decryptAndVerify(byte[] ciphertext, EncryptionPurpose expected, boolean rejectUntagged) {
        CryptoResult<byte[], ?> decryptResult = awsCrypto.decryptData(cryptoMaterialsManager, ciphertext);
        Map<String, String> context = decryptResult.getEncryptionContext();
        String found = context == null ? null : context.get(EncryptionContexts.PURPOSE_KEY);
        byte[] plaintext = decryptResult.getResult();

        if (found == null) {
            if (rejectUntagged) {
                return refuse(
                        plaintext,
                        "ciphertext carries no encryption context purpose; expected " + expected.wireValue());
            }
            reportLegacy(expected);
            return plaintext;
        }

        if (!found.equals(expected.wireValue())) {
            return refuse(
                    plaintext,
                    "encryption context purpose mismatch: expected " + expected.wireValue() + ", found " + found);
        }

        return plaintext;
    }

    private byte[] refuse(byte[] plaintext, String message) {
        Arrays.fill(plaintext, (byte) 0);
        throw new EncryptionContextMismatchException(message);
    }

    private void reportLegacy(EncryptionPurpose expected) {
        long count = legacyCounts
                .computeIfAbsent(expected, key -> new AtomicLong())
                .incrementAndGet();
        if (count == 1L || count % LEGACY_LOG_EVERY == 0L) {
            log.warn(
                    "{}: decrypted ciphertext with no bound purpose, expected={}, countThisInstance={}",
                    LEGACY_MARKER,
                    expected.wireValue(),
                    count);
        }
    }

    @PostConstruct
    private void checkKmsConnection() {
        byte[] testBytes = "something".getBytes();
        try {
            awsCrypto.encryptData(cryptoMaterialsManager, testBytes);
            log.info("encryption setup health check passed");
        } catch (Exception e) {
            log.error("test encrypt operation failed, check configuration");
            throw e;
        }
    }
}
```

Note `refuse` returns `byte[]` it never produces — that is so the call sites read as `return refuse(...)`, which keeps the compiler satisfied on every branch without an unreachable `return null`.

- [ ] **Step 5: Register the properties bean**

In `EncryptionAutoConfiguration.java`, add the import and annotate the top-level class so the bean exists for `DataEncryptDecrypt` regardless of which nested configuration is active:

```java
@AutoConfiguration
@Slf4j
@EnableConfigurationProperties(EncryptionContextProperties.class)
@Import(DataEncryptDecrypt.class)
public class EncryptionAutoConfiguration {
```

`@EnableConfigurationProperties` is already imported in this file for the nested classes; confirm the import is at the top level and not only inside them.

- [ ] **Step 6: Run the tests to verify they pass**

```bash
cd /Users/thomaswarn/repo/direct-file/direct-file/libs
./mvnw -pl data-models test -Dtest=DataEncryptDecryptTest
```

Expected: PASS.

- [ ] **Step 7: Run the whole data-models suite**

```bash
cd /Users/thomaswarn/repo/direct-file/direct-file/libs
./mvnw -pl data-models test
```

Expected: PASS. `EncryptionAutoConfigurationTest` is the one to watch — it asserts specific startup failures, and adding a properties bean with a default must not change which bean is reported missing.

- [ ] **Step 8: Format and commit**

```bash
cd /Users/thomaswarn/repo/direct-file/direct-file/libs
./mvnw spotless:apply
cd /Users/thomaswarn/repo/direct-file
git add -A && git commit -m "feat(data-models): verify encryption context purpose on decrypt"
```

---

## Task 3: Thread the purpose through the two encryptors

Spec §2.2. `GenericStringEncryptor` is the shared decrypt path for three unrelated data kinds, so the expectation has to be a parameter, not a field.

**Files:**
- Modify: `direct-file/libs/data-models/src/main/java/gov/irs/directfile/models/encryption/FactsEncryptor.java`
- Modify: `direct-file/libs/data-models/src/main/java/gov/irs/directfile/models/encryption/GenericStringEncryptor.java`
- Create: `direct-file/libs/data-models/src/test/java/gov/irs/directfile/models/encryption/EncryptorPurposeTest.java`

**Interfaces:**
- Produces, on both classes: `convertToDatabaseColumn(value, EncryptionPurpose, String actorId)` and `convertToEntityAttribute(dbData, EncryptionPurpose expected)`. `GenericStringEncryptor` additionally gets `convertToEntityAttributeLegacyTolerant(dbData, EncryptionPurpose expected)` for the data-import paths.
- Old signatures stay until Task 6.

**Design note.** `FactsEncryptor` gets no legacy-tolerant variant: its only reader is the tax-return `@PostLoad`, which Phase B will migrate. Adding one would create a way to opt out of the eventual enforcement.

- [ ] **Step 1: Write the failing tests**

```java
package gov.irs.directfile.models.encryption;

import java.util.Map;

import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

public class EncryptorPurposeTest {

    @Test
    void genericStringEncryptor_encryptsUnderTheGivenPurposeAndActor() {
        DataEncryptDecrypt ded = mock(DataEncryptDecrypt.class);
        when(ded.encrypt(any(), any(EncryptionPurpose.class), any())).thenReturn(new byte[] {1, 2, 3});

        new GenericStringEncryptor(ded)
                .convertToDatabaseColumn("value", EncryptionPurpose.TAX_RETURN_STORE, "actor-1");

        verify(ded).encrypt(any(), eq(EncryptionPurpose.TAX_RETURN_STORE), eq("actor-1"));
    }

    @Test
    void genericStringEncryptor_decryptsUnderTheExpectedPurpose() {
        DataEncryptDecrypt ded = mock(DataEncryptDecrypt.class);
        when(ded.decrypt(any(), any(EncryptionPurpose.class))).thenReturn("value".getBytes());

        String result = new GenericStringEncryptor(ded)
                .convertToEntityAttribute(
                        java.util.Base64.getEncoder().encodeToString(new byte[] {1, 2, 3}),
                        EncryptionPurpose.TAX_RETURN_STORE);

        assertThat(result).isEqualTo("value");
        verify(ded).decrypt(any(), eq(EncryptionPurpose.TAX_RETURN_STORE));
    }

    @Test
    void genericStringEncryptor_legacyTolerantPathUsesTheLegacyTolerantDecrypt() {
        DataEncryptDecrypt ded = mock(DataEncryptDecrypt.class);
        when(ded.decryptLegacyTolerant(any(), any(EncryptionPurpose.class))).thenReturn("value".getBytes());

        new GenericStringEncryptor(ded)
                .convertToEntityAttributeLegacyTolerant(
                        java.util.Base64.getEncoder().encodeToString(new byte[] {1, 2, 3}),
                        EncryptionPurpose.DATA_IMPORT_POPULATED_DATA);

        verify(ded).decryptLegacyTolerant(any(), eq(EncryptionPurpose.DATA_IMPORT_POPULATED_DATA));
    }

    @Test
    void genericStringEncryptor_nullAndEmptyPassThroughWithoutTouchingCrypto() {
        DataEncryptDecrypt ded = mock(DataEncryptDecrypt.class);
        GenericStringEncryptor subject = new GenericStringEncryptor(ded);

        assertThat(subject.convertToDatabaseColumn(null, EncryptionPurpose.TAX_RETURN_STORE, null))
                .isNull();
        assertThat(subject.convertToDatabaseColumn("", EncryptionPurpose.TAX_RETURN_STORE, null))
                .isEmpty();
        assertThat(subject.convertToEntityAttribute(null, EncryptionPurpose.TAX_RETURN_STORE))
                .isNull();
        org.mockito.Mockito.verifyNoInteractions(ded);
    }

    @Test
    void factsEncryptor_encryptsUnderFactsPurpose() {
        DataEncryptDecrypt ded = mock(DataEncryptDecrypt.class);
        when(ded.encrypt(any(), any(EncryptionPurpose.class), any())).thenReturn(new byte[] {1, 2, 3});

        new FactsEncryptor(ded)
                .convertToDatabaseColumn(
                        Map.of(
                                "/foo",
                                new gov.irs.directfile.models.FactTypeWithItem(
                                        "gov.irs.factgraph.persisters.StringWrapper",
                                        com.fasterxml.jackson.databind.node.TextNode.valueOf("baz"))),
                        EncryptionPurpose.TAX_RETURN_FACTS,
                        null);

        ArgumentCaptor<EncryptionPurpose> purpose = ArgumentCaptor.captor();
        verify(ded).encrypt(any(), purpose.capture(), any());
        assertThat(purpose.getValue()).isEqualTo(EncryptionPurpose.TAX_RETURN_FACTS);
    }
}
```

`FactTypeWithItem` is the record `(String type, JsonNode item)`, so the item has to be a `JsonNode` — hence the `TextNode`. The `$type` string is not parsed by anything on this path; any non-null value works. `TestFactsWrapper`, already in this test tree, may offer a tidier fixture worth reusing.

- [ ] **Step 2: Run the tests to verify they fail**

```bash
cd /Users/thomaswarn/repo/direct-file/direct-file/libs
./mvnw -pl data-models test -Dtest=EncryptorPurposeTest
```

Expected: compilation failure.

- [ ] **Step 3: Add the new methods to `GenericStringEncryptor`**

Keep the existing two methods; add three. Note `@AllArgsConstructor` already gives the constructor the tests use.

```java
    public String convertToDatabaseColumn(String attribute, EncryptionPurpose purpose, String actorId) {
        if (attribute == null || attribute.isEmpty()) {
            return attribute;
        }
        byte[] ciphertext = dataEncryptDecrypt.encrypt(attribute.getBytes(), purpose, actorId);
        return Base64.getEncoder().encodeToString(ciphertext);
    }

    public String convertToEntityAttribute(String dbData, EncryptionPurpose expected) {
        if (dbData == null || dbData.isEmpty()) {
            return dbData;
        }
        byte[] ciphertext = Base64.getDecoder().decode(dbData);
        return new String(dataEncryptDecrypt.decrypt(ciphertext, expected));
    }

    /** See {@link DataEncryptDecrypt#decryptLegacyTolerant} — data-import populations only. */
    public String convertToEntityAttributeLegacyTolerant(String dbData, EncryptionPurpose expected) {
        if (dbData == null || dbData.isEmpty()) {
            return dbData;
        }
        byte[] ciphertext = Base64.getDecoder().decode(dbData);
        return new String(dataEncryptDecrypt.decryptLegacyTolerant(ciphertext, expected));
    }
```

- [ ] **Step 4: Add the new methods to `FactsEncryptor`**

```java
    @SneakyThrows
    public String convertToDatabaseColumn(
            Map<String, FactTypeWithItem> attribute, EncryptionPurpose purpose, String actorId) {
        if (attribute == null) {
            return null;
        }
        if (attribute.isEmpty()) {
            return "";
        }
        byte[] bytes = mapper.writeValueAsBytes(attribute);
        byte[] ciphertext = dataEncryptDecrypt.encrypt(bytes, purpose, actorId);
        return Base64.getEncoder().encodeToString(ciphertext);
    }

    @SneakyThrows
    public Map<String, FactTypeWithItem> convertToEntityAttribute(String dbData, EncryptionPurpose expected) {
        if (dbData == null || dbData.isEmpty()) {
            return new HashMap<>();
        }
        byte[] ciphertext = Base64.getDecoder().decode(dbData);
        byte[] bytes = dataEncryptDecrypt.decrypt(ciphertext, expected);
        return mapper.readValue(bytes, new TypeReference<>() {});
    }
```

- [ ] **Step 5: Run the tests, then the module suite**

```bash
cd /Users/thomaswarn/repo/direct-file/direct-file/libs
./mvnw -pl data-models test
```

Expected: PASS.

- [ ] **Step 6: Format, install, and commit**

Downstream modules need the new jar before Tasks 4 and 5 will compile.

```bash
cd /Users/thomaswarn/repo/direct-file/direct-file/libs
./mvnw spotless:apply && ./mvnw install -DskipTests
cd /Users/thomaswarn/repo/direct-file
git add -A && git commit -m "feat(data-models): thread encryption purpose through the encryptors"
```

---

## Task 4: Normalize the backend's tax-return contexts

Spec §2.1. This is where facts and store stop being written under one identical context.

**Files:**
- Modify: `direct-file/backend/src/main/java/gov/irs/directfile/api/taxreturn/models/TaxReturnEntityListener.java`
- Modify: `direct-file/backend/src/main/java/gov/irs/directfile/api/dataimport/model/PopulatedDataEntityListener.java`
- Modify: `direct-file/backend/src/main/java/gov/irs/directfile/api/dataimport/model/RawResponseDecryptor.java`
- Modify: `direct-file/backend/src/test/java/gov/irs/directfile/api/taxreturn/TaxReturnRepositoryTest.java` (`:176-177`)
- Modify: `direct-file/backend/src/test/java/gov/irs/directfile/api/taxreturn/submissions/handlers/s3eventnotification/PDFBackfillToS3HandlerTest.java` (`:139-152`, `:181-194`)
- Create: `direct-file/backend/src/test/java/gov/irs/directfile/api/taxreturn/models/TaxReturnEntityListenerTest.java`

**Interfaces:**
- Produces: facts written under `tax-return-facts`, store under `tax-return-store`, both with `system=DIRECT-FILE` and `id` when a principal is in scope. Reads assert the matching purpose.
- No change to entity or column shape, and no migration.

**Design notes.**

*The `id`/`system` branch collapses.* Today the `try/catch` produces *either* `{id}` *or* `{system,type}`. After this change both branches produce the same verified keys and differ only in whether `id` is present. Keep the `try/catch` — it is how the code detects a system-triggered write — but reduce it to computing an actor ID or null.

*Note the spelling change.* The backend's `system` value moves from `DIRECTFILE` to `DIRECT-FILE`. It is unverified, so nothing breaks; it is normalized so a future check against it is possible at all.

*Do not change the data-import call sites' behavior* — only route them to the legacy-tolerant method with an explicit purpose, so that a blob tagged with some *other* purpose is still rejected there.

- [ ] **Step 1: Write the failing tests**

Create `TaxReturnEntityListenerTest.java`. `TaxReturnEntityListener` wires its collaborators through a static `configure(...)`, so the test calls that directly.

```java
package gov.irs.directfile.api.taxreturn.models;

import java.util.Map;
import java.util.UUID;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;

import gov.irs.directfile.api.authentication.NullAuthenticationException;
import gov.irs.directfile.api.config.identity.IdentityAttributes;
import gov.irs.directfile.api.config.identity.IdentitySupplier;
import gov.irs.directfile.models.FactTypeWithItem;
import gov.irs.directfile.models.encryption.DataEncryptDecrypt;
import gov.irs.directfile.models.encryption.EncryptionPurpose;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

public class TaxReturnEntityListenerTest {
    private DataEncryptDecrypt ded;
    private IdentitySupplier identitySupplier;
    private TaxReturnEntityListener listener;

    @BeforeEach
    void setUp() {
        ded = mock(DataEncryptDecrypt.class);
        identitySupplier = mock(IdentitySupplier.class);
        when(ded.encrypt(any(), any(EncryptionPurpose.class), any())).thenReturn(new byte[] {1, 2, 3});
        listener = new TaxReturnEntityListener();
        listener.configure(identitySupplier, ded, new ObjectMapper());
    }

    private TaxReturn taxReturnWithContent() {
        TaxReturn taxReturn = new TaxReturn();
        taxReturn.setFacts(Map.<String, FactTypeWithItem>of());
        taxReturn.setStore("{}");
        return taxReturn;
    }

    @Test
    void encryptColumns_writesFactsAndStoreUnderDistinctPurposes() {
        when(identitySupplier.get()).thenThrow(new NullAuthenticationException());
        TaxReturn taxReturn = new TaxReturn();
        taxReturn.setFacts(Map.of(
                "/foo",
                new FactTypeWithItem(
                        "gov.irs.factgraph.persisters.StringWrapper",
                        com.fasterxml.jackson.databind.node.TextNode.valueOf("baz"))));
        taxReturn.setStore("{}");

        listener.encryptColumns(taxReturn);

        ArgumentCaptor<EncryptionPurpose> purposes = ArgumentCaptor.captor();
        verify(ded, org.mockito.Mockito.atLeast(2)).encrypt(any(), purposes.capture(), any());
        assertThat(purposes.getAllValues())
                .contains(EncryptionPurpose.TAX_RETURN_FACTS, EncryptionPurpose.TAX_RETURN_STORE);
    }

    @Test
    void encryptColumns_bindsTheActorIdWhenAPrincipalIsInScope() {
        UUID externalId = UUID.randomUUID();
        // IdentityAttributes is a record, so it is final and cannot be mocked - build a real one.
        IdentityAttributes attributes =
                new IdentityAttributes(UUID.randomUUID(), externalId, "taxpayer@example.com", "123456789");
        when(identitySupplier.get()).thenReturn(attributes);

        listener.encryptColumns(taxReturnWithContent());

        ArgumentCaptor<String> actorId = ArgumentCaptor.captor();
        verify(ded, org.mockito.Mockito.atLeastOnce())
                .encrypt(any(), any(EncryptionPurpose.class), actorId.capture());
        assertThat(actorId.getValue()).isEqualTo(externalId.toString());
    }

    @Test
    void encryptColumns_omitsTheActorIdForSystemTriggeredWrites() {
        when(identitySupplier.get()).thenThrow(new NullAuthenticationException());

        listener.encryptColumns(taxReturnWithContent());

        ArgumentCaptor<String> actorId = ArgumentCaptor.captor();
        verify(ded, org.mockito.Mockito.atLeastOnce())
                .encrypt(any(), any(EncryptionPurpose.class), actorId.capture());
        assertThat(actorId.getValue()).isNull();
    }

    @Test
    void decryptColumns_readsEachColumnUnderItsOwnPurpose() {
        when(ded.decrypt(any(), any(EncryptionPurpose.class))).thenReturn("{}".getBytes());
        TaxReturn taxReturn = new TaxReturn();
        taxReturn.setFactsCipherText(java.util.Base64.getEncoder().encodeToString(new byte[] {1, 2, 3}));
        taxReturn.setStoreCipherText(java.util.Base64.getEncoder().encodeToString(new byte[] {1, 2, 3}));

        listener.decryptColumns(taxReturn);

        ArgumentCaptor<EncryptionPurpose> purposes = ArgumentCaptor.captor();
        verify(ded, org.mockito.Mockito.atLeast(2)).decrypt(any(), purposes.capture());
        assertThat(purposes.getAllValues())
                .contains(EncryptionPurpose.TAX_RETURN_FACTS, EncryptionPurpose.TAX_RETURN_STORE);
    }
}
```

Both collaborators were checked against the real types while writing this plan: `IdentityAttributes` is the record `(UUID id, UUID externalId, String email, String tin)` — final, so it is constructed rather than mocked — and `NullAuthenticationException` extends `RuntimeException` with only the implicit no-arg constructor. Neither needs re-deriving; do re-read them if either test fails to compile, since a record's component order is not something the compiler will catch you swapping.

- [ ] **Step 2: Run the tests to verify they fail**

```bash
cd /Users/thomaswarn/repo/direct-file/direct-file/backend
./mvnw test -Dtest=TaxReturnEntityListenerTest
```

Expected: failure — the listener still writes both columns under the same map and calls the deprecated overloads.

- [ ] **Step 3: Rewrite `encryptColumns` and `decryptColumns`**

```java
    @PostLoad
    public <T extends TaxReturnEntity> void decryptColumns(T taxReturn) {
        taxReturn.setFactsWithoutDirtyingEntity(factsEncryptor.convertToEntityAttribute(
                taxReturn.getFactsCipherText(), EncryptionPurpose.TAX_RETURN_FACTS));
        taxReturn.setStoreWithoutDirtyingEntity(genericStringEncryptor.convertToEntityAttribute(
                taxReturn.getStoreCipherText(), EncryptionPurpose.TAX_RETURN_STORE));
    }

    @PrePersist
    @PreUpdate
    public <T extends TaxReturnEntity> void encryptColumns(T taxReturn) {
        String actorId;
        try {
            IdentityAttributes identityAttributes = identitySupplier.get();
            actorId = identityAttributes.externalId().toString();
        } catch (NullAuthenticationException e) {
            // this write was triggered by a system event (e.g. sqs message handler)
            actorId = null;
        }

        taxReturn.setFactsCipherText(factsEncryptor.convertToDatabaseColumn(
                taxReturn.getFacts(), EncryptionPurpose.TAX_RETURN_FACTS, actorId));
        taxReturn.setStoreCipherText(genericStringEncryptor.convertToDatabaseColumn(
                taxReturn.getStore(), EncryptionPurpose.TAX_RETURN_STORE, actorId));
    }
```

Remove the now-unused `java.util.HashMap` / `java.util.Map` imports and add `gov.irs.directfile.models.encryption.EncryptionPurpose`.

- [ ] **Step 4: Route the data-import read paths explicitly**

In `PopulatedDataEntityListener:28`:

```java
            String decrypted = genericStringEncryptor.convertToEntityAttributeLegacyTolerant(
                    populatedData.getDataCipherText(), EncryptionPurpose.DATA_IMPORT_POPULATED_DATA);
```

In `RawResponseDecryptor:24`:

```java
            String decrypted = genericStringEncryptor.convertToEntityAttributeLegacyTolerant(
                    populatedData.getRawDataCipherText(), EncryptionPurpose.DATA_IMPORT_RAW_RESPONSE);
```

Add a comment at both sites pointing at spec §2.3, so the next reader knows the tolerance is deliberate and what would lift it.

- [ ] **Step 5: Update the two existing tests that stub the old overloads**

`TaxReturnRepositoryTest:176-177` and `PDFBackfillToS3HandlerTest:139-152` and `:181-194` stub `encrypt(eq(bytes), anyMap())` and `decrypt(bytes)`. Those stubs no longer match, so the mocks will return null and the tests will fail with an NPE rather than an obvious message. Change each to the purpose-aware forms:

```java
        when(dataEncryptDecrypt.encrypt(eq(factsBytes), any(EncryptionPurpose.class), any()))
                .thenReturn(factsBytes);
        when(dataEncryptDecrypt.decrypt(eq(factsBytes), any(EncryptionPurpose.class)))
                .thenReturn(factsBytes);
```

Add `import static org.mockito.ArgumentMatchers.any;` where missing, and drop `anyMap` imports if they become unused. Grep for any other stub of these methods before moving on:

```bash
cd /Users/thomaswarn/repo/direct-file/direct-file
grep -rn "dataEncryptDecrypt\.\(encrypt\|decrypt\)" --include=*.java backend/src/test
```

- [ ] **Step 6: Run the touched tests, then the module suite**

```bash
cd /Users/thomaswarn/repo/direct-file/direct-file/backend
./mvnw test -Dtest='TaxReturnEntityListenerTest,TaxReturnRepositoryTest,PDFBackfillToS3HandlerTest'
./mvnw test
```

Expected: PASS. The full suite is the real check here — the entity listener sits under every tax-return read and write in the service, so a mistake shows up broadly rather than locally.

- [ ] **Step 7: Format and commit**

```bash
cd /Users/thomaswarn/repo/direct-file/direct-file/backend
./mvnw spotless:apply
cd /Users/thomaswarn/repo/direct-file
git add -A && git commit -m "feat(backend): bind and verify distinct encryption purposes for facts and store"
```

---

## Task 5: Normalize the state-api export token context

Spec §2.4. Low risk — no controller reaches this path — but it fixes the `DIRECTFILE`/`DIRECT-FILE` split and closes the token against substitution.

**Files:**
- Modify: `direct-file/state-api/src/main/java/gov/irs/directfile/stateapi/authorization/AuthorizationTokenService.java` (the `encryptToken` method, `:93-101`)
- Modify: `direct-file/state-api/src/test/java/gov/irs/directfile/stateapi/authorization/AuthorizationTokenServiceTest.java` (`:102` asserts the exact context map)
- Modify: `direct-file/state-api/src/test/java/gov/irs/directfile/stateapi/authorization/AuthorizationTokenServiceIntegrationTest.java` (`:48` calls the no-expectation `decrypt`)

**Interfaces:**
- Produces: token ciphertext bound to `state-export-token`. The Base64url encoding, the JWS structure, and the signing key handling are all unchanged.

**Design note.** `AuthorizationTokenServiceIntegrationTest` already does a real encrypt/decrypt round trip against a real `DataEncryptDecrypt` under the `token-integration-test` profile. That makes it the right place — the only place in the repository — to prove end-to-end with real crypto that a wrong-purpose read is rejected. Add that case there rather than only asserting on mocks.

- [ ] **Step 1: Update the unit test's context assertion**

At `AuthorizationTokenServiceTest:98-102`, the captor asserts:

```java
        assertEquals(Map.of("system", "DIRECT-FILE", "type", "STATE-API"), encryptionContextCaptor.getValue());
```

The service no longer passes a map. Replace the capture with a purpose capture:

```java
        ArgumentCaptor<EncryptionPurpose> purposeCaptor = ArgumentCaptor.captor();
        // ...
        verify(dataEncryptDecrypt).encrypt(any(), purposeCaptor.capture(), any());
        assertEquals(EncryptionPurpose.STATE_EXPORT_TOKEN, purposeCaptor.getValue());
```

The other stubs in this file (`:80`, `:112`, `:128`, `:135`, `:152`) use `encrypt(any(), any())` or `encrypt(any(), anyMap())` and need their arity updated to three arguments. Work through every one; the compiler catches the arity but not a mismatched `any()` that silently stops matching.

- [ ] **Step 2: Add the real-crypto negative test**

In `AuthorizationTokenServiceIntegrationTest`, change the existing decrypt at `:48` to the purpose-aware call and add a new test:

```java
        byte[] decrypted = dataEncryptDecrypt.decrypt(ciphertext, EncryptionPurpose.STATE_EXPORT_TOKEN);
```

```java
    @Test
    public void givenAnExportToken_whenReadAsTaxReturnFacts_thenItIsRejected() {
        AuthCodeRequest authCodeRequest =
                new AuthCodeRequest(UUID.randomUUID(), "123-00-4567", 2023, "MA", "123456789AB");
        AuthorizationTokenClaims claimsMap = mapper.convertValue(authCodeRequest, AuthorizationTokenClaims.class);

        StepVerifier.create(authorizationTokenService.generateAndEncrypt(claimsMap))
                .assertNext((token) -> {
                    byte[] ciphertext = Base64.getUrlDecoder().decode(token);
                    assertThrows(
                            EncryptionContextMismatchException.class,
                            () -> dataEncryptDecrypt.decrypt(ciphertext, EncryptionPurpose.TAX_RETURN_FACTS));
                })
                .expectComplete()
                .verify();
    }
```

This is the test that demonstrates the finding is closed: a state-export token can no longer be read as a tax-return facts blob under the same CMK.

- [ ] **Step 3: Run the tests to verify they fail**

```bash
cd /Users/thomaswarn/repo/direct-file/direct-file/state-api
./mvnw test -Dtest='AuthorizationTokenServiceTest,AuthorizationTokenServiceIntegrationTest'
```

Expected: failure.

- [ ] **Step 4: Rewrite `encryptToken`**

```java
    private String encryptToken(byte[] claims) {
        byte[] ciphertext = dataEncryptDecrypt.encrypt(claims, EncryptionPurpose.STATE_EXPORT_TOKEN, null);
        return Base64.getUrlEncoder().encodeToString(ciphertext);
    }
```

Add `import gov.irs.directfile.models.encryption.EncryptionPurpose;`. The wildcard `java.util.*` import already covers `Base64`; `HashMap` and `Map` may now be unused in this file — check before removing, as the wildcard import hides it.

- [ ] **Step 5: Run the tests, then the whole suite**

```bash
cd /Users/thomaswarn/repo/direct-file/direct-file/state-api
./mvnw test
```

Expected: PASS.

- [ ] **Step 6: Format and commit**

```bash
cd /Users/thomaswarn/repo/direct-file/direct-file/state-api
./mvnw spotless:apply
cd /Users/thomaswarn/repo/direct-file
git add -A && git commit -m "feat(state-api): bind the export token to a verified encryption purpose"
```

---

## Task 6: Remove the unverified primitives and document the mode

With every caller migrated, delete the escape hatches. After this task it is not possible to write an untagged ciphertext or read one without an expectation.

**Files:**
- Modify: `direct-file/libs/data-models/src/main/java/gov/irs/directfile/models/encryption/DataEncryptDecrypt.java`
- Modify: `direct-file/libs/data-models/src/main/java/gov/irs/directfile/models/encryption/FactsEncryptor.java`
- Modify: `direct-file/libs/data-models/src/main/java/gov/irs/directfile/models/encryption/GenericStringEncryptor.java`
- Modify: `direct-file/backend/README.md` and `direct-file/state-api/README.md`

- [ ] **Step 1: Confirm nothing still calls the deprecated methods**

```bash
cd /Users/thomaswarn/repo/direct-file/direct-file
grep -rn "\.encrypt([^,]*, *[a-zA-Z]*[Cc]ontext)" --include=*.java .
grep -rn "\.decrypt([^,)]*)" --include=*.java . | grep -v "EncryptionPurpose"
grep -rn "convertToDatabaseColumn\|convertToEntityAttribute" --include=*.java . | grep -v "EncryptionPurpose"
```

Every hit must be either a definition or a test that was already migrated. Resolve each before continuing — a hit found here is a caller Tasks 4 and 5 missed.

- [ ] **Step 2: Delete the deprecated methods**

Remove `encrypt(byte[], Map<String,String>)` and `decrypt(byte[])` from `DataEncryptDecrypt`, and the two-argument `convertToDatabaseColumn` / one-argument `convertToEntityAttribute` from both encryptors. Drop imports that become unused.

- [ ] **Step 3: Rebuild everything from clean**

The deletions are the point at which a missed caller surfaces, and it will surface as a compile error in a module other than the one you changed.

```bash
cd /Users/thomaswarn/repo/direct-file/direct-file/libs && ./mvnw clean install -DskipTests
cd /Users/thomaswarn/repo/direct-file/direct-file/backend && ./mvnw clean test
cd /Users/thomaswarn/repo/direct-file/direct-file/state-api && ./mvnw clean test
cd /Users/thomaswarn/repo/direct-file/direct-file/email-service && ./mvnw clean test
```

`email-service` is in the list because `SendEmailV1HandlerIntegrationTest:60` holds a `DataEncryptDecrypt` field. It appears not to call either method, but it is the one module outside the two you edited that references the class, so build it before believing the deletion is safe.

- [ ] **Step 4: Document the property**

Add to `direct-file/backend/README.md` and `direct-file/state-api/README.md`:

```markdown
### Encryption context verification

Every ciphertext this service writes binds a `purpose` into its AWS Encryption SDK
encryption context, and every decrypt asserts the purpose it expected. A blob carrying
the *wrong* purpose is always rejected.

`direct-file.encryption.context-verification` governs only ciphertext written before
purposes existed:

| Value | Untagged ciphertext |
|---|---|
| `warn` (default) | accepted, logged under the marker `ENCRYPTION_CONTEXT_LEGACY` |
| `enforce` | rejected |

Leave it at `warn` until the legacy population has been re-encrypted. Flipping to
`enforce` while untagged rows remain makes those rows unreadable. The gate for flipping
is a log query for `ENCRYPTION_CONTEXT_LEGACY` returning zero across an observation
window longer than the longest interval at which a dormant tax return can be loaded.

See `docs/security/2026-08-25_h1-encryption-context-spec.md`.
```

- [ ] **Step 5: Format and commit**

```bash
cd /Users/thomaswarn/repo/direct-file/direct-file/libs && ./mvnw spotless:apply
cd /Users/thomaswarn/repo/direct-file/direct-file/backend && ./mvnw spotless:apply
cd /Users/thomaswarn/repo/direct-file/direct-file/state-api && ./mvnw spotless:apply
cd /Users/thomaswarn/repo/direct-file
git add -A && git commit -m "refactor(data-models): remove the unverified encrypt and decrypt primitives"
```

---

## Verification

- [ ] **Full builds, all four affected modules**

```bash
cd /Users/thomaswarn/repo/direct-file/direct-file/libs && ./mvnw clean install
cd /Users/thomaswarn/repo/direct-file/direct-file/backend && ./mvnw clean test
cd /Users/thomaswarn/repo/direct-file/direct-file/state-api && ./mvnw clean test
cd /Users/thomaswarn/repo/direct-file/direct-file/email-service && ./mvnw clean test
```

Expected: PASS, zero failures.

- [ ] **Integration tests**, if Docker is available

```bash
cd /Users/thomaswarn/repo/direct-file/direct-file/state-api
./integrationtest.sh
```

Expected: PASS. These exercise the real export path end to end and are the strongest evidence the protocol is untouched.

- [ ] **Prove the finding is closed, not merely tested**

`AuthorizationTokenServiceIntegrationTest.givenAnExportToken_whenReadAsTaxReturnFacts_thenItIsRejected` must pass with real crypto. Before this change, that read succeeded and returned plaintext. Confirm by stashing the Task 5 service change alone and watching it fail; then restore.

- [ ] **Prove the dual-read window is real**

`DataEncryptDecryptTest.acceptsLegacyUntaggedCiphertext_inWarnMode` must pass. If it does not, a deploy of this change makes every existing row unreadable — this is the single highest-consequence test in the plan.

- [ ] **Confirm the default is `warn` in every deployed profile**

```bash
cd /Users/thomaswarn/repo/direct-file/direct-file
grep -rn "context-verification" --include=*.yaml --include=*.yml . || echo "unset everywhere — default warn applies"
```

Unset is correct for Phase A. An `enforce` anywhere at this stage is a mistake.

- [ ] **Confirm scope was not exceeded**

No changes under `df-client/`, no Liquibase changesets, no changes to `PopulatedData`, `User`, or any KMS configuration. Phase B and Phase C are not in this plan.

```bash
cd /Users/thomaswarn/repo/direct-file
git diff --stat main...HEAD -- direct-file/df-client direct-file/backend/src/main/resources/db
```

Expected: empty.

- [ ] **Hand back the operational items this plan cannot perform**

State explicitly to the milestone owner, from spec §6:

1. **Check the KMS key policy for `kms:EncryptionContext:` conditions** before deploying. This change alters the context shape — it drops `type` and adds `purpose`. If the policy constrains those keys, Encrypt calls begin failing at deploy. This is the most likely way this change fails in production and the code cannot detect it in advance.
2. **Confirm `generateAuthorizationToken` is unreachable in deployed environments.** No controller in this repository calls it. If some deployed configuration does, there is a state-api ciphertext population that Phase B must also cover.
3. **Decide the Phase C observation window** — bounded by how long a tax return can sit unread and still be loaded. This is a data-retention question, not an engineering one.
4. **Approve the loss of `id` attribution on backfilled rows** before Phase B runs.
5. **Confirm nothing outside this repository reads `taxreturns.updated_at`**, which a Phase B full-table pass will bump.
6. **Note that H-1 is now "underway", not "closed".** The spec's go-live standard for this item is that it be underway; that is satisfied by Phase A. It is not closed until Phase C.
