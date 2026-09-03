# Delta Security Review Remediation Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Close D-1 and D-2 from the delta security review — the only finding that leaves the original H-1 scenario open, and the backfill-completion gap that has to be trustworthy before D-1's own backfill can be trusted — plus the two mechanical Low findings, D-3 and D-5. D-4 is deliberately not code in this plan; see Handback 1.

**Architecture:** D-2 first: add attempted/succeeded/failed counters to the backfill's persisted progress row and a single-query Phase C gate, so "completed" stops meaning "every row was attempted" and starts meaning "every row was attempted and none failed." D-1 second, in two tasks: first the library-level change (a `record` key in the encryption context, verified on decrypt behind its own independent warn/enforce flag, exactly mirroring how `purpose` verification was introduced — this task ships nothing wired to a caller and is fully testable in isolation), then wiring `TaxReturnEntityListener` to bind and verify `record=<row id>` and re-driving the existing Phase B backfill machinery under the new schema by resetting its persisted cursor, which is why D-2 has to land first. D-3 and D-5 are independent, small, and can land in any order.

**Tech Stack:** Java 21, Spring Boot 3.3.10, Spring Data JPA, Liquibase, AWS Encryption SDK, JUnit 5, Mockito, AssertJ, Spotless with palantir-java-format, PMD, SpotBugs.

**Spec:** `docs/security/2026-09-02_delta-security-review.md`, findings D-1 through D-5. That document is on `main` (commit `977b5f3`), unlike the five prior plans' citations of the original 2026-08-22 review, which now is too (`2962948`).

## Global Constraints

- **Java 21.** No language features beyond it.
- **Spotless runs in the build.** Run `./mvnw spotless:apply` before committing any Java change in `backend` or `libs`, or `verify` fails on formatting.
- **Liquibase, not Flyway, and `ddl-auto: none`.** Schema and data migrations are YAML changesets under `direct-file/backend/src/main/resources/db/migrations/`, auto-included by `direct-file/backend/src/main/resources/db/changelog.yaml`'s `includeAll`. Filename convention: `YYYYMMDDHHMMSS-kebab-case-description.yaml`.
- **`libs` must be installed before `backend` builds if `libs` changed.** `cd direct-file/libs && ./mvnw clean install` before running `backend`'s own `verify` in any task that touches `libs/data-models`.
- **Do not run `verify` on `status` or `submit`.** Neither compiles in this checkout.
- **Additive, not breaking.** Every method signature change in this plan is a new overload. No existing call site outside the files a task explicitly lists changes its arguments. Verify this with the grep each task gives before assuming it.

---

## Task 1: Backfill completion tracking, and a Phase C gate that can answer the question (D-2)

**Files:**
- Create: `direct-file/backend/src/main/resources/db/migrations/20260903100000-encryption-backfill-progress-add-counters.yaml`
- Modify: `direct-file/backend/src/main/java/gov/irs/directfile/api/taxreturn/models/EncryptionBackfillProgress.java`
- Modify: `direct-file/backend/src/main/java/gov/irs/directfile/api/taxreturn/EncryptionBackfillProgressRepository.java`
- Modify: `direct-file/backend/src/main/java/gov/irs/directfile/api/taxreturn/EncryptionBackfillService.java`
- Modify: `direct-file/libs/data-models/src/main/java/gov/irs/directfile/models/encryption/DataEncryptDecrypt.java` (the `LEGACY_MARKER` Javadoc only)
- Test: `direct-file/backend/src/test/java/gov/irs/directfile/api/taxreturn/EncryptionBackfillServiceTest.java`
- Test: `direct-file/backend/src/test/java/gov/irs/directfile/api/taxreturn/EncryptionBackfillProgressRepositoryTest.java`

**Interfaces:**
- Consumes: nothing from other tasks.
- Produces: `EncryptionBackfillProgress.getAttempted()/getSucceeded()/getFailed()`, and `EncryptionBackfillProgressRepository.allTablesCleanlyMigrated(): boolean`. Task 3 depends on the schema this task adds — its own migration runs against these three new columns.

`completed` is set to `true` the moment the id query returns an empty page, regardless of whether any row in any prior page actually succeeded. `BatchResult` already carries `attempted` and `succeeded` per batch, but only to a log line — nothing persists them, so a sweep in which every row failed is durably indistinguishable from a clean one, and the only artifact built to answer that question cannot.

- [ ] **Step 1: Confirm the current shape**

```bash
cd direct-file/backend
grep -n "attempted\|succeeded\|failed" src/main/java/gov/irs/directfile/api/taxreturn/models/EncryptionBackfillProgress.java
```

Expected: no matches. If any exist, this task's premise is wrong — stop and report.

- [ ] **Step 2: Add the migration**

Create `direct-file/backend/src/main/resources/db/migrations/20260903100000-encryption-backfill-progress-add-counters.yaml`:

```yaml
databaseChangeLog:
  - changeSet:
      id: encryption-backfill-progress-add-counters
      author: directfile
      changes:
        - addColumn:
            tableName: encryption_backfill_progress
            columns:
              - column:
                  name: attempted
                  type: int
                  defaultValueNumeric: 0
                  constraints:
                    nullable: false
              - column:
                  name: succeeded
                  type: int
                  defaultValueNumeric: 0
                  constraints:
                    nullable: false
              - column:
                  name: failed
                  type: int
                  defaultValueNumeric: 0
                  constraints:
                    nullable: false
      rollback:
        - dropColumn:
            tableName: encryption_backfill_progress
            columns:
              - column:
                  name: attempted
              - column:
                  name: succeeded
              - column:
                  name: failed
```

- [ ] **Step 3: Add the fields to the entity**

In `EncryptionBackfillProgress.java`, add after the `completed` field:

```java
    /** Rows this sweep has tried to migrate, across every batch. Never decreases. */
    @Column(name = "attempted", nullable = false)
    private int attempted;

    /** Rows successfully re-encrypted. {@code attempted - succeeded == failed}, always. */
    @Column(name = "succeeded", nullable = false)
    private int succeeded;

    /**
     * Rows the sweep could not migrate and advanced past. {@code completed && failed == 0}
     * is the only durable signal that a sweep actually finished cleanly — see {@link
     * EncryptionBackfillProgressRepository#allTablesCleanlyMigrated()}.
     */
    @Column(name = "failed", nullable = false)
    private int failed;
```

- [ ] **Step 4: Accumulate the counters in the service**

In `EncryptionBackfillService.processNextBatch`, replace:

```java
        // Advance past every id in the page, including any that failed. A row that cannot
        // be migrated is reported under FAILURE_MARKER and left behind rather than retried
        // forever; leaving it would stall the sweep permanently.
        progress.setLastId(ids.get(ids.size() - 1));
        progressRepository.save(progress);

        return new BatchResult(ids.size(), succeeded, false);
```

with:

```java
        // Advance past every id in the page, including any that failed. A row that cannot
        // be migrated is reported under FAILURE_MARKER and left behind rather than retried
        // forever; leaving it would stall the sweep permanently. The counters commit in the
        // same save as the cursor, so they can never drift out of sync with it.
        progress.setLastId(ids.get(ids.size() - 1));
        progress.setAttempted(progress.getAttempted() + ids.size());
        progress.setSucceeded(progress.getSucceeded() + succeeded);
        progress.setFailed(progress.getFailed() + (ids.size() - succeeded));
        progressRepository.save(progress);

        return new BatchResult(ids.size(), succeeded, false);
```

- [ ] **Step 5: Add the Phase C gate query**

Replace the whole of `EncryptionBackfillProgressRepository.java`:

```java
package gov.irs.directfile.api.taxreturn;

import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.CrudRepository;
import org.springframework.stereotype.Repository;

import gov.irs.directfile.api.taxreturn.models.EncryptionBackfillProgress;

@Repository
public interface EncryptionBackfillProgressRepository extends CrudRepository<EncryptionBackfillProgress, String> {

    /**
     * The precondition for flipping an encryption-context-verification flag from warn to
     * enforce: every persisted progress row finished its sweep, and not one of them left a
     * single row unmigrated. False if even one row is still in progress or ended with any
     * failures at all. Checkable with one query rather than a log search whose answer
     * depends on retention outliving the sweep.
     */
    @Query("SELECT COUNT(p) = 0 FROM EncryptionBackfillProgress p WHERE p.completed = false OR p.failed > 0")
    boolean allTablesCleanlyMigrated();
}
```

- [ ] **Step 6: Correct the Phase C gate's own documentation**

In `direct-file/libs/data-models/src/main/java/gov/irs/directfile/models/encryption/DataEncryptDecrypt.java`, replace:

```java
    /** Stable log marker. The Phase C gate is a log query for this string returning zero. */
    private static final String LEGACY_MARKER = "ENCRYPTION_CONTEXT_LEGACY";
```

with:

```java
    /**
     * Stable log marker for ciphertext seen with no bound purpose. Useful for watching a
     * sweep in progress, but the Phase C gate itself is
     * {@code EncryptionBackfillProgressRepository.allTablesCleanlyMigrated()} — a query
     * against the persisted counters, not a search over logs whose retention this class has
     * no control over.
     */
    private static final String LEGACY_MARKER = "ENCRYPTION_CONTEXT_LEGACY";
```

- [ ] **Step 7: Write the tests**

Add to `EncryptionBackfillServiceTest.java`, after `processNextBatch_advancesTheCursorToTheLastIdInThePage`:

```java
    @Test
    void processNextBatch_accumulatesCountersAcrossBatchesRatherThanOverwriting() {
        UUID a = new UUID(0L, 1L);
        EncryptionBackfillProgress existing = new EncryptionBackfillProgress();
        existing.setTargetTable(EncryptionBackfillProgress.TAX_RETURNS);
        existing.setLastId(new UUID(0L, 5L));
        existing.setAttempted(10);
        existing.setSucceeded(9);
        existing.setFailed(1);
        when(progressRepository.findById(EncryptionBackfillProgress.TAX_RETURNS))
                .thenReturn(Optional.of(existing));
        when(taxReturnRepository.findIdsForBackfillAfter(eq(existing.getLastId()), any()))
                .thenReturn(List.of(a));
        when(rowService.reencryptTaxReturn(a)).thenReturn(false);

        service.processNextBatch(EncryptionBackfillProgress.TAX_RETURNS, 10);

        ArgumentCaptor<EncryptionBackfillProgress> saved = ArgumentCaptor.forClass(EncryptionBackfillProgress.class);
        verify(progressRepository).save(saved.capture());
        assertThat(saved.getValue().getAttempted()).isEqualTo(11);
        assertThat(saved.getValue().getSucceeded()).isEqualTo(9);
        assertThat(saved.getValue().getFailed()).isEqualTo(2);
    }
```

Add to `EncryptionBackfillProgressRepositoryTest.java`. It extends `BaseRepositoryTest` and already autowires the repository under a field named `repository` (not `progressRepository`) and a `TestEntityManager entityManager` — use those exact names, matching its two existing tests:

```java
    @Test
    void allTablesCleanlyMigrated_isFalseWhenAnyTableIsIncomplete() {
        EncryptionBackfillProgress incomplete = new EncryptionBackfillProgress();
        incomplete.setTargetTable(EncryptionBackfillProgress.TAX_RETURNS);
        incomplete.setCompleted(false);
        repository.save(incomplete);

        assertThat(repository.allTablesCleanlyMigrated()).isFalse();
    }

    @Test
    void allTablesCleanlyMigrated_isFalseWhenACompletedTableHasFailures() {
        EncryptionBackfillProgress completedWithFailures = new EncryptionBackfillProgress();
        completedWithFailures.setTargetTable(EncryptionBackfillProgress.TAX_RETURNS);
        completedWithFailures.setCompleted(true);
        completedWithFailures.setFailed(1);
        repository.save(completedWithFailures);

        assertThat(repository.allTablesCleanlyMigrated()).isFalse();
    }

    @Test
    void allTablesCleanlyMigrated_isTrueWhenEveryTableFinishedWithZeroFailures() {
        EncryptionBackfillProgress clean = new EncryptionBackfillProgress();
        clean.setTargetTable(EncryptionBackfillProgress.TAX_RETURNS);
        clean.setCompleted(true);
        clean.setFailed(0);
        repository.save(clean);

        assertThat(repository.allTablesCleanlyMigrated()).isTrue();
    }
```

None of these three need the existing tests' `entityManager.flush()`/`.clear()` dance: `allTablesCleanlyMigrated()` is a JPQL `@Query`, and Spring Data JPA flushes pending changes in the same transaction before running one automatically (`FlushModeType.AUTO`), unlike `findById`, which can be served from the first-level cache without ever touching the database.

- [ ] **Step 8: Run the module builds**

```bash
cd direct-file/libs && ./mvnw --batch-mode --no-transfer-progress clean install
cd ../backend && ./mvnw --batch-mode --no-transfer-progress verify
```

Expected: BUILD SUCCESS for both. Liquibase applies the new migration as part of the integration tests' schema setup — if it fails to apply, check the changeset `id` is not already used elsewhere in `db/migrations/`.

- [ ] **Step 9: Format and commit**

```bash
cd direct-file/backend && ./mvnw spotless:apply
cd ../libs && ./mvnw spotless:apply
cd ../..
git add direct-file/backend/src/main/resources/db/migrations/20260903100000-encryption-backfill-progress-add-counters.yaml \
        direct-file/backend/src/main/java/gov/irs/directfile/api/taxreturn/models/EncryptionBackfillProgress.java \
        direct-file/backend/src/main/java/gov/irs/directfile/api/taxreturn/EncryptionBackfillProgressRepository.java \
        direct-file/backend/src/main/java/gov/irs/directfile/api/taxreturn/EncryptionBackfillService.java \
        direct-file/libs/data-models/src/main/java/gov/irs/directfile/models/encryption/DataEncryptDecrypt.java \
        direct-file/backend/src/test/java/gov/irs/directfile/api/taxreturn/EncryptionBackfillServiceTest.java \
        direct-file/backend/src/test/java/gov/irs/directfile/api/taxreturn/EncryptionBackfillProgressRepositoryTest.java
git commit -m "fix(backend): track backfill success and failure, not just completion

completed was set the moment an id query returned empty, which means
every row was attempted -- not that any row was migrated. A sweep where
every row failed was durably indistinguishable from a clean one, and
the documented Phase C gate was a log query whose answer depended on
retention outliving the sweep.

Added attempted/succeeded/failed counters to EncryptionBackfillProgress,
accumulated in the same save as the cursor advance so they can never
drift out of sync with it. The real gate is now
EncryptionBackfillProgressRepository.allTablesCleanlyMigrated(): one
query, true only when every row finished with zero failures.

Refs D-2."
```

---

## Task 2: Bind a record identity in the encryption context, verified behind its own flag (D-1, library)

**Files:**
- Modify: `direct-file/libs/data-models/src/main/java/gov/irs/directfile/models/encryption/EncryptionContexts.java`
- Modify: `direct-file/libs/data-models/src/main/java/gov/irs/directfile/models/encryption/DataEncryptDecrypt.java`
- Modify: `direct-file/libs/data-models/src/main/java/gov/irs/directfile/models/autoconfigure/EncryptionContextProperties.java`
- Modify: `direct-file/libs/data-models/src/main/java/gov/irs/directfile/models/encryption/FactsEncryptor.java`
- Modify: `direct-file/libs/data-models/src/main/java/gov/irs/directfile/models/encryption/GenericStringEncryptor.java`
- Test: `direct-file/libs/data-models/src/test/java/gov/irs/directfile/models/encryption/EncryptionContextsTest.java`
- Test: `direct-file/libs/data-models/src/test/java/gov/irs/directfile/models/encryption/DataEncryptDecryptTest.java`

**Interfaces:**
- Consumes: nothing from other tasks (Task 1's schema is a `backend` concern; this task is entirely inside `libs`).
- Produces: `EncryptionContexts.forPurpose(purpose, actorId, recordId)`; `DataEncryptDecrypt.encrypt(bytes, purpose, actorId, recordId)` and `.decrypt(ciphertext, expected, expectedRecordId)`; `FactsEncryptor`/`GenericStringEncryptor` overloads taking a record id. Every existing method keeps its exact current signature and behavior — this task only adds overloads. Task 3 is the only caller of the new ones.

**Every taxpayer's facts are written under the identical context.** `purpose=TAX_RETURN_FACTS` for every return, `system` constant, `id` set to whichever principal happened to write it. Swapping two rows' ciphertext produces a clean decrypt either way. `id` records the *writer*, which `EncryptionContexts`' own Javadoc is correct that a reader can never verify. A row's own identity is different: `TaxReturnEntity.getId()` is available on both the write side (`@PrePersist`/`@PreUpdate`) and the read side (`@PostLoad`, where the entity being hydrated *is* the row whose ciphertext is being decrypted), so binding and checking it is possible in a way binding and checking the actor never was.

**Why a separate flag from `context-verification`.** That flag already governs `purpose`, and in this codebase it has never been flipped to `enforce` — but it could be, independently of whether `record` has finished backfilling, and the two must not be coupled. If enforcement were one flag governing both, flipping it for `purpose` alone would also start rejecting every row that has not yet been touched by the `record` backfill, which is the exact bootstrapping failure `EncryptionBackfillWorker.verifyRunnable` already exists to prevent for `purpose`. `record-context-verification` is `warn` by default, independent, and gates only whether a missing `record` value is tolerated or refused.

- [ ] **Step 1: Confirm today's shape**

```bash
cd direct-file/libs/data-models
grep -n "RECORD_KEY\|recordContextVerification\|recordId" src/main/java/gov/irs/directfile/models/encryption/EncryptionContexts.java src/main/java/gov/irs/directfile/models/autoconfigure/EncryptionContextProperties.java
```

Expected: no matches. If any exist, stop and report.

- [ ] **Step 2: Add `record` to the context builder**

Replace the whole of `EncryptionContexts.java`:

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
 *
 * <p>{@code record} is different in kind from {@code id}: it names the row the ciphertext
 * belongs to, not who wrote it, and the row being hydrated at {@code @PostLoad} is exactly
 * the row whose identity should be bound -- so, unlike {@code id}, it CAN be checked at read
 * time. It is optional: only callers with a natural per-row identity supply one, and {@link
 * DataEncryptDecrypt} verifies it only when the caller asks it to.
 */
public final class EncryptionContexts {
    public static final String PURPOSE_KEY = "purpose";
    public static final String SYSTEM_KEY = "system";
    public static final String ID_KEY = "id";
    public static final String RECORD_KEY = "record";

    public static final String SYSTEM_VALUE = "DIRECT-FILE";

    private EncryptionContexts() {}

    public static Map<String, String> forPurpose(EncryptionPurpose purpose) {
        return forPurpose(purpose, null, null);
    }

    public static Map<String, String> forPurpose(EncryptionPurpose purpose, String actorId) {
        return forPurpose(purpose, actorId, null);
    }

    public static Map<String, String> forPurpose(EncryptionPurpose purpose, String actorId, String recordId) {
        if (purpose == null) {
            throw new IllegalArgumentException("encryption purpose is required");
        }
        Map<String, String> context = new LinkedHashMap<>();
        context.put(PURPOSE_KEY, purpose.wireValue());
        context.put(SYSTEM_KEY, SYSTEM_VALUE);
        if (actorId != null && !actorId.isBlank()) {
            context.put(ID_KEY, actorId);
        }
        if (recordId != null && !recordId.isBlank()) {
            context.put(RECORD_KEY, recordId);
        }
        return Map.copyOf(context);
    }
}
```

- [ ] **Step 3: Add the independent verification flag**

Replace the whole of `EncryptionContextProperties.java`:

```java
package gov.irs.directfile.models.autoconfigure;

import jakarta.annotation.PostConstruct;
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

    /**
     * As {@link #contextVerification}, but for the {@code record} key rather than
     * {@code purpose}, and independent of it: {@code purpose} enforcement could be turned on
     * before every row carries a bound {@code record}, and doing so must not also start
     * rejecting rows the record backfill has not reached yet. A ciphertext carrying the
     * <em>wrong</em> record is rejected under both modes, exactly as a wrong purpose is.
     */
    private String recordContextVerification = WARN;

    public boolean isEnforcing() {
        return ENFORCE.equalsIgnoreCase(contextVerification);
    }

    public boolean isRecordEnforcing() {
        return ENFORCE.equalsIgnoreCase(recordContextVerification);
    }

    @PostConstruct
    void validate() {
        validateMode("context-verification", contextVerification);
        validateMode("record-context-verification", recordContextVerification);
    }

    private static void validateMode(String propertyName, String value) {
        if (!WARN.equalsIgnoreCase(value) && !ENFORCE.equalsIgnoreCase(value)) {
            throw new IllegalStateException("direct-file.encryption." + propertyName + " must be '" + WARN + "' or '"
                    + ENFORCE + "', got: " + value);
        }
    }
}
```

- [ ] **Step 4: Widen `DataEncryptDecrypt`**

Replace the whole of `DataEncryptDecrypt.java`:

```java
package gov.irs.directfile.models.encryption;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicLong;

import com.amazonaws.encryptionsdk.AwsCrypto;
import com.amazonaws.encryptionsdk.CryptoMaterialsManager;
import com.amazonaws.encryptionsdk.CryptoResult;
import jakarta.annotation.PostConstruct;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;

import gov.irs.directfile.models.autoconfigure.EncryptionContextProperties;

@Component
@Slf4j
@SuppressWarnings("PMD.UnusedPrivateMethod")
public class DataEncryptDecrypt {
    /**
     * Stable log marker for ciphertext seen with no bound purpose. Useful for watching a
     * sweep in progress, but the Phase C gate itself is
     * {@code EncryptionBackfillProgressRepository.allTablesCleanlyMigrated()} — a query
     * against the persisted counters, not a search over logs whose retention this class has
     * no control over.
     */
    private static final String LEGACY_MARKER = "ENCRYPTION_CONTEXT_LEGACY";

    /** As {@link #LEGACY_MARKER}, but for ciphertext seen with no bound record. */
    private static final String RECORD_LEGACY_MARKER = "ENCRYPTION_CONTEXT_RECORD_LEGACY";

    private static final long LEGACY_LOG_EVERY = 1000L;

    private final AwsCrypto awsCrypto;
    private final CryptoMaterialsManager cryptoMaterialsManager;
    private final EncryptionContextProperties encryptionContextProperties;
    private final ConcurrentHashMap<EncryptionPurpose, AtomicLong> legacyCounts = new ConcurrentHashMap<>();
    private final AtomicLong legacyRecordCount = new AtomicLong();

    public DataEncryptDecrypt(
            AwsCrypto awsCrypto,
            CryptoMaterialsManager cryptoMaterialsManager,
            EncryptionContextProperties encryptionContextProperties) {
        this.awsCrypto = awsCrypto;
        this.cryptoMaterialsManager = cryptoMaterialsManager;
        this.encryptionContextProperties = encryptionContextProperties;
    }

    public byte[] encrypt(byte[] bytes, EncryptionPurpose purpose, String actorId) {
        return encrypt(bytes, purpose, actorId, null);
    }

    /** As {@link #encrypt(byte[], EncryptionPurpose, String)}, additionally binding a record id. */
    public byte[] encrypt(byte[] bytes, EncryptionPurpose purpose, String actorId, String recordId) {
        CryptoResult<byte[], ?> encryptResult = awsCrypto.encryptData(
                cryptoMaterialsManager, bytes, EncryptionContexts.forPurpose(purpose, actorId, recordId));
        return encryptResult.getResult();
    }

    /**
     * Decrypts and verifies that the bound purpose is {@code expected}. Ciphertext written
     * before purposes existed is accepted or rejected according to
     * {@code direct-file.encryption.context-verification}.
     */
    public byte[] decrypt(byte[] ciphertext, EncryptionPurpose expected) {
        return decrypt(ciphertext, expected, null);
    }

    /**
     * As {@link #decrypt(byte[], EncryptionPurpose)}, additionally verifying the bound
     * {@code record} equals {@code expectedRecordId} when non-null. A ciphertext with no
     * bound record is accepted or rejected according to
     * {@code direct-file.encryption.record-context-verification}; a ciphertext bound to a
     * <em>different</em> record is always refused, in either mode.
     */
    public byte[] decrypt(byte[] ciphertext, EncryptionPurpose expected, String expectedRecordId) {
        return decryptAndVerify(
                ciphertext,
                expected,
                expectedRecordId,
                encryptionContextProperties.isEnforcing() ? UntaggedPolicy.REJECT : UntaggedPolicy.REPORT);
    }

    /**
     * As {@link #decrypt(byte[], EncryptionPurpose)}, but always tolerates untagged ciphertext
     * regardless of mode.
     *
     * <p>For the data-import populations only: their writers live outside this repository,
     * so this codebase cannot migrate them and the tolerance is permanent. It is a distinct
     * method rather than a config exemption so the exception is visible at the call site.
     * Remove it when those writers adopt the purpose schema.
     */
    public byte[] decryptLegacyTolerant(byte[] ciphertext, EncryptionPurpose expected) {
        return decryptAndVerify(ciphertext, expected, null, UntaggedPolicy.ACCEPT_SILENTLY);
    }

    /** What to do with ciphertext that carries no bound purpose. */
    private enum UntaggedPolicy {
        /** Enforcing mode: the migration is finished, so untagged is a fault. */
        REJECT,
        /** Warn mode: accept, and emit the marker the Phase C gate is measured against. */
        REPORT,
        /**
         * Accept without reporting. Only for the permanently-pinned data-import paths: their
         * untagged state is expected and will never change, so reporting it would mean the
         * Phase C gate's log query could never reach zero.
         */
        ACCEPT_SILENTLY
    }

    private byte[] decryptAndVerify(
            byte[] ciphertext, EncryptionPurpose expected, String expectedRecordId, UntaggedPolicy untaggedPolicy) {
        CryptoResult<byte[], ?> decryptResult = awsCrypto.decryptData(cryptoMaterialsManager, ciphertext);
        Map<String, String> context = decryptResult.getEncryptionContext();
        String foundPurpose = context == null ? null : context.get(EncryptionContexts.PURPOSE_KEY);
        byte[] plaintext = decryptResult.getResult();

        if (foundPurpose == null) {
            if (untaggedPolicy == UntaggedPolicy.REJECT) {
                return refuse(plaintext, expected, null);
            }
            if (untaggedPolicy == UntaggedPolicy.REPORT) {
                reportLegacy(expected);
            }
            return plaintext;
        }

        if (!foundPurpose.equals(expected.wireValue())) {
            return refuse(plaintext, expected, foundPurpose);
        }

        if (expectedRecordId != null) {
            String foundRecord = context.get(EncryptionContexts.RECORD_KEY);
            if (foundRecord == null) {
                if (encryptionContextProperties.isRecordEnforcing()) {
                    return refuseRecordMismatch(plaintext, expectedRecordId, null);
                }
                reportLegacyRecord();
            } else if (!foundRecord.equals(expectedRecordId)) {
                return refuseRecordMismatch(plaintext, expectedRecordId, foundRecord);
            }
        }

        return plaintext;
    }

    /**
     * Refuses a decrypted plaintext whose bound purpose did not match. Zeroes the plaintext, logs
     * the stable {@link EncryptionContextMismatchException#MARKER} once here — the single place
     * every refusal passes through, so the marker fires for every purpose this codebase verifies,
     * not just the callers that happen to add their own catch — and throws.
     *
     * <p>{@code found} is null for "no purpose bound at all" (rejected only under enforce mode)
     * and a string for "bound to some other purpose" (rejected in every mode). Sanitized through
     * {@link EncryptionPurpose#fromWireValue} before it ever reaches a log line or an exception
     * message: it was read out of the ciphertext's context, which this class does not otherwise
     * treat as trusted input.
     */
    private byte[] refuse(byte[] plaintext, EncryptionPurpose expected, String found) {
        String safeFound = found == null
                ? "<none>"
                : EncryptionPurpose.fromWireValue(found)
                        .map(EncryptionPurpose::wireValue)
                        .orElse("<unrecognized>");
        String message =
                "encryption context purpose mismatch: expected " + expected.wireValue() + ", found " + safeFound;
        log.error("{}: {}", EncryptionContextMismatchException.MARKER, message);
        Arrays.fill(plaintext, (byte) 0);
        throw new EncryptionContextMismatchException(message);
    }

    /**
     * As {@link #refuse}, but for a record mismatch rather than a purpose mismatch. A distinct
     * method rather than a shared one with a field-name parameter: the two failure modes have
     * different messages and no shared sanitization logic (a record id is a UUID string, not a
     * value from a closed enum), and keeping them apart matches how {@link
     * #decryptLegacyTolerant} is a distinct method rather than a config branch on the same one.
     */
    private byte[] refuseRecordMismatch(byte[] plaintext, String expectedRecordId, String foundRecordId) {
        String message = "encryption context record mismatch: expected record=" + expectedRecordId + ", found record="
                + (foundRecordId == null ? "<none>" : foundRecordId);
        log.error("{}: {}", EncryptionContextMismatchException.MARKER, message);
        Arrays.fill(plaintext, (byte) 0);
        throw new EncryptionContextMismatchException(message);
    }

    /**
     * Untagged decrypts seen by this instance for {@code purpose}. Package-private: it exists so
     * tests can assert that the permanently-pinned paths do not inflate the Phase C gate's signal.
     */
    long legacyCountFor(EncryptionPurpose purpose) {
        AtomicLong count = legacyCounts.get(purpose);
        return count == null ? 0L : count.get();
    }

    /** As {@link #legacyCountFor}, but for the record key. Not split by purpose: unlike purpose
     * mismatches, which are meaningful per data type, "how many rows have no bound record yet"
     * is one number regardless of which column it came from. */
    long legacyRecordCount() {
        return legacyRecordCount.get();
    }

    private void reportLegacy(EncryptionPurpose expected) {
        long count =
                legacyCounts.computeIfAbsent(expected, key -> new AtomicLong()).incrementAndGet();
        if (count == 1L || count % LEGACY_LOG_EVERY == 0L) {
            log.warn(
                    "{}: decrypted ciphertext with no bound purpose, expected={}, countThisInstance={}",
                    LEGACY_MARKER,
                    expected.wireValue(),
                    count);
        }
    }

    private void reportLegacyRecord() {
        long count = legacyRecordCount.incrementAndGet();
        if (count == 1L || count % LEGACY_LOG_EVERY == 0L) {
            log.warn(
                    "{}: decrypted ciphertext with no bound record, countThisInstance={}",
                    RECORD_LEGACY_MARKER,
                    count);
        }
    }

    @PostConstruct
    private void checkKmsConnection() {
        byte[] testBytes = "something".getBytes(StandardCharsets.UTF_8);
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

- [ ] **Step 5: Widen `FactsEncryptor` and `GenericStringEncryptor`**

In `FactsEncryptor.java`, add these two methods (keep the existing two exactly as they are):

```java
    @SneakyThrows
    public String convertToDatabaseColumn(
            Map<String, FactTypeWithItem> attribute, EncryptionPurpose purpose, String actorId, String recordId) {
        if (attribute == null) {
            return null;
        }
        if (attribute.isEmpty()) {
            return "";
        }
        byte[] bytes = mapper.writeValueAsBytes(attribute);
        byte[] ciphertext = dataEncryptDecrypt.encrypt(bytes, purpose, actorId, recordId);
        return Base64.getEncoder().encodeToString(ciphertext);
    }

    @SneakyThrows
    public Map<String, FactTypeWithItem> convertToEntityAttribute(
            String dbData, EncryptionPurpose expected, String expectedRecordId) {
        if (dbData == null || dbData.isEmpty()) {
            return new HashMap<>();
        }
        byte[] ciphertext = Base64.getDecoder().decode(dbData);
        byte[] bytes = dataEncryptDecrypt.decrypt(ciphertext, expected, expectedRecordId);
        return mapper.readValue(bytes, new TypeReference<>() {});
    }
```

In `GenericStringEncryptor.java`, add these two methods (keep the existing three exactly as they are):

```java
    public String convertToDatabaseColumn(String attribute, EncryptionPurpose purpose, String actorId, String recordId) {
        if (attribute == null || attribute.isEmpty()) {
            return attribute;
        }
        byte[] ciphertext =
                dataEncryptDecrypt.encrypt(attribute.getBytes(StandardCharsets.UTF_8), purpose, actorId, recordId);
        return Base64.getEncoder().encodeToString(ciphertext);
    }

    public String convertToEntityAttribute(String dbData, EncryptionPurpose expected, String expectedRecordId) {
        if (dbData == null || dbData.isEmpty()) {
            return dbData;
        }
        byte[] ciphertext = Base64.getDecoder().decode(dbData);
        return new String(dataEncryptDecrypt.decrypt(ciphertext, expected, expectedRecordId), StandardCharsets.UTF_8);
    }
```

- [ ] **Step 6: Confirm no existing caller's arguments changed**

```bash
cd direct-file
grep -rn "\.encrypt(\|\.decrypt(\|convertToDatabaseColumn(\|convertToEntityAttribute(" \
    backend/src/main/java/gov/irs/directfile/api/dataimport/model/RawResponseDecryptor.java \
    backend/src/main/java/gov/irs/directfile/api/dataimport/model/PopulatedDataEntityListener.java \
    state-api/src/main/java/gov/irs/directfile/stateapi/authorization/AuthorizationTokenService.java
```

Expected: every call site still passes the same number of arguments it did before this task — `RawResponseDecryptor`/`PopulatedDataEntityListener` call `convertToEntityAttributeLegacyTolerant` (untouched by this task), `AuthorizationTokenService` calls the 3-arg `encrypt`. If any of these three files needs a code change to keep compiling, this task added an overload incorrectly — stop and report.

- [ ] **Step 7: Write the tests**

Add to `EncryptionContextsTest.java`, after `everyPurposeHasADistinctWireValue`:

```java
    @Test
    void forPurpose_withRecordId_addsRecordWithoutDisturbingVerifiedKeys() {
        Map<String, String> context =
                EncryptionContexts.forPurpose(EncryptionPurpose.TAX_RETURN_FACTS, "actor-1", "row-42");
        assertThat(context)
                .containsEntry("purpose", "tax-return-facts")
                .containsEntry("id", "actor-1")
                .containsEntry("record", "row-42");
    }

    @Test
    void forPurpose_withNullOrBlankRecordId_omitsRecordRatherThanWritingEmpty() {
        assertThat(EncryptionContexts.forPurpose(EncryptionPurpose.TAX_RETURN_FACTS, "actor-1", null))
                .doesNotContainKey("record");
        assertThat(EncryptionContexts.forPurpose(EncryptionPurpose.TAX_RETURN_FACTS, "actor-1", "   "))
                .doesNotContainKey("record");
    }
```

Add to `DataEncryptDecryptTest.java`. First, add a second `subject` helper alongside the existing one (do not modify the existing one-argument `subject`):

```java
    private DataEncryptDecrypt subject(String contextMode, String recordMode) {
        EncryptionContextProperties properties = new EncryptionContextProperties();
        properties.setContextVerification(contextMode);
        properties.setRecordContextVerification(recordMode);
        return new DataEncryptDecrypt(awsCrypto, cmm, properties);
    }
```

Then add these tests:

```java
    @Test
    void roundTripsUnderMatchingPurposeAndRecord() {
        DataEncryptDecrypt subject = subject("warn", "warn");
        byte[] ciphertext = subject.encrypt(PLAINTEXT, EncryptionPurpose.TAX_RETURN_FACTS, null, "row-1");
        assertThat(subject.decrypt(ciphertext, EncryptionPurpose.TAX_RETURN_FACTS, "row-1"))
                .isEqualTo(PLAINTEXT);
    }

    @Test
    void rejectsARecordSwap_regardlessOfRecordMode() {
        // The scenario D-1 exists to close: two rows under the same purpose, substituted.
        DataEncryptDecrypt subject = subject("warn", "warn");
        byte[] taxpayerA = subject.encrypt(PLAINTEXT, EncryptionPurpose.TAX_RETURN_FACTS, null, "row-a");
        assertThatThrownBy(() -> subject.decrypt(taxpayerA, EncryptionPurpose.TAX_RETURN_FACTS, "row-b"))
                .isInstanceOf(EncryptionContextMismatchException.class);
    }

    @Test
    void rejectsARecordSwap_inEnforceModeToo() {
        DataEncryptDecrypt subject = subject("enforce", "enforce");
        byte[] taxpayerA = subject.encrypt(PLAINTEXT, EncryptionPurpose.TAX_RETURN_FACTS, null, "row-a");
        assertThatThrownBy(() -> subject.decrypt(taxpayerA, EncryptionPurpose.TAX_RETURN_FACTS, "row-b"))
                .isInstanceOf(EncryptionContextMismatchException.class);
    }

    @Test
    void acceptsUnboundRecordUnderRecordWarnMode() {
        // Not yet migrated by the record backfill -- accepted, and reported.
        DataEncryptDecrypt subject = subject("warn", "warn");
        byte[] unbound = subject.encrypt(PLAINTEXT, EncryptionPurpose.TAX_RETURN_FACTS, null);
        assertThat(subject.decrypt(unbound, EncryptionPurpose.TAX_RETURN_FACTS, "row-1"))
                .isEqualTo(PLAINTEXT);
    }

    @Test
    void rejectsUnboundRecordUnderRecordEnforceMode() {
        DataEncryptDecrypt subject = subject("warn", "enforce");
        byte[] unbound = subject.encrypt(PLAINTEXT, EncryptionPurpose.TAX_RETURN_FACTS, null);
        assertThatThrownBy(() -> subject.decrypt(unbound, EncryptionPurpose.TAX_RETURN_FACTS, "row-1"))
                .isInstanceOf(EncryptionContextMismatchException.class);
    }

    @Test
    void recordVerificationIsSkippedWhenNoRecordIsExpected() {
        // Callers with no natural per-row identity -- state-api's export token, for one --
        // pass no expected record and must not be affected by record mode at all.
        DataEncryptDecrypt subject = subject("warn", "enforce");
        byte[] ciphertext = subject.encrypt(PLAINTEXT, EncryptionPurpose.STATE_EXPORT_TOKEN, null);
        assertThat(subject.decrypt(ciphertext, EncryptionPurpose.STATE_EXPORT_TOKEN)).isEqualTo(PLAINTEXT);
    }

    @Test
    void purposeAndRecordEnforcementAreIndependent() {
        // Purpose enforcement on, record still warn: an unbound record is tolerated even
        // though purpose enforcement is strict. This is the exact bootstrapping case the
        // separate flag exists for.
        DataEncryptDecrypt subject = subject("enforce", "warn");
        byte[] taggedPurposeOnly = subject.encrypt(PLAINTEXT, EncryptionPurpose.TAX_RETURN_FACTS, null);
        assertThat(subject.decrypt(taggedPurposeOnly, EncryptionPurpose.TAX_RETURN_FACTS, "row-1"))
                .isEqualTo(PLAINTEXT);
    }

    @Test
    void warnModeReportsUnboundRecord_soAGateHasASignal() {
        DataEncryptDecrypt subject = subject("warn", "warn");
        byte[] unbound = subject.encrypt(PLAINTEXT, EncryptionPurpose.TAX_RETURN_FACTS, null);

        subject.decrypt(unbound, EncryptionPurpose.TAX_RETURN_FACTS, "row-1");

        assertThat(subject.legacyRecordCount()).isEqualTo(1L);
    }

    @Test
    void recordMismatchMessageNamesRecordsAndNothingElse() {
        DataEncryptDecrypt subject = subject("warn", "warn");
        byte[] ciphertext = subject.encrypt(PLAINTEXT, EncryptionPurpose.TAX_RETURN_FACTS, "actor-1", "row-a");
        assertThatThrownBy(() -> subject.decrypt(ciphertext, EncryptionPurpose.TAX_RETURN_FACTS, "row-b"))
                .hasMessageContaining("row-a")
                .hasMessageContaining("row-b")
                .hasMessageNotContaining("actor-1");
    }

    @Test
    void invalidRecordVerificationModeRefusesToStart() {
        EncryptionContextProperties properties = new EncryptionContextProperties();
        properties.setRecordContextVerification("sometimes");
        assertThatThrownBy(properties::validate)
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("record-context-verification");
    }
```

`EncryptionContextProperties.validate()` is package-visible-by-default `void` with no explicit modifier in the original file — confirm it is callable from this test (same package, `gov.irs.directfile.models.autoconfigure`, so it is) before assuming the last test compiles as written.

- [ ] **Step 8: Run the module build**

```bash
cd direct-file/libs && ./mvnw --batch-mode --no-transfer-progress clean install
```

Expected: BUILD SUCCESS, all new and existing tests pass.

- [ ] **Step 9: Format and commit**

```bash
cd direct-file/libs && ./mvnw spotless:apply
cd ../..
git add direct-file/libs/data-models/src/main/java/gov/irs/directfile/models/encryption/EncryptionContexts.java \
        direct-file/libs/data-models/src/main/java/gov/irs/directfile/models/encryption/DataEncryptDecrypt.java \
        direct-file/libs/data-models/src/main/java/gov/irs/directfile/models/autoconfigure/EncryptionContextProperties.java \
        direct-file/libs/data-models/src/main/java/gov/irs/directfile/models/encryption/FactsEncryptor.java \
        direct-file/libs/data-models/src/main/java/gov/irs/directfile/models/encryption/GenericStringEncryptor.java \
        direct-file/libs/data-models/src/test/java/gov/irs/directfile/models/encryption/EncryptionContextsTest.java \
        direct-file/libs/data-models/src/test/java/gov/irs/directfile/models/encryption/DataEncryptDecryptTest.java
git commit -m "feat(data-models): bind and verify a record identity, independent of purpose

purpose verification closes cross-purpose substitution but does nothing
for cross-row substitution within a purpose: every taxpayer's facts are
tax-return-facts, so swapping two rows still decrypts cleanly. id cannot
close this either -- it names the writer, which EncryptionContexts'
own Javadoc is right that a reader can never verify.

record is different: it names the row, and the row being hydrated at
@PostLoad is exactly the row whose identity should be bound, so unlike
id it can be checked at read time. Verified behind its own
record-context-verification flag, independent of context-verification,
so purpose enforcement (never turned on in this codebase, but a
config change away) cannot be coupled to a record backfill that has not
run yet.

Not yet wired to any caller. Every existing method signature is
untouched; this is additive overloads only.

Refs D-1."
```

---

## Task 3: Wire the record binding into `TaxReturnEntityListener` and re-drive the backfill (D-1, wiring)

**Files:**
- Modify: `direct-file/backend/src/main/java/gov/irs/directfile/api/taxreturn/models/TaxReturnEntityListener.java`
- Modify: `direct-file/backend/src/main/java/gov/irs/directfile/api/taxreturn/EncryptionBackfillWorker.java`
- Modify: `direct-file/backend/src/main/resources/application.yaml`
- Create: `direct-file/backend/src/main/resources/db/migrations/20260903110000-reset-encryption-backfill-progress-for-record-schema.yaml`
- Test: `direct-file/backend/src/test/java/gov/irs/directfile/api/taxreturn/models/TaxReturnEntityListenerTest.java`
- Test: new `direct-file/backend/src/test/java/gov/irs/directfile/api/taxreturn/models/TaxReturnEntityListenerIntegrationTest.java`
- Test: `direct-file/backend/src/test/java/gov/irs/directfile/api/taxreturn/EncryptionBackfillWorkerTest.java`

**Interfaces:**
- Consumes: `DataEncryptDecrypt`/`FactsEncryptor`/`GenericStringEncryptor`'s new overloads (Task 2), and `EncryptionBackfillProgress`'s `attempted`/`succeeded`/`failed` columns (Task 1 — this task's own migration resets them, so Task 1's migration must already exist).
- Produces: nothing other tasks consume.

**This step depends on one fact that must be verified, not assumed: that `TaxReturnEntity.getId()` is non-null inside `@PrePersist`.** `TaxReturn`/`TaxReturnSubmission` both use `@GeneratedValue(generator = "UUID4")` on a `UUID` column — an in-memory generator, not one requiring a database round trip (unlike `GenerationType.IDENTITY`), and Hibernate assigns in-memory-generated ids before firing `@PrePersist` callbacks precisely so that callback code can see them. Step 1 below proves this against this codebase's own real Postgres-backed test setup rather than trusting that reasoning.

**Why this re-drives the existing sweep instead of creating a new one.** `EncryptionBackfillRowService.reencrypt` dirties and saves a row; whatever `TaxReturnEntityListener.encryptColumns` does at that moment is what gets written — the row-service's own Javadoc says so: "using whatever context schema the listener implements at the time." Once the listener binds `record`, the *existing* sweep mechanism re-encrypts every row under the new schema the next time it runs from the start. It only needs to run from the start again, which means resetting the two persisted progress rows — not building a second, parallel sweep with its own tracking keys for what is mechanically the identical operation.

- [ ] **Step 1: Prove `getId()` is populated at `@PrePersist`, against a REAL `DataEncryptDecrypt`**

`TaxReturnRepositoryTest.java` (the existing pattern for a `TaxReturn`-persisting test) `@MockBean`s `DataEncryptDecrypt` deliberately, to keep that file fast and crypto-free — which means it can never prove anything about what actually gets bound into a real encryption context, since a mock returns whatever Mockito defaults to regardless of arguments. This step needs a *real* encrypt-then-decrypt round trip, so it needs a different test class with a real `DataEncryptDecrypt`, constructed the same way `DataEncryptDecryptTest.java` already does — a local JCE master key needing no AWS access — rather than the auto-configured KMS-backed one.

Create `direct-file/backend/src/test/java/gov/irs/directfile/api/taxreturn/models/TaxReturnEntityListenerIntegrationTest.java`:

```java
package gov.irs.directfile.api.taxreturn.models;

import java.security.SecureRandom;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.TimeUnit;
import javax.crypto.spec.SecretKeySpec;

import com.amazonaws.encryptionsdk.AwsCrypto;
import com.amazonaws.encryptionsdk.CryptoMaterialsManager;
import com.amazonaws.encryptionsdk.caching.CachingCryptoMaterialsManager;
import com.amazonaws.encryptionsdk.caching.LocalCryptoMaterialsCache;
import com.amazonaws.encryptionsdk.jce.JceMasterKey;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.orm.jpa.TestEntityManager;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.context.annotation.Bean;

import gov.irs.directfile.api.config.identity.IdentityAttributes;
import gov.irs.directfile.api.config.identity.IdentitySupplier;
import gov.irs.directfile.api.taxreturn.TaxReturnRepository;
import gov.irs.directfile.api.user.models.User;
import gov.irs.directfile.api.util.base.BaseRepositoryTest;
import gov.irs.directfile.models.FactTypeWithItem;
import gov.irs.directfile.models.autoconfigure.EncryptionContextProperties;
import gov.irs.directfile.models.encryption.DataEncryptDecrypt;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.doReturn;

/**
 * The one test in this codebase that runs TaxReturnEntityListener against a real
 * DataEncryptDecrypt and a real database rather than a mocked encryptor. Exists specifically
 * to prove record=<id> binding against an actual encrypt-then-decrypt round trip -- a mock
 * cannot prove anything about what got bound into a real encryption context.
 */
@ExtendWith(MockitoExtension.class)
class TaxReturnEntityListenerIntegrationTest extends BaseRepositoryTest {

    @TestConfiguration
    static class TestConfig {
        @Bean
        ObjectMapper objectMapper() {
            return new ObjectMapper();
        }

        @Bean
        DataEncryptDecrypt dataEncryptDecrypt() {
            byte[] rawKey = new byte[32];
            new SecureRandom().nextBytes(rawKey);
            JceMasterKey masterKey = JceMasterKey.getInstance(
                    new SecretKeySpec(rawKey, "AES"), "local", "local", "AES/GCM/NoPadding");
            CryptoMaterialsManager cmm = CachingCryptoMaterialsManager.newBuilder()
                    .withMasterKeyProvider(masterKey)
                    .withCache(new LocalCryptoMaterialsCache(10))
                    .withMaxAge(60, TimeUnit.SECONDS)
                    .withMessageUseLimit(1000)
                    .build();
            EncryptionContextProperties properties = new EncryptionContextProperties();
            properties.setContextVerification(EncryptionContextProperties.WARN);
            properties.setRecordContextVerification(EncryptionContextProperties.WARN);
            return new DataEncryptDecrypt(AwsCrypto.standard(), cmm, properties);
        }
    }

    @MockBean
    private IdentitySupplier mockIdentitySupplier;

    @Autowired
    private TestEntityManager entityManager;

    @Autowired
    private TaxReturnRepository taxReturnRepo;

    @BeforeEach
    void configure() {
        doReturn(new IdentityAttributes(UUID.randomUUID(), UUID.randomUUID(), "email@example.com", "123456789"))
                .when(mockIdentitySupplier)
                .get();
    }

    @Test
    void newlyPersistedTaxReturnRoundTripsThroughRealEncryptionWithARecordBinding() {
        // If this fails because taxReturn.getId() was null inside encryptColumns on this
        // first-time insert, the whole premise of binding record=<id> at @PrePersist is wrong
        // -- stop and report rather than adding a null-guard to make this pass.
        User user = new User(UUID.randomUUID());
        entityManager.persist(user);

        TaxReturn taxReturn = new TaxReturn();
        taxReturn.addOwner(user);
        taxReturn.setFacts(Map.of(
                "/foo",
                new FactTypeWithItem(
                        "gov.irs.factgraph.persisters.StringWrapper",
                        com.fasterxml.jackson.databind.node.TextNode.valueOf("baz"))));
        taxReturn.setStore("{}");

        TaxReturn saved = taxReturnRepo.save(taxReturn);
        entityManager.flush();
        entityManager.clear();

        assertThat(saved.getId()).isNotNull();

        // Force a real @PostLoad against what was actually persisted, not the in-memory
        // instance the persistence context would otherwise hand back unchanged. decryptColumns
        // runs here using saved.getId() as the expected record -- if the id were null at
        // @PrePersist, the written record value and this read-time expectation would already
        // disagree, and this would throw EncryptionContextMismatchException before reaching
        // the assertion below.
        TaxReturn reloaded = taxReturnRepo.findById(saved.getId()).orElseThrow();
        assertThat(reloaded.getFacts()).containsKey("/foo");
    }
}
```

Run it in isolation before writing anything else in this task:

```bash
cd direct-file/backend
./mvnw --batch-mode --no-transfer-progress test -Dtest=TaxReturnEntityListenerIntegrationTest
```

Expected: PASSES already, before Step 2 changes anything. `TaxReturnEntityListener.encryptColumns`/`decryptColumns` still call the pre-Task-2 two-argument overloads at this point, which never touch `record` at all — this run establishes that the real-encryption test harness itself works (real encrypt, real decrypt, real database, real id) before Step 2 makes the test actually exercise the record binding. If it fails here, the failure is in the harness (a missing bean, a bad FK), not in anything this task's own code changes — fix the harness before proceeding to Step 2.

- [ ] **Step 2: Wire the listener**

Replace the whole of `TaxReturnEntityListener.java`:

```java
package gov.irs.directfile.api.taxreturn.models;

import com.fasterxml.jackson.databind.ObjectMapper;
import edu.umd.cs.findbugs.annotations.SuppressFBWarnings;
import jakarta.persistence.PostLoad;
import jakarta.persistence.PrePersist;
import jakarta.persistence.PreUpdate;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import gov.irs.directfile.api.authentication.NullAuthenticationException;
import gov.irs.directfile.api.config.identity.IdentityAttributes;
import gov.irs.directfile.api.config.identity.IdentitySupplier;
import gov.irs.directfile.models.encryption.DataEncryptDecrypt;
import gov.irs.directfile.models.encryption.EncryptionPurpose;
import gov.irs.directfile.models.encryption.FactsEncryptor;
import gov.irs.directfile.models.encryption.GenericStringEncryptor;

@Component
@SuppressFBWarnings(value = {"ST_WRITE_TO_STATIC_FROM_INSTANCE_METHOD"})
public class TaxReturnEntityListener {
    private static IdentitySupplier identitySupplier;
    private static FactsEncryptor factsEncryptor;
    private static GenericStringEncryptor genericStringEncryptor;

    @Autowired
    public void configure(
            IdentitySupplier dfIdentitySupplier, DataEncryptDecrypt dataEncryptDecrypt, ObjectMapper objectMapper) {
        identitySupplier = dfIdentitySupplier;
        factsEncryptor = new FactsEncryptor(dataEncryptDecrypt);
        genericStringEncryptor = new GenericStringEncryptor(dataEncryptDecrypt);
    }

    @PostLoad
    public <T extends TaxReturnEntity> void decryptColumns(T taxReturn) {
        String recordId = taxReturn.getId().toString();
        taxReturn.setFactsWithoutDirtyingEntity(factsEncryptor.convertToEntityAttribute(
                taxReturn.getFactsCipherText(), EncryptionPurpose.TAX_RETURN_FACTS, recordId));
        taxReturn.setStoreWithoutDirtyingEntity(genericStringEncryptor.convertToEntityAttribute(
                taxReturn.getStoreCipherText(), EncryptionPurpose.TAX_RETURN_STORE, recordId));
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

        String recordId = taxReturn.getId().toString();
        taxReturn.setFactsCipherText(factsEncryptor.convertToDatabaseColumn(
                taxReturn.getFacts(), EncryptionPurpose.TAX_RETURN_FACTS, actorId, recordId));
        taxReturn.setStoreCipherText(genericStringEncryptor.convertToDatabaseColumn(
                taxReturn.getStore(), EncryptionPurpose.TAX_RETURN_STORE, actorId, recordId));
    }
}
```

No null-guard on `taxReturn.getId()` in either method — Step 1 exists specifically to convert "getId() is available at PrePersist" from an assumption into a verified fact before this code depends on it. If Step 1's test failed for a reason other than the record mismatch this step introduces, do not add a null-guard here as a workaround — stop and report, because it means new inserts would need a different design (persist once unbound, then a follow-up update) than the one this task assumes.

- [ ] **Step 3: Re-run the integration test**

```bash
cd direct-file/backend
./mvnw --batch-mode --no-transfer-progress test -Dtest=TaxReturnEntityListenerIntegrationTest
```

Expected: still PASSES — but for a materially different reason than Step 1's run. This is not a red-to-green step and should not be reported as one: Step 1 already passed without any record binding in play at all. What changed is what the pass now proves. The `entityManager.clear()` already in the test (Step 1) forces the reload's `@PostLoad` to run against what Hibernate actually persisted rather than handing back the same in-memory managed instance untouched — so this run is the first one where a mismatched `record` value between the `@PrePersist` write and the `@PostLoad` read would actually surface as a thrown `EncryptionContextMismatchException` instead of passing vacuously. Say exactly this in the eventual PR rather than describing Step 1 and Step 3 as a failing-then-passing pair.

- [ ] **Step 4: Update the existing listener unit tests**

`TaxReturnEntityListenerTest.java`'s existing tests construct a bare `new TaxReturn()` and never persist it, so `getId()` is null on that path — Step 2's change makes every one of those tests NPE. Update the test helper and every test that calls `encryptColumns` or `decryptColumns` to set an id first. Change `taxReturnWithContent()`:

```java
    private TaxReturn taxReturnWithContent() {
        TaxReturn taxReturn = new TaxReturn();
        taxReturn.setId(java.util.UUID.randomUUID());
        taxReturn.setFacts(Map.of(
                "/foo",
                new FactTypeWithItem(
                        "gov.irs.factgraph.persisters.StringWrapper",
                        com.fasterxml.jackson.databind.node.TextNode.valueOf("baz"))));
        taxReturn.setStore("{}");
        return taxReturn;
    }
```

`TaxReturn.java` has no `setId(...)` at all today — its class-level annotation is `@Getter` only, and the `id` field carries no field-level `@Setter` either (unlike its sibling `TaxReturnSubmission.java`, whose `id` field has `@Setter` directly on it). Add `@Setter` to `TaxReturn.java`'s `id` field:

```java
    @Id
    @Setter
    @GeneratedValue(generator = "UUID4")
    @Column(nullable = false, updatable = false)
    private UUID id;
```

This is a one-annotation addition for exactly this reason (tests need to construct a persistable-looking instance without a real database) and mirrors `TaxReturnSubmission`'s own field exactly.

`encryptColumns_writesFactsAndStoreUnderDistinctPurposes` and the two tests directly following it construct their own `TaxReturn` inline rather than via the helper — add `taxReturn.setId(UUID.randomUUID());` to each of those constructions too. `decryptColumns_readsEachColumnUnderItsOwnPurpose` also constructs its own `TaxReturn` — add the same line there.

- [ ] **Step 5: Add the record-binding guard to the backfill worker**

In `EncryptionBackfillWorker.verifyRunnable`, replace:

```java
    @PostConstruct
    public void verifyRunnable() {
        if (!enabled) {
            return;
        }
        if (encryptionContextProperties.isEnforcing()) {
            throw new IllegalStateException("The encryption backfill requires "
                    + "direct-file.encryption.context-verification=warn. Under enforce, untagged "
                    + "ciphertext cannot be read, so the sweep would skip every row it exists to migrate.");
        }
        log.warn("Encryption backfill is ENABLED, batchSize={}", batchSize);
    }
```

with:

```java
    @PostConstruct
    public void verifyRunnable() {
        if (!enabled) {
            return;
        }
        if (encryptionContextProperties.isEnforcing() || encryptionContextProperties.isRecordEnforcing()) {
            throw new IllegalStateException("The encryption backfill requires both "
                    + "direct-file.encryption.context-verification and "
                    + "direct-file.encryption.record-context-verification to be 'warn'. Under enforce, untagged "
                    + "ciphertext cannot be read, so the sweep would skip every row it exists to migrate.");
        }
        log.warn("Encryption backfill is ENABLED, batchSize={}", batchSize);
    }
```

- [ ] **Step 6: Update the worker's unit tests for the new guard**

In `EncryptionBackfillWorkerTest.java`, the existing `enforceMode()` helper only sets `setContextVerification`. Add a sibling:

```java
    private EncryptionContextProperties recordEnforceMode() {
        EncryptionContextProperties properties = new EncryptionContextProperties();
        properties.setContextVerification(EncryptionContextProperties.WARN);
        properties.setRecordContextVerification(EncryptionContextProperties.ENFORCE);
        return properties;
    }
```

And add a test alongside `refusesToStartUnderEnforceMode`:

```java
    @Test
    void refusesToStartUnderRecordEnforceModeToo() {
        EncryptionBackfillWorker worker =
                new EncryptionBackfillWorker(service, recordEnforceMode(), advisoryLockRepository, true, 100);

        assertThatThrownBy(worker::verifyRunnable)
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("record-context-verification");
    }
```

`warnMode()` already sets only `contextVerification`; `EncryptionContextProperties.recordContextVerification` defaults to `WARN` in the class itself, so every other existing test in this file (which builds properties via `warnMode()`/`enforceMode()` and never touches the record flag) keeps passing unchanged.

- [ ] **Step 7: Add the flag to `application.yaml`**

`context-verification` is not currently set in `application.yaml` at all (it relies on the Java default). Add the record flag the same way, as a comment-only placeholder next to where the backfill's own config already lives:

```yaml
  encryption:
    # H-1 Phase B. Off by default; enabling requires context-verification=warn and the
    # two owner approvals in docs/security/2026-08-25_h1-encryption-context-spec.md §6.
    # record-context-verification also defaults to warn (see EncryptionContextProperties)
    # and is not set here for the same reason context-verification is not: neither has ever
    # been flipped to enforce in this codebase. Flipping either is an operator decision
    # gated by EncryptionBackfillProgressRepository.allTablesCleanlyMigrated(), not a step
    # in any plan.
    backfill:
      enabled: false
      batch-size: 100
      fixed-delay-millis: 5000
```

- [ ] **Step 8: Re-drive the sweep**

Create `direct-file/backend/src/main/resources/db/migrations/20260903110000-reset-encryption-backfill-progress-for-record-schema.yaml`:

```yaml
databaseChangeLog:
  - changeSet:
      id: reset-encryption-backfill-progress-for-record-schema
      author: directfile
      comment: >
        TaxReturnEntityListener now binds a record identity in addition to purpose
        (D-1 of the 2026-09-02 delta security review). The sweep mechanism re-encrypts
        whatever the listener's current schema produces on every dirty-and-save -- it
        does not need new tracking keys, only a reason to run from the start again.
        Resetting these two rows is that reason. This is data, not schema: safe to run
        more than once, and each existing row is reset to the same "not started" state
        EncryptionBackfillService already treats a missing row as.
      changes:
        - update:
            tableName: encryption_backfill_progress
            columns:
              - column:
                  name: last_id
                  value: null
              - column:
                  name: completed
                  valueBoolean: false
              - column:
                  name: attempted
                  valueNumeric: 0
              - column:
                  name: succeeded
                  valueNumeric: 0
              - column:
                  name: failed
                  valueNumeric: 0
            where: target_table IN ('taxreturns', 'taxreturn_submissions')
      rollback:
        - empty
```

`rollback: - empty` is deliberate: there is no meaningful rollback for "un-reset a cursor" — the prior values were themselves the output of a real sweep and are not recoverable from this changeset. If Liquibase requires a non-empty rollback block to validate, use a `sql` no-op (`SELECT 1;`) instead of `empty` — check which form this repo's other migrations use for changesets with no real rollback, if any exist, before assuming either syntax works.

This migration must run after Task 1's (`20260903100000-...`) both because it references the `attempted`/`succeeded`/`failed` columns Task 1 adds and because its own timestamp sorts after Task 1's in `changelog.yaml`'s `includeAll`.

- [ ] **Step 9: Run the full backend build**

```bash
cd direct-file/libs && ./mvnw --batch-mode --no-transfer-progress clean install
cd ../backend && ./mvnw --batch-mode --no-transfer-progress verify
```

Expected: BUILD SUCCESS. This is the step that proves the reset migration is syntactically valid Liquibase (it runs against the test database as part of the integration test suite's schema setup) and that every listener test updated in Step 4 passes.

- [ ] **Step 10: Format and commit**

```bash
cd direct-file/backend && ./mvnw spotless:apply
cd ../..
git add direct-file/backend/src/main/java/gov/irs/directfile/api/taxreturn/models/TaxReturnEntityListener.java \
        direct-file/backend/src/main/java/gov/irs/directfile/api/taxreturn/EncryptionBackfillWorker.java \
        direct-file/backend/src/main/resources/application.yaml \
        direct-file/backend/src/main/resources/db/migrations/20260903110000-reset-encryption-backfill-progress-for-record-schema.yaml \
        direct-file/backend/src/test/java/gov/irs/directfile/api/taxreturn/models/TaxReturnEntityListenerTest.java \
        direct-file/backend/src/test/java/gov/irs/directfile/api/taxreturn/models/TaxReturnEntityListenerIntegrationTest.java \
        direct-file/backend/src/test/java/gov/irs/directfile/api/taxreturn/EncryptionBackfillWorkerTest.java
git add direct-file/backend/src/main/java/gov/irs/directfile/api/taxreturn/models/TaxReturn.java
git commit -m "fix(backend): bind and verify record=<row id>, closing the H-1 row-swap scenario

TaxReturnEntityListener now passes the entity's own id as the expected
record on every encrypt and decrypt, using the record-aware overloads
DataEncryptDecrypt gained for exactly this. Every taxpayer's facts were
previously written under an identical context (purpose=TAX_RETURN_FACTS
for every return); swapping two rows' ciphertext decrypted cleanly
either way. That is now refused, in both verification modes.

record-context-verification defaults to warn, independent of
context-verification, so this does not require any row to already
carry the new binding -- it starts reporting unbound rows rather than
rejecting them, exactly as purpose verification did at its own
introduction.

Re-drives the existing sweep by resetting its two persisted progress
rows rather than building a second one: the sweep mechanism re-encrypts
whatever the listener's current schema produces, so it only needed a
reason to run from the start again, not new tracking keys for what is
mechanically the same operation.

Verified TaxReturnEntity.getId() is populated inside @PrePersist with a
real save-then-reload integration test before depending on it, rather
than assuming Hibernate's UUID-generator timing.

Refs D-1."
```

---

## Task 4: Namespace the advisory-lock keyspace (D-3)

**Files:**
- Modify: `direct-file/backend/src/main/java/gov/irs/directfile/api/taxreturn/submissions/lock/AdvisoryLockRepository.java`
- Modify: `direct-file/backend/src/main/java/gov/irs/directfile/api/taxreturn/EncryptionBackfillWorker.java`
- Modify: `direct-file/backend/src/main/java/gov/irs/directfile/api/taxreturn/TaxReturnService.java`
- Test: `direct-file/backend/src/test/java/gov/irs/directfile/api/taxreturn/EncryptionBackfillWorkerTest.java`

**Interfaces:**
- Consumes: nothing from other tasks.
- Produces: nothing other tasks consume. Fully independent of Tasks 1-3.

Two unrelated lock namespaces share one 32-bit key space: `"encryption-backfill-sweep".hashCode()` and `taxReturnId.hashCode()` both go through `pg_try_advisory_lock(:lockId)`, the single-argument form. A tax return whose UUID happens to hash to the backfill's constant makes that return's submission and the sweep mutually exclusive. Postgres's two-argument form, `pg_try_advisory_lock(key1, key2)`, exists precisely to namespace unrelated lock spaces.

- [ ] **Step 1: Confirm today's shape**

```bash
cd direct-file/backend
grep -n "pg_try_advisory_lock\|pg_advisory_lock\|pg_advisory_unlock" src/main/java/gov/irs/directfile/api/taxreturn/submissions/lock/AdvisoryLockRepository.java
```

Expected: three matches, all single-argument. If any already take two arguments, stop and report.

- [ ] **Step 2: Add the namespaced two-argument variants**

Add to `AdvisoryLockRepository.java` (keep the three existing single-argument methods exactly as they are, for now — Step 3 and Step 4 replace their call sites, not this interface's existing methods):

```java
    @Query(value = "SELECT pg_try_advisory_lock(:namespace, :lockId)", nativeQuery = true)
    boolean acquireLock(int namespace, int lockId);

    @Query(value = "SELECT pg_advisory_unlock(:namespace, :lockId)", nativeQuery = true)
    boolean releaseLock(int namespace, int lockId);
```

- [ ] **Step 3: Namespace the backfill's lock**

In `EncryptionBackfillWorker.java`, add a namespace constant next to `LOCK_ID` and update its three call sites:

```java
    /** Distinguishes this lock's keyspace from TaxReturnService's per-return submission locks,
     * which share the same single 32-bit pg_try_advisory_lock(int) space by hashing an
     * unrelated value (a tax return UUID) into it. Any fixed, arbitrary value works here --
     * what matters is that it differs from the namespace TaxReturnService uses. */
    private static final int NAMESPACE = "encryption-backfill".hashCode();

    /** String.hashCode() is specified and stable across JVM restarts, unlike Object.hashCode(). */
    private static final int LOCK_ID = "encryption-backfill-sweep".hashCode();
```

Replace the two lock calls in `tick()`:

```java
        if (!advisoryLockRepository.acquireLock(LOCK_ID)) {
```
→
```java
        if (!advisoryLockRepository.acquireLock(NAMESPACE, LOCK_ID)) {
```

```java
            if (!advisoryLockRepository.releaseLock(LOCK_ID)) {
```
→
```java
            if (!advisoryLockRepository.releaseLock(NAMESPACE, LOCK_ID)) {
```

- [ ] **Step 4: Namespace the submission lock**

In `TaxReturnService.java`, find the two `advisoryLockRepository.acquireLock(lockId)` / `releaseLock(lockId)` calls around line 385 and the constant they use. Add a namespace constant at class level:

```java
    /** Distinguishes this lock's keyspace from EncryptionBackfillWorker's sweep lock, which
     * shares the same single 32-bit pg_try_advisory_lock(int) space via a different fixed
     * hash. Any fixed, arbitrary value works here -- what matters is that it differs from
     * that one. */
    private static final int SUBMISSION_LOCK_NAMESPACE = "tax-return-submission".hashCode();
```

Then change:

```java
        int lockId = taxReturnId.hashCode();
        boolean lockAcquired = advisoryLockRepository.acquireLock(lockId);
```

to:

```java
        int lockId = taxReturnId.hashCode();
        boolean lockAcquired = advisoryLockRepository.acquireLock(SUBMISSION_LOCK_NAMESPACE, lockId);
```

and the corresponding release call from `advisoryLockRepository.releaseLock(lockId)` to `advisoryLockRepository.releaseLock(SUBMISSION_LOCK_NAMESPACE, lockId)`. Read the surrounding method in full first — the release call is in a `finally` block some lines below the acquire, and this plan is not quoting every line of that method, only the two call sites that must change.

- [ ] **Step 5: Update the worker's tests for the new call signature**

`EncryptionBackfillWorkerTest.java`'s existing mocks use `advisoryLockRepository.acquireLock(anyInt())` / `releaseLock(anyInt())` — the single-argument overload, which still exists on the interface but is no longer called by `EncryptionBackfillWorker`. Confirm the exact count before editing rather than trusting a number written here:

```bash
grep -n "acquireLock(anyInt())\|releaseLock(anyInt())" src/test/java/gov/irs/directfile/api/taxreturn/EncryptionBackfillWorkerTest.java
```

Every `when(...)`, `verify(...)`, and `verify(..., never())` this prints must change to the two-argument form: `acquireLock(anyInt(), anyInt())` / `releaseLock(anyInt(), anyInt())`. Update every one; do not leave any single-argument mock stub in this file, since none of them will ever be invoked once Step 3 lands and the test would then be asserting nothing.

- [ ] **Step 6: Run the backend build**

```bash
cd direct-file/backend
./mvnw --batch-mode --no-transfer-progress verify
```

Expected: BUILD SUCCESS.

- [ ] **Step 7: Format and commit**

```bash
./mvnw spotless:apply
cd ../..
git add direct-file/backend/src/main/java/gov/irs/directfile/api/taxreturn/submissions/lock/AdvisoryLockRepository.java \
        direct-file/backend/src/main/java/gov/irs/directfile/api/taxreturn/EncryptionBackfillWorker.java \
        direct-file/backend/src/main/java/gov/irs/directfile/api/taxreturn/TaxReturnService.java \
        direct-file/backend/src/test/java/gov/irs/directfile/api/taxreturn/EncryptionBackfillWorkerTest.java
git commit -m "fix(backend): namespace the advisory-lock keyspace

EncryptionBackfillWorker's sweep lock and TaxReturnService's per-return
submission lock shared one 32-bit pg_try_advisory_lock(int) space. A tax
return whose UUID happened to hash to the sweep's constant made that
return's submission and the sweep mutually exclusive -- rare (roughly
n/2^32), transient, and silent when it happened.

Added the two-argument pg_try_advisory_lock(key1, key2)/pg_advisory_unlock
variants Postgres provides for exactly this, and gave each subsystem its
own fixed namespace constant. The existing single-argument methods are
untouched on the interface; nothing else in this codebase calls them.

Refs D-3."
```

---

## Task 5: `lastFour` no longer emits a short TIN unchanged (D-5)

**Files:**
- Modify: `direct-file/backend/src/main/java/gov/irs/directfile/api/user/UserService.java`
- Test: `direct-file/backend/src/test/java/gov/irs/directfile/api/user/UserServiceTest.java`

**Interfaces:**
- Consumes: nothing from other tasks.
- Produces: nothing other tasks consume. Fully independent.

A TIN of four characters or fewer is malformed and should not exist, but `lastFour` currently returns it unchanged rather than the last four characters, because `tin.length() <= 4` treats "exactly four" and "fewer than four" the same. The M-1 remediation means this map is no longer the last line of defense against a full TIN reaching a log, so this is Info severity, not a live defect — but a fixed placeholder is both safer and a clearer signal that upstream validation failed than silently forwarding a too-short value.

- [ ] **Step 1: Confirm today's shape**

```bash
cd direct-file/backend
grep -n "lastFour" -A5 src/main/java/gov/irs/directfile/api/user/UserService.java
```

Expected: `return tin.length() <= 4 ? tin : tin.substring(tin.length() - 4);`. If different, stop and report.

- [ ] **Step 2: Fix it**

Replace:

```java
    private static String lastFour(String tin) {
        if (tin == null) {
            return null;
        }
        return tin.length() <= 4 ? tin : tin.substring(tin.length() - 4);
    }
```

with:

```java
    private static String lastFour(String tin) {
        if (tin == null) {
            return null;
        }
        if (tin.length() < 4) {
            // Malformed: a real TIN is never this short. Emitting it unchanged would put
            // more into the audit map than "last four" promises, for no operational benefit
            // -- a fixed placeholder is both safer and a clearer signal that validation
            // upstream of this method failed.
            return "????";
        }
        return tin.substring(tin.length() - 4);
    }
```

A TIN of exactly four characters still returns unchanged (`substring(0)` is the whole string) — only the strictly-shorter case changes.

- [ ] **Step 3: Update the test that asserts today's behavior**

In `UserServiceTest.java`, replace `getCurrentUserInfo_handlesAShortOrMissingTinWithoutThrowing`:

```java
    @Test
    void getCurrentUserInfo_handlesAShortOrMissingTinWithoutThrowing() {
        IdentityAttributes shortTin =
                new IdentityAttributes(UUID.randomUUID(), UUID.randomUUID(), "taxpayer@example.com", "12");
        when(identitySupplier.get()).thenReturn(shortTin);

        userService.getCurrentUserInfo();

        // Never pad, never substring past the end, never log more than four characters.
        verify(auditService).addEventProperty(AuditLogElement.USER_TIN_LAST4, "12");
    }
```

with:

```java
    @Test
    void getCurrentUserInfo_handlesAShortOrMissingTinWithoutThrowing() {
        IdentityAttributes shortTin =
                new IdentityAttributes(UUID.randomUUID(), UUID.randomUUID(), "taxpayer@example.com", "12");
        when(identitySupplier.get()).thenReturn(shortTin);

        userService.getCurrentUserInfo();

        // A TIN this short is malformed and should not exist. A fixed placeholder is both
        // safer than forwarding it unchanged and a clearer signal that something upstream
        // is wrong, regardless of how short the input actually was.
        verify(auditService).addEventProperty(AuditLogElement.USER_TIN_LAST4, "????");
    }
```

- [ ] **Step 4: Run the test and commit**

```bash
cd direct-file/backend
./mvnw --batch-mode --no-transfer-progress test -Dtest=UserServiceTest
./mvnw spotless:apply
cd ../..
git add direct-file/backend/src/main/java/gov/irs/directfile/api/user/UserService.java \
        direct-file/backend/src/test/java/gov/irs/directfile/api/user/UserServiceTest.java
git commit -m "fix(backend): lastFour no longer emits a short TIN unchanged

tin.length() <= 4 treated \"exactly four\" and \"fewer than four\" the
same, so a malformed TIN under four characters was emitted into the
audit map in full rather than truncated. Such a TIN should not exist,
and M-1 means this map is no longer the last line of defense, so this
was Info severity -- but a fixed placeholder for the malformed case is
both safer and a clearer signal that upstream validation failed than
silently forwarding whatever arrived.

Refs D-5."
```

---

## Handbacks

1. **D-4 (No clickjacking protection) is deliberately not code in this plan.** Whether it is exploitable depends on edge/CDN configuration this repository cannot see — the meta-delivered CSP's own comment already says `frame-ancestors` needs a response header, and a repository-wide search confirms no `X-Frame-Options` header, no `frame-ancestors` directive, and no Spring Security `frameOptions` configuration exist anywhere. Someone who can inspect the actual deployment edge needs to confirm whether it already sets one of those. If it does, record that. If it does not, the CSP needs to move off the `<meta>` tag onto a real response header — which also recovers `report-uri` and the ability to stage changes in report-only mode, the other two capabilities meta delivery costs, and was already a client-hardening-plan handback for a different reason.

2. **The interim mitigation for D-1, until Task 3 lands, is `TaxReturnRepository`'s existing scoping** (`findByIdAndUserId`, joins through `t.owners`), which the original review examined and found sound. It is a single layer, and defeating it — reaching a row swap by some other means — was the premise of the H-1 scenario D-1 closes. This plan does not change that scoping; Task 3 adds a second, independent layer behind it.

3. **Record verification is not split per-purpose the way the existing purpose-mismatch legacy counter is.** `DataEncryptDecrypt.legacyRecordCount()` is one counter across both `TAX_RETURN_FACTS` and `TAX_RETURN_STORE`, unlike `legacyCountFor(EncryptionPurpose)`. Nothing in this plan needs the finer granularity; if an operator ever wants to know "are facts migrated but not store" during the re-driven sweep, that is a small, separate addition to make later rather than something this plan builds speculatively now.

4. **Enforcing either verification flag is still a future, separate operator decision — this plan does not flip either.** `context-verification` has never been set to `enforce` anywhere in this codebase, and this plan does not change that; `record-context-verification` is introduced defaulting to `warn` for the same reason. `EncryptionBackfillProgressRepository.allTablesCleanlyMigrated()` (Task 1) is the gate for both, once the re-driven sweep (Task 3) actually completes.

5. **Branch protection on `main` is still not applied.** `gh api repos/twarn247/direct-file/branches/main/protection` returns `404 Branch not protected`. Three plans have now carried this forward.

6. **The security review's register is not fully closed until Task 1-3 land here.** With them, D-1 and D-2 join the original review's fully-closed set; D-3 and D-5 close in this plan too. D-4 remains open pending the edge-configuration question in Handback 1.
