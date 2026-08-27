# H-1 Phase B — Ciphertext Backfill Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Re-encrypt every existing `taxreturns` and `taxreturn_submissions` row so its ciphertext carries a bound encryption purpose, driving the `ENCRYPTION_CONTEXT_LEGACY` count to zero and making Phase C's flip to `enforce` safe.

**Architecture:** A resumable, restartable batch worker in the backend. It pages through each table by primary key using an id-only query (deliberately not an entity query — see Task 2), loads one entity at a time, dirties it so the existing `@PreUpdate` listener re-encrypts it with the Phase A purpose schema, and advances a persisted cursor. No new cryptographic code: the re-encryption is entirely the mechanism Phase A already built, driven from outside. A single scheduled tick processes one batch and returns, so the worker is stoppable at any point and resumes where it stopped.

**Tech Stack:** Java 21, Spring Boot 3.3.10, Spring Data JPA, Liquibase, Maven (`./mvnw`), JUnit 5 + Mockito, Spotless with palantir-java-format.

**Spec:** `docs/security/2026-08-25_h1-encryption-context-spec.md` — §4 defines the Phase B interface and is the design this plan implements.

## Global Constraints

- **Java 21.** Do not use preview features.
- **Format before every commit:** `./mvnw spotless:apply` from `direct-file/backend/`. CI enforces palantir-java-format 2.39.0.
- **Backend tests run from `direct-file/backend/`** with `./mvnw test`.
- **No new dependencies.** Everything needed is on the backend's classpath.
- **The backfill must run in `warn` mode.** `direct-file.encryption.context-verification` defaults to `warn` (`EncryptionContextProperties:22`). Under `enforce`, `decrypt` rejects untagged ciphertext — which is exactly the population Phase B exists to migrate, so the backfill could not read the rows it needs to rewrite. Task 5 adds a startup guard; do not weaken it.
- **Do not touch `EncryptionPurpose`, `EncryptionContexts`, or `DataEncryptDecrypt`.** Phase A settled the schema. Phase B is a driver, not a change to the crypto layer.
- **Two tables are in scope:** `taxreturns` (facts + store) and `taxreturn_submissions` (facts only). Both use `TaxReturnEntityListener`.

## Scope note

**This is Phase B only.** Phase C — flipping `context-verification` to `enforce` — is not in this plan. Phase B's completion is *necessary but not sufficient* for Phase C: the gate is the `ENCRYPTION_CONTEXT_LEGACY` log marker reading zero across an observation window, and that window's length is a data-retention decision the milestone owner still owes (spec §6 item 3).

**Two owner approvals gate execution**, both from spec §6. Task 5 Step 1 makes the implementer confirm them before the worker can be enabled anywhere:

- Item 4 — **the loss of `id` attribution on backfilled rows.** The backfill runs with no authenticated principal, so `TaxReturnEntityListener.encryptColumns` takes its `NullAuthenticationException` branch and writes `actorId = null`. A backfilled row is no longer attributable to its original writer in CloudTrail. `id` is informational and unverified by design, so this is a real but bounded trade.
- Item 5 — **whether anything outside this repository reads `taxreturns.updated_at`.** `TaxReturn.updatedAt` is `@UpdateTimestamp`, so a full-table pass bumps every row. No application query in `backend/src/main` reads it, but downstream analytics or retention tooling might.

**One open question changes scope rather than gating it** (spec §6 item 2): if `generateAuthorizationToken` turns out to be reachable in a deployed environment, state-api has a ciphertext population too and Phase B grows a third table. Task 5 Step 2 records the check; it does not block the other work.

## File structure

| File | Responsibility |
|---|---|
| `db/migrations/20260827090000-create-encryption-backfill-progress-table.yaml` | Cursor table |
| `models/EncryptionBackfillProgress.java` | Cursor entity, one row per target table |
| `EncryptionBackfillProgressRepository.java` | Cursor persistence |
| `TaxReturnRepository` / `TaxReturnSubmissionRepository` | id-only paging queries (added methods) |
| `models/TaxReturnEntity.java` | Gains `setFacts` so the backfill can be generic (added method) |
| `EncryptionBackfillRowService.java` | Re-encrypt one row, in its own transaction |
| `EncryptionBackfillService.java` | Process one batch; advance the cursor |
| `EncryptionBackfillWorker.java` | Scheduling, enable flag, warn-mode guard, progress logging |

Three beans rather than one. The row service is separate from the batch service because `@Transactional(REQUIRES_NEW)` works through a Spring proxy: a self-invocation from the batch loop would bypass it and silently give every row the caller's transaction, so one row's failure could mark the whole batch rollback-only. Separating the worker from both keeps the operational concerns — enabled/disabled, mode guard, logging cadence — in one place a reviewer can read on its own.

---

## Task 1: Persist backfill progress

A full-table pass over encrypted data will be interrupted — deploys, restarts, an operator stopping it. Progress must survive that, per target table.

**Files:**
- Create: `direct-file/backend/src/main/resources/db/migrations/20260827090000-create-encryption-backfill-progress-table.yaml`
- Create: `direct-file/backend/src/main/java/gov/irs/directfile/api/taxreturn/models/EncryptionBackfillProgress.java`
- Create: `direct-file/backend/src/main/java/gov/irs/directfile/api/taxreturn/EncryptionBackfillProgressRepository.java`
- Test: `direct-file/backend/src/test/java/gov/irs/directfile/api/taxreturn/EncryptionBackfillProgressRepositoryTest.java`

**Interfaces:**
- Consumes: nothing from earlier tasks.
- Produces:
  - `EncryptionBackfillProgress` entity — fields `targetTable` (String, `@Id`), `lastId` (UUID, nullable), `completed` (boolean), `updatedAt` (Date).
  - `EncryptionBackfillProgressRepository extends CrudRepository<EncryptionBackfillProgress, String>`.
  - Constants `EncryptionBackfillProgress.TAX_RETURNS = "taxreturns"` and `EncryptionBackfillProgress.TAX_RETURN_SUBMISSIONS = "taxreturn_submissions"`.

**Design note.** The cursor is an explicit `lastId` UUID rather than a Spring Data `KeysetScrollPosition`, because a scroll position is an in-memory object that cannot be persisted across a restart. `WHERE id > :lastId ORDER BY id ASC` is trivially resumable and gives a total order — Postgres compares `uuid` bytewise, so ordering is stable even though UUIDv4 values are not monotonic.

- [ ] **Step 1: Write the migration**

Create `direct-file/backend/src/main/resources/db/migrations/20260827090000-create-encryption-backfill-progress-table.yaml`:

```yaml
databaseChangeLog:
  - changeSet:
      id: create-encryption-backfill-progress-table
      author: directfile
      changes:
        - createTable:
            tableName: encryption_backfill_progress
            columns:
              - column:
                  name: target_table
                  type: varchar(64)
                  constraints:
                    nullable: false
                    primaryKey: true
                    primaryKeyName: encryption_backfill_progress_pkey
              # Highest primary key already re-encrypted. Null means "not started".
              - column:
                  name: last_id
                  type: uuid
                  constraints:
                    nullable: true
              - column:
                  name: completed
                  type: boolean
                  defaultValueBoolean: false
                  constraints:
                    nullable: false
              - column:
                  name: updated_at
                  type: timestamp
                  defaultValueComputed: 'CURRENT_TIMESTAMP'
                  constraints:
                    nullable: false
      rollback:
        - dropTable:
            tableName: encryption_backfill_progress
```

`db/changelog.yaml` uses `includeAll` over `migrations/`, so no registration step is needed.

- [ ] **Step 2: Write the failing test**

Create `direct-file/backend/src/test/java/gov/irs/directfile/api/taxreturn/EncryptionBackfillProgressRepositoryTest.java`. Match the persistence-test style already used in this package — find an existing `@DataJpaTest` or `@SpringBootTest` repository test and copy its annotations and any test-profile setup rather than inventing new ones:

```java
package gov.irs.directfile.api.taxreturn;

import java.util.Optional;
import java.util.UUID;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;

import gov.irs.directfile.api.taxreturn.models.EncryptionBackfillProgress;

import static org.assertj.core.api.Assertions.assertThat;

class EncryptionBackfillProgressRepositoryTest {

    @Autowired
    private EncryptionBackfillProgressRepository repository;

    @Test
    void persistsAndReadsBackACursor() {
        UUID cursor = UUID.randomUUID();
        EncryptionBackfillProgress progress = new EncryptionBackfillProgress();
        progress.setTargetTable(EncryptionBackfillProgress.TAX_RETURNS);
        progress.setLastId(cursor);
        progress.setCompleted(false);

        repository.save(progress);

        Optional<EncryptionBackfillProgress> found = repository.findById(EncryptionBackfillProgress.TAX_RETURNS);
        assertThat(found).isPresent();
        assertThat(found.get().getLastId()).isEqualTo(cursor);
        assertThat(found.get().isCompleted()).isFalse();
    }

    @Test
    void tracksTheTwoTablesIndependently() {
        UUID returnsCursor = UUID.randomUUID();
        UUID submissionsCursor = UUID.randomUUID();

        EncryptionBackfillProgress returns = new EncryptionBackfillProgress();
        returns.setTargetTable(EncryptionBackfillProgress.TAX_RETURNS);
        returns.setLastId(returnsCursor);

        EncryptionBackfillProgress submissions = new EncryptionBackfillProgress();
        submissions.setTargetTable(EncryptionBackfillProgress.TAX_RETURN_SUBMISSIONS);
        submissions.setLastId(submissionsCursor);
        submissions.setCompleted(true);

        repository.saveAll(java.util.List.of(returns, submissions));

        assertThat(repository
                        .findById(EncryptionBackfillProgress.TAX_RETURNS)
                        .orElseThrow()
                        .getLastId())
                .isEqualTo(returnsCursor);
        assertThat(repository
                        .findById(EncryptionBackfillProgress.TAX_RETURN_SUBMISSIONS)
                        .orElseThrow()
                        .isCompleted())
                .isTrue();
    }
}
```

Add the class-level annotation the neighbouring repository tests use (likely `@DataJpaTest` plus an active test profile). If those tests use Testcontainers or a docker-compose Postgres, follow suit — do not switch this one to H2, which would not exercise the `uuid` column type.

- [ ] **Step 3: Run the test to verify it fails**

From `direct-file/backend/`:

```bash
./mvnw test -Dtest=EncryptionBackfillProgressRepositoryTest
```

Expected: FAIL to compile — `EncryptionBackfillProgress` and its repository do not exist.

- [ ] **Step 4: Create the entity**

Create `direct-file/backend/src/main/java/gov/irs/directfile/api/taxreturn/models/EncryptionBackfillProgress.java`:

```java
package gov.irs.directfile.api.taxreturn.models;

import java.util.Date;
import java.util.UUID;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import lombok.Getter;
import lombok.Setter;
import org.hibernate.annotations.UpdateTimestamp;

/**
 * Resume point for the H-1 Phase B ciphertext backfill, one row per target table.
 *
 * <p>Deliberately a persisted cursor rather than an in-memory scroll position: a
 * full-table pass over encrypted data will be interrupted by deploys and restarts, and
 * restarting from the beginning each time would never finish on a large table.
 */
@Entity
@Table(name = "encryption_backfill_progress")
@Getter
@Setter
public class EncryptionBackfillProgress {

    public static final String TAX_RETURNS = "taxreturns";
    public static final String TAX_RETURN_SUBMISSIONS = "taxreturn_submissions";

    @Id
    @Column(name = "target_table", nullable = false)
    private String targetTable;

    /** Highest primary key already re-encrypted. Null means the sweep has not started. */
    @Column(name = "last_id")
    private UUID lastId;

    @Column(name = "completed", nullable = false)
    private boolean completed;

    @UpdateTimestamp
    @Column(name = "updated_at", nullable = false)
    private Date updatedAt;
}
```

- [ ] **Step 5: Create the repository**

Create `direct-file/backend/src/main/java/gov/irs/directfile/api/taxreturn/EncryptionBackfillProgressRepository.java`:

```java
package gov.irs.directfile.api.taxreturn;

import org.springframework.data.repository.CrudRepository;
import org.springframework.stereotype.Repository;

import gov.irs.directfile.api.taxreturn.models.EncryptionBackfillProgress;

@Repository
public interface EncryptionBackfillProgressRepository extends CrudRepository<EncryptionBackfillProgress, String> {}
```

- [ ] **Step 6: Run the test to verify it passes**

```bash
./mvnw test -Dtest=EncryptionBackfillProgressRepositoryTest
```

Expected: PASS.

- [ ] **Step 7: Format and commit**

```bash
./mvnw spotless:apply
git add direct-file/backend/src/main/resources/db/migrations/ direct-file/backend/src/main/java/gov/irs/directfile/api/taxreturn/ direct-file/backend/src/test/java/gov/irs/directfile/api/taxreturn/
git commit -m "feat(backend): persist encryption backfill progress per target table

Resume point for the H-1 Phase B sweep. A persisted lastId cursor rather
than an in-memory scroll position, so the pass survives restarts.

Refs H-1 Phase B."
```

---

## Task 2: Id-only paging queries

**Files:**
- Modify: `direct-file/backend/src/main/java/gov/irs/directfile/api/taxreturn/TaxReturnRepository.java`
- Modify: `direct-file/backend/src/main/java/gov/irs/directfile/api/taxreturn/TaxReturnSubmissionRepository.java`
- Test: `direct-file/backend/src/test/java/gov/irs/directfile/api/taxreturn/TaxReturnRepositoryTest.java` (or the existing repository test for this class)

**Interfaces:**
- Consumes: nothing from earlier tasks.
- Produces:
  - `TaxReturnRepository.findIdsForBackfillAfter(UUID afterId, Limit limit): List<UUID>`
  - `TaxReturnSubmissionRepository.findIdsForBackfillAfter(UUID afterId, Limit limit): List<UUID>`
  - Both return ids strictly greater than `afterId`, ascending.

**Design note — this is the important one in the whole plan.** These queries return **ids, not entities**, and that is deliberate.

Loading a page of entities fires `@PostLoad` → `TaxReturnEntityListener.decryptColumns` for every row *during query materialization*. If any single row's ciphertext is corrupt, or carries a purpose that does not match, `decrypt` throws `EncryptionContextMismatchException` and **the entire page fails to load**. The backfill would then retry that page forever, never advance its cursor, and never complete — a permanent stall caused by one bad row.

Fetching ids first, then loading each entity individually (Task 3), isolates that failure to the row that caused it. The cost is one extra query per batch, which is negligible against the KMS round trips.

- [ ] **Step 1: Write the failing tests**

Add to the existing repository test for `TaxReturnRepository` (find it under `direct-file/backend/src/test/java/gov/irs/directfile/api/taxreturn/`; if none exists, create `TaxReturnRepositoryTest.java` following the annotations used in Task 1's test):

```java
    @Test
    void findIdsForBackfillAfter_returnsAscendingIdsStrictlyGreaterThanCursor() {
        // Persist three tax returns, then page from the lowest id.
        List<UUID> allIds = taxReturnRepository.findIdsForBackfillAfter(
                new UUID(0L, 0L), Limit.of(100));

        assertThat(allIds).isSorted();
        assertThat(allIds).hasSizeGreaterThanOrEqualTo(1);

        UUID first = allIds.get(0);
        List<UUID> afterFirst = taxReturnRepository.findIdsForBackfillAfter(first, Limit.of(100));

        assertThat(afterFirst).doesNotContain(first);
        assertThat(afterFirst).isSorted();
    }

    @Test
    void findIdsForBackfillAfter_respectsTheLimit() {
        List<UUID> page = taxReturnRepository.findIdsForBackfillAfter(new UUID(0L, 0L), Limit.of(1));

        assertThat(page).hasSizeLessThanOrEqualTo(1);
    }
```

The test needs at least two persisted tax returns. Reuse whatever fixture builder the neighbouring tests use rather than constructing `TaxReturn` by hand — it has required columns and a `@ManyToMany` owners relationship that a hand-built instance will trip over.

- [ ] **Step 2: Run the tests to verify they fail**

```bash
./mvnw test -Dtest=TaxReturnRepositoryTest
```

Expected: FAIL to compile — `findIdsForBackfillAfter` does not exist.

- [ ] **Step 3: Add the query to `TaxReturnRepository`**

In `direct-file/backend/src/main/java/gov/irs/directfile/api/taxreturn/TaxReturnRepository.java`, add:

```java
    /**
     * Primary keys for the H-1 Phase B backfill, ascending, strictly greater than
     * {@code afterId}. Pass the all-zero UUID to start from the beginning.
     *
     * <p>Returns ids rather than entities on purpose: loading entities fires @PostLoad,
     * which decrypts every row in the page, so one undecryptable row would fail the whole
     * page and stall the sweep permanently. The backfill loads each row individually.
     */
    @Query("SELECT t.id FROM TaxReturn t WHERE t.id > :afterId ORDER BY t.id ASC")
    List<UUID> findIdsForBackfillAfter(@Param("afterId") UUID afterId, Limit limit);
```

Add `import org.springframework.data.repository.query.Param;` if absent. `Limit` and `List` are already imported.

- [ ] **Step 4: Add the query to `TaxReturnSubmissionRepository`**

In `direct-file/backend/src/main/java/gov/irs/directfile/api/taxreturn/TaxReturnSubmissionRepository.java`, add the same query against the submission entity:

```java
    /**
     * Primary keys for the H-1 Phase B backfill, ascending, strictly greater than
     * {@code afterId}. See TaxReturnRepository.findIdsForBackfillAfter for why this
     * returns ids rather than entities.
     */
    @Query("SELECT s.id FROM TaxReturnSubmission s WHERE s.id > :afterId ORDER BY s.id ASC")
    List<UUID> findIdsForBackfillAfter(@Param("afterId") UUID afterId, Limit limit);
```

Add `import org.springframework.data.domain.Limit;`, `import org.springframework.data.repository.query.Param;`, `import java.util.UUID;`, and `import java.util.List;` as needed. Note this repository's existing queries use `nativeQuery = true` in places — the new one is JPQL, so do **not** copy a `nativeQuery` flag onto it.

- [ ] **Step 5: Run the tests to verify they pass**

```bash
./mvnw test -Dtest=TaxReturnRepositoryTest
```

Expected: PASS.

- [ ] **Step 6: Format and commit**

```bash
./mvnw spotless:apply
git add direct-file/backend/src/
git commit -m "feat(backend): add id-only paging queries for the encryption backfill

Ids rather than entities so one undecryptable row cannot fail a whole page
and stall the sweep. The backfill loads each row individually.

Refs H-1 Phase B."
```

---

## Task 3: Re-encrypt a single row

The core of the backfill, and the smallest piece worth testing on its own.

**Files:**
- Modify: `direct-file/backend/src/main/java/gov/irs/directfile/api/taxreturn/models/TaxReturnEntity.java`
- Create: `direct-file/backend/src/main/java/gov/irs/directfile/api/taxreturn/EncryptionBackfillRowService.java`
- Test: `direct-file/backend/src/test/java/gov/irs/directfile/api/taxreturn/EncryptionBackfillRowServiceTest.java`

**Interfaces:**
- Consumes: the paging queries (Task 2).
- Produces:
  - `TaxReturnEntity.setFacts(Map<String, FactTypeWithItem> facts)` — added to the interface; both implementors already declare it.
  - `EncryptionBackfillRowService.reencryptTaxReturn(UUID id): boolean` — true if re-encrypted, false if the row vanished or could not be read.
  - `EncryptionBackfillRowService.reencryptSubmission(UUID id): boolean` — same contract.
  - `EncryptionBackfillRowService.FAILURE_MARKER` — the stable log marker for a row that could not be migrated.

**Design note — why dirtying one column is enough.** `TaxReturnEntityListener.encryptColumns` re-encrypts *both* `factsCipherText` and `storeCipherText` on every `@PreUpdate`, regardless of which one changed. So dirtying facts alone migrates both columns. That is why the backfill can be generic over `TaxReturnEntity` even though `TaxReturnSubmission` has no store: the interface's default no-op store methods never need to be called.

**Design note — why `REQUIRES_NEW`, and why its own bean.** Each row gets its own transaction so a failure on one row rolls back only that row, and so the cursor advance in Task 4 commits independently of any individual row's fate. Without it, a mid-batch failure would roll back the cursor too and the batch would repeat forever.

That only works if the annotation is honoured, and `@Transactional` is proxy-based: if Task 4's batch loop called these methods on itself, Spring would bypass the proxy entirely and every row would silently join the caller's transaction. Hence a separate bean. This is the same proxy trap that put `CertificateLoader` in its own class during Tranche 1.

- [ ] **Step 1: Add `setFacts` to the entity interface**

In `direct-file/backend/src/main/java/gov/irs/directfile/api/taxreturn/models/TaxReturnEntity.java`, add to the interface:

```java
    /**
     * Sets the decrypted facts and marks the entity dirty, so a subsequent flush triggers
     * @PreUpdate and re-encrypts. This is the hook the H-1 Phase B backfill drives.
     */
    void setFacts(Map<String, FactTypeWithItem> facts);
```

Both `TaxReturn` (`:53`) and `TaxReturnSubmission` already declare a public `setFacts(Map<String, FactTypeWithItem>)`, so this compiles with no change to either class. Verify that is true of `TaxReturnSubmission` before proceeding:

```bash
grep -n "public void setFacts" direct-file/backend/src/main/java/gov/irs/directfile/api/taxreturn/models/TaxReturnSubmission.java
```

If its signature differs, add `@Override` to whichever implementation needs it rather than changing the interface.

- [ ] **Step 2: Write the failing tests**

Create `direct-file/backend/src/test/java/gov/irs/directfile/api/taxreturn/EncryptionBackfillRowServiceTest.java`:

```java
package gov.irs.directfile.api.taxreturn;

import java.util.Optional;
import java.util.UUID;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import gov.irs.directfile.api.taxreturn.models.TaxReturn;
import gov.irs.directfile.models.encryption.EncryptionContextMismatchException;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class EncryptionBackfillRowServiceTest {

    @InjectMocks
    private EncryptionBackfillRowService service;

    @Mock
    private TaxReturnRepository taxReturnRepository;

    @Mock
    private TaxReturnSubmissionRepository taxReturnSubmissionRepository;

    @Test
    void reencryptTaxReturn_dirtiesAndSavesTheRow() {
        UUID id = UUID.randomUUID();
        TaxReturn taxReturn = new TaxReturn();
        taxReturn.setFactsWithoutDirtyingEntity(java.util.Map.of());
        when(taxReturnRepository.findById(id)).thenReturn(Optional.of(taxReturn));

        boolean result = service.reencryptTaxReturn(id);

        assertThat(result).isTrue();
        verify(taxReturnRepository).save(taxReturn);
    }

    @Test
    void reencryptTaxReturn_returnsFalseWhenTheRowIsGone() {
        UUID id = UUID.randomUUID();
        when(taxReturnRepository.findById(id)).thenReturn(Optional.empty());

        boolean result = service.reencryptTaxReturn(id);

        assertThat(result).isFalse();
        verify(taxReturnRepository, never()).save(any());
    }

    @Test
    void reencryptTaxReturn_returnsFalseWhenTheRowCannotBeDecrypted() {
        UUID id = UUID.randomUUID();
        // @PostLoad decryption failure surfaces from findById.
        when(taxReturnRepository.findById(id))
                .thenThrow(new EncryptionContextMismatchException("purpose mismatch"));

        boolean result = service.reencryptTaxReturn(id);

        assertThat(result).isFalse();
        verify(taxReturnRepository, never()).save(any());
    }
}
```

Check `EncryptionContextMismatchException`'s constructor signature before running — Phase A created it, and if it takes something other than a single `String`, match what it actually declares.

- [ ] **Step 3: Run the tests to verify they fail**

```bash
./mvnw test -Dtest=EncryptionBackfillRowServiceTest
```

Expected: FAIL to compile — `EncryptionBackfillRowService` does not exist.

- [ ] **Step 4: Implement the service**

Create `direct-file/backend/src/main/java/gov/irs/directfile/api/taxreturn/EncryptionBackfillRowService.java`:

```java
package gov.irs.directfile.api.taxreturn;

import java.util.Optional;
import java.util.UUID;
import java.util.function.Function;

import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;

import gov.irs.directfile.api.taxreturn.models.TaxReturn;
import gov.irs.directfile.api.taxreturn.models.TaxReturnEntity;
import gov.irs.directfile.api.taxreturn.models.TaxReturnSubmission;

/**
 * H-1 Phase B: re-encrypts existing ciphertext so it carries a bound encryption purpose.
 *
 * <p>Contains no cryptographic code. Loading a row decrypts it via @PostLoad; dirtying it
 * and saving re-encrypts it via @PreUpdate using whatever context schema the listener
 * implements at the time. This class only drives that mechanism, one row at a time.
 *
 * <p>Deliberately a separate bean from EncryptionBackfillService: @Transactional is
 * proxy-based, so calling these methods from the batch loop on the same bean would bypass
 * REQUIRES_NEW and give every row the caller's transaction.
 */
@Service
@Slf4j
public class EncryptionBackfillRowService {

    /** Stable marker for rows the backfill could not migrate. Operators alert on this. */
    public static final String FAILURE_MARKER = "ENCRYPTION_BACKFILL_ROW_FAILED";

    private final TaxReturnRepository taxReturnRepository;
    private final TaxReturnSubmissionRepository taxReturnSubmissionRepository;

    public EncryptionBackfillRowService(
            TaxReturnRepository taxReturnRepository, TaxReturnSubmissionRepository taxReturnSubmissionRepository) {
        this.taxReturnRepository = taxReturnRepository;
        this.taxReturnSubmissionRepository = taxReturnSubmissionRepository;
    }

    @Transactional(propagation = Propagation.REQUIRES_NEW)
    public boolean reencryptTaxReturn(UUID id) {
        return reencrypt("taxreturns", id, taxReturnRepository::findById, taxReturnRepository::save);
    }

    @Transactional(propagation = Propagation.REQUIRES_NEW)
    public boolean reencryptSubmission(UUID id) {
        return reencrypt(
                "taxreturn_submissions",
                id,
                taxReturnSubmissionRepository::findById,
                taxReturnSubmissionRepository::save);
    }

    /**
     * Loads one row, dirties it, and saves it.
     *
     * <p>Dirtying facts alone is sufficient for both tables: encryptColumns re-encrypts
     * every ciphertext column on any @PreUpdate, not only the one that changed. That is
     * also why this works unchanged for TaxReturnSubmission, which has no store column.
     *
     * <p>Failures are swallowed and reported rather than propagated. A row that cannot be
     * decrypted must not stall the sweep — the caller advances past it, and the marker is
     * what tells an operator to go look.
     */
    private <T extends TaxReturnEntity> boolean reencrypt(
            String table, UUID id, Function<UUID, Optional<T>> find, Function<T, T> save) {
        try {
            Optional<T> found = find.apply(id);
            if (found.isEmpty()) {
                // Deleted between the id query and now. Nothing to migrate.
                return false;
            }
            T entity = found.get();
            entity.setFacts(entity.getFacts());
            save.apply(entity);
            return true;
        } catch (Exception e) {
            log.error(
                    "{}: table={}, id={}, {}: {}",
                    FAILURE_MARKER,
                    table,
                    id,
                    e.getClass().getName(),
                    e.getMessage());
            return false;
        }
    }
}
```

Remove the unused `TaxReturn` / `TaxReturnSubmission` imports if the compiler flags them — the generic signature may not need them.

- [ ] **Step 5: Run the tests to verify they pass**

```bash
./mvnw test -Dtest=EncryptionBackfillRowServiceTest
```

Expected: PASS.

- [ ] **Step 6: Format and commit**

```bash
./mvnw spotless:apply
git add direct-file/backend/src/
git commit -m "feat(backend): re-encrypt a single row for the H-1 Phase B backfill

Drives the existing @PostLoad/@PreUpdate mechanism row by row in its own
transaction. Dirtying facts is enough for both tables because encryptColumns
rewrites every ciphertext column on any update.

Row failures are reported and swallowed so one bad row cannot stall the sweep.

Refs H-1 Phase B."
```

---

## Task 4: Process one batch and advance the cursor

**Files:**
- Create: `direct-file/backend/src/main/java/gov/irs/directfile/api/taxreturn/EncryptionBackfillService.java`
- Test: `direct-file/backend/src/test/java/gov/irs/directfile/api/taxreturn/EncryptionBackfillServiceTest.java`

**Interfaces:**
- Consumes: `EncryptionBackfillRowService.reencryptTaxReturn` / `.reencryptSubmission` (Task 3), the paging queries (Task 2), `EncryptionBackfillProgressRepository` (Task 1).
- Produces:
  - `record BatchResult(int attempted, int succeeded, boolean complete)` — nested in `EncryptionBackfillService`.
  - `EncryptionBackfillService.processNextBatch(String targetTable, int batchSize): BatchResult`.

**Design note.** The cursor advances to the last id in the page **whether or not each row succeeded**. This is the deliberate choice that keeps the sweep monotone: a row that cannot be decrypted is logged under `ENCRYPTION_BACKFILL_ROW_FAILED` and skipped, rather than retried forever. Those rows are exactly the population Phase C's gate will still see, which is the correct place for them to surface.

- [ ] **Step 1: Write the failing tests**

Add to `EncryptionBackfillServiceTest`:

```java
    private static final UUID ZERO = new UUID(0L, 0L);

    // The batch service under test, with the row service mocked out.
    // @InjectMocks wires rowService, the two repositories, and progressRepository.
    @Mock
    private EncryptionBackfillRowService rowService;

    @Test
    void processNextBatch_startsFromZeroWhenNoCursorExists() {
        when(progressRepository.findById(EncryptionBackfillProgress.TAX_RETURNS)).thenReturn(Optional.empty());
        when(taxReturnRepository.findIdsForBackfillAfter(eq(ZERO), any())).thenReturn(List.of());

        EncryptionBackfillService.BatchResult result =
                service.processNextBatch(EncryptionBackfillProgress.TAX_RETURNS, 10);

        assertThat(result.complete()).isTrue();
        assertThat(result.attempted()).isZero();
    }

    @Test
    void processNextBatch_advancesTheCursorToTheLastIdInThePage() {
        UUID a = new UUID(0L, 1L);
        UUID b = new UUID(0L, 2L);
        when(progressRepository.findById(EncryptionBackfillProgress.TAX_RETURNS)).thenReturn(Optional.empty());
        when(taxReturnRepository.findIdsForBackfillAfter(eq(ZERO), any())).thenReturn(List.of(a, b));
        when(rowService.reencryptTaxReturn(any())).thenReturn(true);

        EncryptionBackfillService.BatchResult result =
                service.processNextBatch(EncryptionBackfillProgress.TAX_RETURNS, 10);

        assertThat(result.attempted()).isEqualTo(2);
        assertThat(result.complete()).isFalse();

        ArgumentCaptor<EncryptionBackfillProgress> saved = ArgumentCaptor.forClass(EncryptionBackfillProgress.class);
        verify(progressRepository).save(saved.capture());
        assertThat(saved.getValue().getLastId()).isEqualTo(b);
        assertThat(saved.getValue().isCompleted()).isFalse();
    }

    @Test
    void processNextBatch_advancesPastRowsThatFail() {
        UUID a = new UUID(0L, 1L);
        when(progressRepository.findById(EncryptionBackfillProgress.TAX_RETURNS)).thenReturn(Optional.empty());
        when(taxReturnRepository.findIdsForBackfillAfter(eq(ZERO), any())).thenReturn(List.of(a));
        when(rowService.reencryptTaxReturn(a)).thenReturn(false);

        EncryptionBackfillService.BatchResult result =
                service.processNextBatch(EncryptionBackfillProgress.TAX_RETURNS, 10);

        assertThat(result.attempted()).isEqualTo(1);
        assertThat(result.succeeded()).isZero();

        // The cursor still moved: a row that cannot be migrated must not stall the sweep.
        ArgumentCaptor<EncryptionBackfillProgress> saved = ArgumentCaptor.forClass(EncryptionBackfillProgress.class);
        verify(progressRepository).save(saved.capture());
        assertThat(saved.getValue().getLastId()).isEqualTo(a);
    }

    @Test
    void processNextBatch_marksCompleteWhenAPageComesBackEmpty() {
        EncryptionBackfillProgress existing = new EncryptionBackfillProgress();
        existing.setTargetTable(EncryptionBackfillProgress.TAX_RETURNS);
        existing.setLastId(new UUID(0L, 5L));
        when(progressRepository.findById(EncryptionBackfillProgress.TAX_RETURNS)).thenReturn(Optional.of(existing));
        when(taxReturnRepository.findIdsForBackfillAfter(eq(existing.getLastId()), any()))
                .thenReturn(List.of());

        EncryptionBackfillService.BatchResult result =
                service.processNextBatch(EncryptionBackfillProgress.TAX_RETURNS, 10);

        assertThat(result.complete()).isTrue();

        ArgumentCaptor<EncryptionBackfillProgress> saved = ArgumentCaptor.forClass(EncryptionBackfillProgress.class);
        verify(progressRepository).save(saved.capture());
        assertThat(saved.getValue().isCompleted()).isTrue();
    }

    @Test
    void processNextBatch_returnsCompleteWithoutWorkWhenAlreadyCompleted() {
        EncryptionBackfillProgress done = new EncryptionBackfillProgress();
        done.setTargetTable(EncryptionBackfillProgress.TAX_RETURNS);
        done.setCompleted(true);
        when(progressRepository.findById(EncryptionBackfillProgress.TAX_RETURNS)).thenReturn(Optional.of(done));

        EncryptionBackfillService.BatchResult result =
                service.processNextBatch(EncryptionBackfillProgress.TAX_RETURNS, 10);

        assertThat(result.complete()).isTrue();
        verify(taxReturnRepository, never()).findIdsForBackfillAfter(any(), any());
    }
```

Add these imports: `org.mockito.ArgumentCaptor`, `java.util.List`, `gov.irs.directfile.api.taxreturn.models.EncryptionBackfillProgress`, and `static org.mockito.ArgumentMatchers.eq`.

- [ ] **Step 2: Run the tests to verify they fail**

```bash
./mvnw test -Dtest=EncryptionBackfillServiceTest
```

Expected: FAIL to compile — `processNextBatch` and `BatchResult` do not exist.

- [ ] **Step 3: Implement `processNextBatch`**

Create `direct-file/backend/src/main/java/gov/irs/directfile/api/taxreturn/EncryptionBackfillService.java`:

```java
package gov.irs.directfile.api.taxreturn;

import java.util.List;
import java.util.UUID;

import lombok.extern.slf4j.Slf4j;
import org.springframework.data.domain.Limit;
import org.springframework.stereotype.Service;

import gov.irs.directfile.api.taxreturn.models.EncryptionBackfillProgress;

/** Drives the H-1 Phase B sweep one batch at a time, tracking a resumable cursor. */
@Service
@Slf4j
public class EncryptionBackfillService {

    private final EncryptionBackfillRowService rowService;
    private final TaxReturnRepository taxReturnRepository;
    private final TaxReturnSubmissionRepository taxReturnSubmissionRepository;
    private final EncryptionBackfillProgressRepository progressRepository;

    public EncryptionBackfillService(
            EncryptionBackfillRowService rowService,
            TaxReturnRepository taxReturnRepository,
            TaxReturnSubmissionRepository taxReturnSubmissionRepository,
            EncryptionBackfillProgressRepository progressRepository) {
        this.rowService = rowService;
        this.taxReturnRepository = taxReturnRepository;
        this.taxReturnSubmissionRepository = taxReturnSubmissionRepository;
        this.progressRepository = progressRepository;
    }
```

then the batch logic inside that class:

```java
    /** Outcome of one batch. {@code complete} means this table has no rows left to sweep. */
    public record BatchResult(int attempted, int succeeded, boolean complete) {
        static BatchResult finished() {
            return new BatchResult(0, 0, true);
        }
    }

    private static final UUID FIRST_CURSOR = new UUID(0L, 0L);

    /**
     * Processes one batch for {@code targetTable} and advances the persisted cursor.
     *
     * <p>Not transactional as a whole: each row commits in its own transaction
     * (REQUIRES_NEW), and the cursor advance commits separately. A crash mid-batch
     * therefore re-processes at most one batch, which is harmless — re-encrypting an
     * already-migrated row is a no-op in effect.
     */
    public BatchResult processNextBatch(String targetTable, int batchSize) {
        EncryptionBackfillProgress progress = progressRepository
                .findById(targetTable)
                .orElseGet(() -> {
                    EncryptionBackfillProgress fresh = new EncryptionBackfillProgress();
                    fresh.setTargetTable(targetTable);
                    return fresh;
                });

        if (progress.isCompleted()) {
            return BatchResult.finished();
        }

        UUID cursor = progress.getLastId() == null ? FIRST_CURSOR : progress.getLastId();
        List<UUID> ids = idsAfter(targetTable, cursor, Limit.of(batchSize));

        if (ids.isEmpty()) {
            progress.setCompleted(true);
            progressRepository.save(progress);
            log.info("Encryption backfill complete for table={}", targetTable);
            return BatchResult.finished();
        }

        int succeeded = 0;
        for (UUID id : ids) {
            // Through the injected bean, never this: REQUIRES_NEW only applies across
            // the proxy boundary.
            boolean ok = EncryptionBackfillProgress.TAX_RETURNS.equals(targetTable)
                    ? rowService.reencryptTaxReturn(id)
                    : rowService.reencryptSubmission(id);
            if (ok) {
                succeeded++;
            }
        }

        // Advance past every id in the page, including any that failed. A row that cannot
        // be migrated is reported under FAILURE_MARKER and left behind rather than retried
        // forever; leaving it would stall the sweep permanently.
        progress.setLastId(ids.get(ids.size() - 1));
        progressRepository.save(progress);

        return new BatchResult(ids.size(), succeeded, false);
    }

    private List<UUID> idsAfter(String targetTable, UUID cursor, Limit limit) {
        if (EncryptionBackfillProgress.TAX_RETURNS.equals(targetTable)) {
            return taxReturnRepository.findIdsForBackfillAfter(cursor, limit);
        }
        if (EncryptionBackfillProgress.TAX_RETURN_SUBMISSIONS.equals(targetTable)) {
            return taxReturnSubmissionRepository.findIdsForBackfillAfter(cursor, limit);
        }
        throw new IllegalArgumentException("Unknown backfill target table: " + targetTable);
    }
```

Close the class with a `}`. The imports are already in the skeleton above.

Note the row calls go through the injected `EncryptionBackfillRowService`, never through `this`. That is what makes `REQUIRES_NEW` actually apply — see Task 3's design note.

- [ ] **Step 4: Run the tests to verify they pass**

```bash
./mvnw test -Dtest=EncryptionBackfillServiceTest
```

Expected: PASS.

- [ ] **Step 5: Format and commit**

```bash
./mvnw spotless:apply
git add direct-file/backend/src/
git commit -m "feat(backend): process one backfill batch and advance the cursor

The cursor advances past failed rows deliberately: a row that cannot be
decrypted is reported and skipped rather than retried forever, and surfaces
in Phase C's gate where it belongs.

Refs H-1 Phase B."
```

---

## Task 5: Schedule the sweep behind an off-by-default flag

**Files:**
- Create: `direct-file/backend/src/main/java/gov/irs/directfile/api/taxreturn/EncryptionBackfillWorker.java`
- Modify: `direct-file/backend/src/main/resources/application.yaml`
- Modify: `direct-file/backend/README.md`
- Test: `direct-file/backend/src/test/java/gov/irs/directfile/api/taxreturn/EncryptionBackfillWorkerTest.java`

**Interfaces:**
- Consumes: `EncryptionBackfillService.processNextBatch` (Task 4), `EncryptionContextProperties.isEnforcing()` (Phase A).
- Produces: `EncryptionBackfillWorker.tick()` — one scheduled pass; sweeps `taxreturns` first, then `taxreturn_submissions`, then idles.

**Design note — the warn-mode guard.** Under `enforce`, `decrypt` rejects untagged ciphertext, which is precisely the population this backfill exists to migrate. Enabling the worker under `enforce` would make every row fail, log a flood of `ENCRYPTION_BACKFILL_ROW_FAILED`, and advance the cursor past rows it never migrated — silently "completing" a sweep that did nothing. The guard refuses to start in that combination.

- [ ] **Step 1: Confirm the two owner approvals before enabling anywhere**

Do not skip this. From spec §6:

- Item 4 — the milestone owner has approved the loss of `id` attribution on backfilled rows.
- Item 5 — nothing outside this repository reads `taxreturns.updated_at`, or the owner accepts that a full-table pass bumps it.

Record both in the PR description with who approved and when. The code in this task ships disabled by default, so merging it is safe without the approvals — **enabling it in any environment holding real data is not.**

- [ ] **Step 2: Record the third-table check**

Spec §6 item 2 asks whether `generateAuthorizationToken` is reachable in deployed environments. Confirm:

```bash
grep -rn "generateAuthorizationToken" direct-file/ --include="*.java" | grep -v "/test/"
```

If the only hits are the state-api service and its interface — with no controller route — the state-api ciphertext population is empty and this plan's two tables are the whole job. If a deployed route exists, note it in the PR: Phase B grows a third table and needs a follow-up task.

- [ ] **Step 3: Write the failing tests**

Create `direct-file/backend/src/test/java/gov/irs/directfile/api/taxreturn/EncryptionBackfillWorkerTest.java`:

```java
package gov.irs.directfile.api.taxreturn;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import gov.irs.directfile.api.taxreturn.models.EncryptionBackfillProgress;
import gov.irs.directfile.models.autoconfigure.EncryptionContextProperties;

import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class EncryptionBackfillWorkerTest {

    @Mock
    private EncryptionBackfillService service;

    private EncryptionContextProperties warnMode() {
        EncryptionContextProperties properties = new EncryptionContextProperties();
        properties.setContextVerification(EncryptionContextProperties.WARN);
        return properties;
    }

    private EncryptionContextProperties enforceMode() {
        EncryptionContextProperties properties = new EncryptionContextProperties();
        properties.setContextVerification(EncryptionContextProperties.ENFORCE);
        return properties;
    }

    @Test
    void refusesToStartUnderEnforceMode() {
        EncryptionBackfillWorker worker = new EncryptionBackfillWorker(service, enforceMode(), true, 100);

        assertThatThrownBy(worker::verifyRunnable)
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("warn");
    }

    @Test
    void startsUnderWarnMode() {
        EncryptionBackfillWorker worker = new EncryptionBackfillWorker(service, warnMode(), true, 100);

        worker.verifyRunnable();
    }

    @Test
    void doesNothingWhenDisabled() {
        EncryptionBackfillWorker worker = new EncryptionBackfillWorker(service, warnMode(), false, 100);

        worker.tick();

        verify(service, never()).processNextBatch(any(), anyInt());
    }

    @Test
    void sweepsTaxReturnsBeforeSubmissions() {
        when(service.processNextBatch(eq(EncryptionBackfillProgress.TAX_RETURNS), anyInt()))
                .thenReturn(new EncryptionBackfillService.BatchResult(10, 10, false));
        EncryptionBackfillWorker worker = new EncryptionBackfillWorker(service, warnMode(), true, 100);

        worker.tick();

        verify(service).processNextBatch(EncryptionBackfillProgress.TAX_RETURNS, 100);
        verify(service, never()).processNextBatch(eq(EncryptionBackfillProgress.TAX_RETURN_SUBMISSIONS), anyInt());
    }

    @Test
    void movesToSubmissionsOnceTaxReturnsAreComplete() {
        when(service.processNextBatch(eq(EncryptionBackfillProgress.TAX_RETURNS), anyInt()))
                .thenReturn(new EncryptionBackfillService.BatchResult(0, 0, true));
        when(service.processNextBatch(eq(EncryptionBackfillProgress.TAX_RETURN_SUBMISSIONS), anyInt()))
                .thenReturn(new EncryptionBackfillService.BatchResult(5, 5, false));
        EncryptionBackfillWorker worker = new EncryptionBackfillWorker(service, warnMode(), true, 100);

        worker.tick();

        verify(service).processNextBatch(EncryptionBackfillProgress.TAX_RETURN_SUBMISSIONS, 100);
    }
}
```

Add `import static org.mockito.ArgumentMatchers.any;`.

- [ ] **Step 4: Run the tests to verify they fail**

```bash
./mvnw test -Dtest=EncryptionBackfillWorkerTest
```

Expected: FAIL to compile — `EncryptionBackfillWorker` does not exist.

- [ ] **Step 5: Implement the worker**

Create `direct-file/backend/src/main/java/gov/irs/directfile/api/taxreturn/EncryptionBackfillWorker.java`:

```java
package gov.irs.directfile.api.taxreturn;

import jakarta.annotation.PostConstruct;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;

import gov.irs.directfile.api.taxreturn.models.EncryptionBackfillProgress;
import gov.irs.directfile.models.autoconfigure.EncryptionContextProperties;

/**
 * Drives the H-1 Phase B backfill on a schedule.
 *
 * <p>Off by default. One tick processes one batch and returns, so the sweep is stoppable
 * at any point — disable the flag, and it resumes from its persisted cursor when
 * re-enabled.
 */
@Component
@Slf4j
public class EncryptionBackfillWorker {

    /** Stable marker for progress lines. Operators watch this to track the sweep. */
    private static final String PROGRESS_MARKER = "ENCRYPTION_BACKFILL_PROGRESS";

    private final EncryptionBackfillService service;
    private final EncryptionContextProperties encryptionContextProperties;
    private final boolean enabled;
    private final int batchSize;

    public EncryptionBackfillWorker(
            EncryptionBackfillService service,
            EncryptionContextProperties encryptionContextProperties,
            @Value("${direct-file.encryption.backfill.enabled:false}") boolean enabled,
            @Value("${direct-file.encryption.backfill.batch-size:100}") int batchSize) {
        this.service = service;
        this.encryptionContextProperties = encryptionContextProperties;
        this.enabled = enabled;
        this.batchSize = batchSize;
    }

    /**
     * Refuses to run the backfill under enforce mode.
     *
     * <p>Under enforce, decrypt rejects untagged ciphertext — the exact population this
     * backfill exists to migrate. Every row would fail, and the cursor would advance past
     * rows that were never migrated, "completing" a sweep that did nothing.
     */
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

    @Scheduled(
            fixedDelayString = "${direct-file.encryption.backfill.fixed-delay-millis:5000}",
            initialDelay = 30000)
    public void tick() {
        if (!enabled) {
            return;
        }

        // Tax returns first, then submissions. One table at a time keeps the load
        // predictable and makes the progress log unambiguous.
        EncryptionBackfillService.BatchResult returns =
                service.processNextBatch(EncryptionBackfillProgress.TAX_RETURNS, batchSize);
        if (!returns.complete()) {
            logProgress(EncryptionBackfillProgress.TAX_RETURNS, returns);
            return;
        }

        EncryptionBackfillService.BatchResult submissions =
                service.processNextBatch(EncryptionBackfillProgress.TAX_RETURN_SUBMISSIONS, batchSize);
        if (!submissions.complete()) {
            logProgress(EncryptionBackfillProgress.TAX_RETURN_SUBMISSIONS, submissions);
        }
    }

    private void logProgress(String table, EncryptionBackfillService.BatchResult result) {
        log.info(
                "{}: table={}, attempted={}, succeeded={}",
                PROGRESS_MARKER,
                table,
                result.attempted(),
                result.succeeded());
    }
}
```

`@Scheduled` needs `@EnableScheduling` active. `ReminderEmailHandler` already uses `@Scheduled` in this application, so it is enabled — confirm with:

```bash
grep -rn "@EnableScheduling" direct-file/backend/src/main --include="*.java"
```

- [ ] **Step 6: Add the configuration**

In `direct-file/backend/src/main/resources/application.yaml`, under the existing `direct-file.encryption` block (create the `backfill` child):

```yaml
direct-file:
  encryption:
    # H-1 Phase B. Off by default; enabling requires context-verification=warn and the
    # two owner approvals in docs/security/2026-08-25_h1-encryption-context-spec.md §6.
    backfill:
      enabled: false
      batch-size: 100
      fixed-delay-millis: 5000
```

Match the file's existing indentation and merge into the `direct-file:` key already present rather than adding a second top-level `direct-file:` block, which YAML would treat as a duplicate key.

- [ ] **Step 7: Run the tests to verify they pass**

```bash
./mvnw test -Dtest=EncryptionBackfillWorkerTest
```

Expected: PASS.

- [ ] **Step 8: Document the runbook**

Add to `direct-file/backend/README.md`, near the existing encryption-verification section that Phase A added:

```markdown
#### H-1 Phase B — ciphertext backfill

Re-encrypts existing `taxreturns` and `taxreturn_submissions` rows so their ciphertext
carries a bound encryption purpose. Off by default.

| Property | Default | Meaning |
|---|---|---|
| `direct-file.encryption.backfill.enabled` | `false` | Master switch |
| `direct-file.encryption.backfill.batch-size` | `100` | Rows per tick |
| `direct-file.encryption.backfill.fixed-delay-millis` | `5000` | Delay between ticks |

**Prerequisites.** `direct-file.encryption.context-verification` must be `warn` — the
application refuses to start with the backfill enabled under `enforce`, because untagged
ciphertext cannot be read in that mode. The two owner approvals in
`docs/security/2026-08-25_h1-encryption-context-spec.md` §6 (items 4 and 5) must be
recorded before enabling against real data.

**Running it.** Set `enabled: true` and watch `ENCRYPTION_BACKFILL_PROGRESS`. The sweep
does tax returns first, then submissions, and stops on its own when both are complete.
It is safe to disable at any point; it resumes from its persisted cursor.

**Watch for `ENCRYPTION_BACKFILL_ROW_FAILED`.** Rows that could not be decrypted are
skipped, not retried — the sweep advances past them deliberately so one bad row cannot
stall it. Any occurrence needs investigating before Phase C, because those rows will
still be untagged when the gate is measured.

**Restarting a completed sweep.** Delete the relevant row from
`encryption_backfill_progress`. There is no admin endpoint by design.

**This does not close H-1.** Phase C — flipping `context-verification` to `enforce` —
is gated on the `ENCRYPTION_CONTEXT_LEGACY` marker reading zero across an observation
window that has not yet been decided.
```

- [ ] **Step 9: Run the whole backend suite**

```bash
./mvnw test
```

Expected: PASS. The worker is disabled by default, so no existing test should change behavior. If a Spring context test fails on the new `@Component`, it is most likely the `@PostConstruct` guard — confirm that test is not setting `enforce` and `backfill.enabled=true` together.

- [ ] **Step 10: Format and commit**

```bash
./mvnw spotless:apply
git add direct-file/backend/
git commit -m "feat(backend): schedule the H-1 Phase B backfill behind an off-by-default flag

One batch per tick, stoppable and resumable from a persisted cursor. Refuses
to start under enforce mode, where untagged ciphertext cannot be read and the
sweep would silently skip every row it exists to migrate.

Refs H-1 Phase B."
```

---

## Verification

- [ ] **Full backend suite**

```bash
cd /Users/thomaswarn/repo/direct-file/direct-file/backend
./mvnw clean test
```

Expected: PASS, zero failures.

- [ ] **Prove the sweep actually migrates ciphertext**

This is the check that matters, and unit tests with mocked repositories cannot make it. Against a local Postgres with the backend running and `backfill.enabled=true`:

1. Seed at least two tax returns and one submission.
2. Confirm reads of them emit `ENCRYPTION_CONTEXT_LEGACY` (they were written before the purpose schema, or write them with the marker-emitting path).
3. Let the sweep run to completion — watch for `ENCRYPTION_BACKFILL_PROGRESS` then silence.
4. Restart the application and read the same rows again.
5. **Expected: no `ENCRYPTION_CONTEXT_LEGACY` for those rows.** That is the whole point of Phase B; if the marker still appears, the sweep did not do its job.

- [ ] **Prove resumability**

Disable the flag mid-sweep, restart, re-enable. The sweep must continue from its cursor rather than restarting — check `encryption_backfill_progress.last_id` advanced monotonically and no row count reset.

- [ ] **Prove the enforce-mode guard fires**

Set `context-verification=enforce` and `backfill.enabled=true`. The application must refuse to start with a message naming `warn`. This is the guard that prevents a silent no-op sweep.

- [ ] **Confirm no unintended writes**

```bash
git diff --stat main
```

Expected: changes only under `direct-file/backend/`. No changes to `libs/data-models` (Phase A settled the crypto layer), no changes under `df-client/`, no changes to `state-api`.

## Handback to the milestone owner

Items this plan cannot perform:

1. **Approve the loss of `id` attribution on backfilled rows** (spec §6 item 4) — required before enabling against real data.
2. **Confirm nothing outside this repository reads `taxreturns.updated_at`** (spec §6 item 5) — a full-table pass bumps every row via `@UpdateTimestamp`.
3. **Schedule the sweep against production load.** Batch size and tick delay are configuration; what they should be depends on row count and the KMS request budget. The `CachingCryptoMaterialsManager` already in place (`EncryptionAutoConfiguration:79`) caches data keys, so KMS calls are far below one per row — but the ceiling is set by `messageUseLimit` and `maxAge`, which are worth reading before choosing a batch size.
4. **Investigate every `ENCRYPTION_BACKFILL_ROW_FAILED`.** Those rows stay untagged and will hold Phase C's gate open. They are skipped by design, not ignored by accident.
5. **Decide the Phase C observation window** (spec §6 item 3) — still outstanding, and it is what Phase C waits on once this sweep completes.
6. **Note that H-1 remains "underway", not "closed".** Phase B removes the legacy population; Phase C closes the finding.
