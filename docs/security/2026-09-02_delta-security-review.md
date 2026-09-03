# Direct File — Delta Security Review

**Date:** 2026-09-02
**Scope:** Everything changed between `e0d5c84` (the snapshot the 2026-08-22 review covered) and `b46cc4d` — 145 files, +4,604/−455 lines, spanning `backend` (49 files), `df-client` (50), `state-api` (29), and `libs` (14). Roughly 80 of those are main-source files; the rest are tests, resources, and CI configuration.
**Method:** Manual source review of the changed main-source files, with the fact graph, entity listeners, and repository queries read where the changed code depends on them.

## Scope caveat — read this first

**This reviews remediation work, and most of it was written in this same series of sessions.** Fresh eyes on unreviewed security-sensitive code is worth having, but self-review does not substitute for an independent pass, and the findings below are weighted toward things that are checkable against a specification (does purpose verification close the scenario H-1 described?) rather than things that require not sharing the author's assumptions.

Two of the four findings are in code the original review's remediation introduced rather than in pre-existing code. That is the expected shape: the highest-risk code in this delta is the code written to handle ciphertext and trust boundaries.

## Summary

| ID | Severity | Finding |
| --- | --- | --- |
| D-1 | High | Encryption context binds the writing actor, not the record — cross-row substitution within a purpose still decrypts cleanly |
| D-2 | Medium | The backfill's `completed` flag cannot distinguish a clean sweep from one where every row failed |
| D-3 | Low | Advisory-lock keyspace collision between the backfill sweep and per-return submission locks |
| D-4 | Low | No clickjacking protection anywhere — CSP is meta-delivered and `frame-ancestors` is unexpressible |
| D-5 | Info | `lastFour` returns a malformed short TIN unchanged |

---

## D-1 — Encryption context binds the writer, not the record

**Severity:** High
**Files:**
- `direct-file/libs/data-models/src/main/java/gov/irs/directfile/models/encryption/EncryptionContexts.java`
- `direct-file/libs/data-models/src/main/java/gov/irs/directfile/models/encryption/DataEncryptDecrypt.java:85-108`
- `direct-file/backend/src/main/java/gov/irs/directfile/api/taxreturn/models/TaxReturnEntityListener.java:44-60`

**The register records H-1 as closed. Half of it is.**

The original finding described two substitution scenarios:

> The `id=<externalId>` binding — the control that would stop one taxpayer's `facts_cipher_text` from being decrypted as another's — does nothing. A row-swap reached by any means […] yields a clean decrypt and taxpayer A being served taxpayer B's return. The same holds across services: a state-API authorization token blob and a tax-return facts blob are mutually substitutable.

The remediation added a `purpose` field to the encryption context and verifies it on decrypt. That closes the second scenario completely — a state-API token blob is `purpose=…` something else and will not decrypt as tax-return facts.

It does not touch the first. Every taxpayer's facts are written with the same context:

```java
context.put(PURPOSE_KEY, purpose.wireValue());   // TAX_RETURN_FACTS for every return
context.put(SYSTEM_KEY, SYSTEM_VALUE);           // constant
if (actorId != null && !actorId.isBlank()) {
    context.put(ID_KEY, actorId);                // who wrote it — never verified
}
```

Taxpayer A's and taxpayer B's `facts_cipher_text` are both bound to `purpose=TAX_RETURN_FACTS`, so swapping the rows still produces a clean decrypt and A is served B's return. That is the scenario the original finding led with, and it is fully open.

**The `id` field cannot be made to help, by construction.** `TaxReturnEntityListener.encryptColumns` sets it from `identitySupplier.get().externalId()` — the principal performing the *write*. `EncryptionContexts`' own documentation is explicit and correct about why that can never be verified:

> `id` records who wrote the blob, which is useful for KMS CloudTrail attribution and cannot be checked at read time, because the reader is not necessarily the writer and, at `@PostLoad`, there may be no authenticated principal at all.

Both halves of that are true. The problem is the choice of what to bind, not the decision not to verify it.

**Recommendation.** Bind the record's own identity rather than the actor's. `TaxReturnEntity` already exposes `getId()`, and at `@PostLoad` the entity being hydrated is exactly the row whose ciphertext is being decrypted — so `record=<taxReturn.getId()>` is available on both sides and is verifiable, which `actor=<externalId>` never will be. Keep the actor field for CloudTrail attribution; add the record field for verification.

This is a third context schema and needs its own backfill, so it is not a small change — Phase B's machinery exists and can be re-driven, and D-2 should be fixed first so that sweep's completion is trustworthy.

**Interim mitigation.** Until the binding changes, the control that would detect a row swap is `TaxReturnRepository`'s scoping (`findByIdAndUserId`, joins through `t.owners`), which the original review examined and found sound. That is a single layer, and defeating it was the premise of the H-1 scenario.

---

## D-2 — The backfill cannot report whether it actually migrated anything

**Severity:** Medium
**Files:**
- `direct-file/backend/src/main/java/gov/irs/directfile/api/taxreturn/EncryptionBackfillService.java:66-91`
- `direct-file/backend/src/main/java/gov/irs/directfile/api/taxreturn/models/EncryptionBackfillProgress.java`

The sweep advances its cursor past rows that failed, which is a deliberate and correct choice — a row that cannot be decrypted must not stall the migration forever. The comment says so plainly. The problem is what gets recorded.

`EncryptionBackfillProgress` persists exactly four fields: `targetTable`, `lastId`, `completed`, `updatedAt`. There is no attempted count, no success count, and no failure count. `completed` is set when the id query returns an empty page:

```java
if (ids.isEmpty()) {
    progress.setCompleted(true);
    progressRepository.save(progress);
    log.info("Encryption backfill complete for table={}", targetTable);
    return BatchResult.finished();
}
```

So `completed = true` means **every row was attempted**, not that any row was migrated. A sweep in which all rows failed is durably indistinguishable from a clean one. `BatchResult` does carry `attempted` and `succeeded`, but only to the progress log line — nothing persists them.

**Why this matters more than a missing metric.** Phase C flips `direct-file.encryption.context-verification` to `enforce`, and under enforce `DataEncryptDecrypt.decrypt` *rejects* untagged ciphertext rather than reporting it. Any row the sweep failed to migrate becomes undecryptable at that moment — that taxpayer cannot load their return. The gate for making that change is documented as a log query:

> `/** Stable log marker. The Phase C gate is a log query for this string returning zero. */`

which makes a correct, irreversible, taxpayer-facing decision depend on log retention outliving the sweep and on nobody having rotated away the `ENCRYPTION_BACKFILL_ROW_FAILED` lines. The durable artifact built specifically to track this migration cannot answer the question.

**Recommendation.** Add `attempted`, `succeeded`, and `failed` counters to `EncryptionBackfillProgress`, accumulated per batch alongside the cursor advance (they commit in the same transaction as the cursor, so they stay consistent with it). Make the Phase C precondition `completed && failed == 0` on both rows, checkable with a single query. Consider also recording failed ids — at a few hundred rows a `failed_ids` array is cheap, and it turns "something failed months ago" into a list an operator can act on.

---

## D-3 — Advisory-lock keyspace collision

**Severity:** Low
**Files:**
- `direct-file/backend/src/main/java/gov/irs/directfile/api/taxreturn/EncryptionBackfillWorker.java:54`
- `direct-file/backend/src/main/java/gov/irs/directfile/api/taxreturn/TaxReturnService.java:385`

Two unrelated lock namespaces share one 32-bit key space:

```java
// EncryptionBackfillWorker
private static final int LOCK_ID = "encryption-backfill-sweep".hashCode();

// TaxReturnService:385
int lockId = taxReturnId.hashCode();
```

Both go to `AdvisoryLockRepository.acquireLock(int)`, which is the single-argument `pg_try_advisory_lock(:lockId)`. A tax return whose UUID hashes to the backfill's constant makes that taxpayer's submission and the sweep mutually exclusive: whichever runs second gets `false` from a non-blocking acquire and takes its lock-not-acquired branch.

The probability is roughly `n / 2^32` for `n` returns — small, and the consequence is a transient failure rather than a correctness or disclosure problem, which is why this is Low. But it is silent when it happens, and it is indistinguishable from ordinary contention in the logs.

**Recommendation.** Postgres provides `pg_try_advisory_lock(key1 int, key2 int)` precisely for namespacing. Add a two-argument variant to `AdvisoryLockRepository` and give each subsystem a distinct classifier. Failing that, partition the space explicitly (for example, reserve negative keys for singleton system locks) and document it where both call sites can see it.

---

## D-4 — No clickjacking protection anywhere

**Severity:** Low
**Files:** `direct-file/df-client/df-client-app/index.html:19-24`

The CSP added for L-6 is delivered by `<meta http-equiv>`, and `frame-ancestors` is header-only — the file's own comment says so. The gap was recorded as a handback in the client-hardening plan and never closed. A repository-wide search finds no `X-Frame-Options` header, no `frame-ancestors` directive, and no Spring Security `frameOptions` configuration: the only match is the comment explaining the limitation.

So the application that renders taxpayer data has no framing protection of any kind. Whether that is exploitable depends on edge configuration this repository cannot see — which is exactly why it should be in the register rather than only in a plan's handback, where it stops being tracked once the plan is merged.

**Recommendation.** Confirm whether the edge sets `Content-Security-Policy: frame-ancestors` or `X-Frame-Options`. If it does, record that; if it does not, the policy needs to move to a response header, which also recovers `report-uri` and the ability to stage changes in report-only mode — the other two capabilities meta delivery costs.

---

## D-5 — `lastFour` returns a short TIN unchanged

**Severity:** Info
**File:** `direct-file/backend/src/main/java/gov/irs/directfile/api/user/UserService.java`

```java
return tin.length() <= 4 ? tin : tin.substring(tin.length() - 4);
```

A TIN of four characters or fewer is emitted in full into the audit event map. Such a value is malformed and should not exist, and the M-1 remediation means the audit map is no longer the last line of defence, so this is a note rather than a defect. If it ever matters, returning a fixed placeholder for anything that is not the expected length is both safer and a signal that upstream validation failed.

---

## Reviewed and found sound

Stated explicitly so these are not re-reviewed without cause.

- **`ClientIpResolver`.** The trust boundary is correct: headers are read only when the immediate peer matches a configured proxy, `X-Forwarded-For` is walked right-to-left, a malformed hop terminates the walk rather than being skipped, and the empty-configuration default ignores both headers. `True-Client-IP` is behind its own flag, correctly separated from `trustedProxies` because it has no append-only structure to make a client-injected copy detectable. Every header value passes Guava's literal-only `InetAddresses.isInetAddress` before reaching `IpAddressMatcher.matches`, whose `InetAddress.getByName` would otherwise DNS-resolve attacker input.
- **M-3 redemption.** `AuthorizationCodeRepository.markRedeemed` is a conditional `UPDATE … WHERE redeemed_at IS NULL` and `StateApiServiceImpl.authorize` rejects a row count of zero. Exactly one caller can redeem a code. Redemption happening before downstream steps means a later failure consumes the code, which fails closed.
- **M-1 log discipline.** `UserService` puts only `USER_TIN_LAST4` into the audit map, and the `includeKeyValueKeyName` allowlist is present on the single encoder in each of `logback.xml` and `logback-local.xml`. No TIN, SSN, or email key appears in either allowlist.
- **Backfill cursor pagination.** `findIdsForBackfillAfter` is `WHERE t.id > :afterId ORDER BY t.id ASC` on both repositories, and the cursor is only ever taken from that query's own last result, so Postgres's bytewise UUID ordering stays self-consistent (it differs from `java.util.UUID.compareTo`, which is never used here). Returning ids rather than entities is the right call and the comment explains it: loading entities fires `@PostLoad`, so one undecryptable row would fail an entire page.
- **Backfill concurrency.** `tick()` is `@Transactional` so the advisory lock's acquire and release pin one pooled connection, which is required for session-scoped Postgres advisory locks. Per-row `REQUIRES_NEW` goes through the injected bean rather than `this`, so the proxy boundary is respected. `verifyRunnable` refuses to start the sweep under `enforce`, which would otherwise advance the cursor past every row while migrating none.
- **`decryptLegacyTolerant` scope.** The permanent tolerance applies only to the untagged case; a ciphertext bound to a *different* purpose is still refused in every mode. The exemption is narrow and is a distinct method rather than a config flag, so it is visible at the call site.
- **`CertificationOverrideGuard`.** Fails closed: an empty active-profile set is treated as production and refuses startup. The override value it logs is a certificate location, not key material.
- **CSP directive set.** `default-src 'self'`, `base-uri 'self'`, `object-src 'none'`, `form-action 'self'`, and a hashed inline bootstrap rather than `'unsafe-inline'`. The remaining `script-src` entries are specific hosts.

## Suggested sequencing

1. **D-2** first, and before any further use of the backfill. It is small, and D-1's remediation will need a trustworthy sweep to stand on.
2. **D-1** next. It is the highest-severity item and the only one that leaves the original H-1 scenario open, but it needs a context-schema change plus a backfill, so it has the longest lead time.
3. **D-4** — mostly a question to answer about edge configuration rather than code to write, and the answer determines whether there is work at all.
4. **D-3**, then **D-5**, as cleanup.

## Not covered

- The ~65 changed `df-client` files that are lint fixes, test changes, and unused-import removals were skimmed rather than read line by line.
- CI workflow changes (`.github/workflows/ci.yml`) were reviewed for secrets handling and permissions scoping during PR #5 and were not re-examined here.
- The unchanged majority of the monorepo. The 2026-08-22 review remains the current statement for that code, and its "reviewed and found sound" section still applies to everything this delta did not touch.
