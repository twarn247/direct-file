# H-1 — Encryption Context Normalization and Verification

**Status:** proposed
**Tranche:** 3 (see `2026-08-23_indiana-milestone-security-spec.md` §8)
**Predecessor:** Tranche 0 & 1 complete — IN-5, M-5, M-3, IN-1, IN-2, L-3, L-4 are closed.
**Implementation plan:** `docs/superpowers/plans/2026-08-25-h1-encryption-context-tranche-3.md`

---

## 1. Why this is the next item

The Indiana milestone spec sequences H-1 last by dependency, not by severity, and says it "should be underway rather than complete at go-live." Everything ahead of it in the code queue is now done. What remains in Tranche 2 — the §6103(d) determination with Indiana DOR (IN-6), the `accepted_only` rationale (IN-3), Indiana's logging confirmations (IN-4) — requires the counterparty and cannot be moved by writing code. H-1 is the only remaining item whose critical path is entirely inside this repository, and it has the longest code lead time in the document.

The spec's argument for starting now is a growth argument: every state added enlarges the population of ciphertext living under an unverified context, and the migration cost grows with it. That argument is unchanged, and one state is about to be added.

## 2. The finding, restated against current code

Every encrypt path binds an encryption context. No decrypt path inspects it.

```java
// libs/data-models/src/main/java/gov/irs/directfile/models/encryption/DataEncryptDecrypt.java:23
public byte[] encrypt(byte[] bytes, Map<String, String> context) {
    CryptoResult<byte[], ?> encryptResult = awsCrypto.encryptData(cryptoMaterialsManager, bytes, context);
    return encryptResult.getResult();
}

// :28
public byte[] decrypt(byte[] ciphertext) {
    CryptoResult<byte[], ?> decryptResult = awsCrypto.decryptData(cryptoMaterialsManager, ciphertext);
    return decryptResult.getResult();
}
```

`decrypt` takes no expectation and discards `decryptResult.getEncryptionContext()`. The AWS Encryption SDK authenticates the context as additional authenticated data — it cannot be tampered with — but authenticating it is not the same as checking it is the context you wanted. Under a single CMK, any ciphertext decrypts in any caller.

### 2.1 What is actually substitutable today

There are exactly three encrypt call sites in this repository, and they write four distinct kinds of plaintext:

| Call site | Context written | Plaintext |
|---|---|---|
| `TaxReturnEntityListener:50` (authenticated write) | `{id: <externalId>}` | facts blob **and** store blob |
| `TaxReturnEntityListener:53-54` (system write) | `{system: DIRECTFILE, type: API}` | facts blob **and** store blob |
| `AuthorizationTokenService:95-96` | `{system: DIRECT-FILE, type: STATE-API}` | signed JWS parts |

Two observations follow directly from that table, and they are the whole finding:

**The facts blob and the store blob are written under an identical context.** `TaxReturnEntityListener.encryptColumns` builds one `Map` and passes the same instance to both `factsEncryptor.convertToDatabaseColumn` (`:57`) and `genericStringEncryptor.convertToDatabaseColumn` (`:59`). Even a decrypt path that checked the context perfectly could not tell `taxreturns.facts` from `taxreturns.store`. Column-to-column substitution within a row is invisible at the crypto layer regardless of verification, until the contexts are made distinct. **Normalization is therefore not cosmetic: without it, verification has nothing to verify.**

**The two `system` values disagree.** The backend writes `DIRECTFILE`; state-api writes `DIRECT-FILE`. Any check written today against one spelling silently fails against the other, and the disagreement is invisible because nothing reads the value.

### 2.2 The read paths that would have to change

Three decrypt call sites, all in `libs/data-models`:

- `FactsEncryptor.convertToEntityAttribute` (`:46`) — reached from `TaxReturnEntityListener.decryptColumns` `@PostLoad` (`:39`)
- `GenericStringEncryptor.convertToEntityAttribute` (`:27`) — reached from three places: the same `@PostLoad` (`:41`), `PopulatedDataEntityListener:28`, and `RawResponseDecryptor:24`

`GenericStringEncryptor` is the one shared decrypt path for three unrelated kinds of data. It is where a purpose expectation has to be threaded through, and it is why the expectation must be a parameter rather than a field on the encryptor.

### 2.3 Two constraints that shape the design

**The `id` context key cannot be verified at read time.** `decryptColumns` runs at `@PostLoad` with no authenticated principal in scope, and even if it had one, `id` records the external ID of whoever *last wrote* the row, which need not be the reader. A per-user context key is useful for KMS CloudTrail attribution and useless as a read-time assertion. The design must therefore separate *verified* keys from *informational* keys rather than checking the whole map.

**Two ciphertext populations are written outside this repository.** `PopulatedData.dataCipherText` and `PopulatedData.rawDataCipherText` are read by `PopulatedDataEntityListener` and `RawResponseDecryptor`, but nothing in this repository writes them — `setDataCipherText` and `setRawDataCipherText` have no call sites here. The same is true of `User.emailCipherText` and `User.tinCipherText`, which have no reader or writer in this repository at all. Whatever produces the data-import ciphertext is out of scope for this plan and cannot be migrated by it. Those read paths must stay legacy-tolerant after the tax-return paths go strict, and saying so explicitly is part of the deliverable.

### 2.4 One scope reduction the plan can bank

`AuthorizationTokenService.generateAndEncrypt` is reachable only from `StateApiServiceImpl.generateAuthorizationToken` (`:172`), which no controller calls. `StateApiController` exposes exactly three endpoints — `POST /state-api/authorization-code`, `GET /state-api/export-return`, `GET /state-api/state-profile` — and none of them reaches it; its only other callers are six tests in `StateApiServiceImplTest`. Nothing in this repository decrypts its output.

So the state-api context is normalized here for consistency and to fix the `DIRECT-FILE`/`DIRECTFILE` split, but it carries no migration risk and no production ciphertext population. **The migration is a backend-only problem.** This should be confirmed against deployed configuration before the plan is executed — the finding is "no caller in this repository", not "provably dead".

## 3. Design

### 3.1 The context schema

Three keys, with different rules:

| Key | Required | Verified on decrypt | Value |
|---|---|---|---|
| `purpose` | yes | **yes** | closed vocabulary, below |
| `system` | yes | no | constant `DIRECT-FILE` |
| `id` | no | no | actor external ID, when a principal is in scope |

`purpose` values, one per distinguishable plaintext kind:

- `tax-return-facts` — `taxreturns.facts`, `taxreturn_submissions.facts`
- `tax-return-store` — `taxreturns.store`
- `state-export-token` — the signed JWS parts blob
- `data-import-populated-data`, `data-import-raw-response` — **reserved**, read-side only; nothing in this repository writes them

The existing `type` key (`API`, `STATE-API`) is dropped. It encoded which service wrote the blob, which is the wrong axis: the threat is substituting one *kind of plaintext* for another, and two kinds written by the same service were indistinguishable under it. `purpose` replaces it on the right axis. `system` is retained as a constant and normalized to the state-api spelling, so that a future second producer is distinguishable.

### 3.2 Verification rule

`decrypt` takes the expected purpose. After a successful ESDK decrypt, inspect `CryptoResult.getEncryptionContext()`:

1. `purpose` present and equal to expected → **accept**.
2. `purpose` present and different → **reject, always, in every mode.**
3. `purpose` absent → legacy ciphertext. Accept or reject per the migration mode in §3.3.

Rule 2 is the load-bearing one. It is unconditional, which means the substitution attack is closed for every blob written after deploy — on the day of deploy, not at the end of the backfill. The migration mode governs only how long previously written ciphertext is tolerated. Stating this the other way: **the dual-read window is a window of incomplete coverage, not a window of no coverage.**

Verification happens after decryption, not before. The ESDK offers no pre-decrypt context filter in this version, and it does not need one: the context is authenticated, so a mismatch detected after decryption is as trustworthy as one detected before it. The plaintext must be discarded on mismatch rather than returned.

### 3.3 Migration modes

One property, `direct-file.encryption.context-verification`, two values:

- **`warn`** (default for Phase A) — rule 3 accepts, and emits a counter increment and a rate-limited log line naming the expected purpose. This is the dual-read state.
- **`enforce`** — rule 3 rejects.

The data-import read paths (`PopulatedDataEntityListener`, `RawResponseDecryptor`) are pinned to legacy-tolerant behavior independent of this property, because §2.3 says this plan cannot migrate their writers. They are marked in code with the reason and the condition for lifting it.

Those pinned paths accept untagged ciphertext **without reporting it**. This is not an oversight: they are untagged permanently, so if they emitted the marker, the Phase C gate in §3.4 — a log query for `ENCRYPTION_CONTEXT_LEGACY` returning zero — could never be satisfied, and the flip would end up gated on some filter improvised at a console instead. The marker must mean exactly one thing, *ciphertext still waiting to be migrated*, or it is not usable as a gate.

A second marker, `ENCRYPTION_CONTEXT_MISMATCH`, records rule-2 refusals. It is never expected in normal operation, and it is emitted even on the pinned paths — permanent tolerance of *untagged* ciphertext is not tolerance of *mislabelled* ciphertext. Both data-import readers currently wrap their decrypt in a catch-all that logs and leaves the field unset; the mismatch is caught ahead of that catch-all so a substitution is not lost among malformed-JSON failures. The degradation behavior is deliberately unchanged — at the point the exception is raised the control has already worked, the plaintext having been refused and zeroed, so what was missing was observability rather than enforcement.

### 3.4 Phasing

**Phase A — code (this plan's implementation).** Normalize all writes to the §3.1 schema. Thread expected purpose through every read path. Ship in `warn`. One deployable unit; no data migration.

**Phase B — backfill.** Re-encrypt `taxreturns.facts`, `taxreturns.store`, and `taxreturn_submissions.facts` under the new contexts. Phase A must be fully deployed first, so that anything the backfill writes is already verified on read.

**Phase C — enforce.** Flip the property once `ENCRYPTION_CONTEXT_LEGACY` has read zero across a full window of legitimate traffic — the window must exceed the longest interval at which a dormant tax return can be loaded, which is a data-retention question, not an engineering one, and the milestone owner has to answer it.

Only Phase A is planned in detail. Phase B is specified at the interface level in §4 because its cost is the reason this item starts now; it is planned properly once Phase A's counter shows the real size of the legacy population.

### 3.5 Deploy and rollback safety

Rolling deploys mix old and new instances. Both directions are safe, and it is worth being precise about why:

- **New writer, old reader.** The old reader ignores the context entirely. Purpose-tagged ciphertext decrypts unchanged.
- **Old writer, new reader.** The new reader sees no `purpose` and, in `warn`, accepts it — that is exactly what rule 3 is for.
- **Rollback after Phase A.** Ciphertext written during the window carries extra context keys that the rolled-back code ignores. No data is stranded.
- **Rollback after Phase C** would strand nothing either, but re-entering `warn` reopens the tolerance, so Phase C should be treated as one-way in practice.

There is no ordering constraint between deploying the reader change and the writer change. They ship together because they are one commit, not because they must.

## 4. Phase B interface (not planned in detail here)

The backfill has a hook already in the code and should use it rather than inventing one. `TaxReturn` carries a sentinel:

```java
// TaxReturn.java:24
private static final String DD = "DD-to-force-reencryption-by-entity-listener";
```

`setFacts` and `setStore` write that sentinel into the ciphertext column to dirty the entity, and `@PreUpdate` then re-encrypts. A backfill therefore needs only to load each row and call `setFacts(getFacts())` / `setStore(getStore())` — no new crypto code, and it inherits whatever `encryptColumns` does at the time it runs. This is the mechanism `PDFBackfillToS3Handler` would be modelled against for batching and idempotency.

Two consequences to carry into the Phase B plan:

- `TaxReturn.updatedAt` is `@UpdateTimestamp`, so a backfill save bumps it. No application query in `backend/src/main` reads `updated_at`, so in-app behavior is unaffected — but downstream analytics or retention tooling outside this repository may read it, and that needs confirming before a full-table pass.
- The `id` context key on a backfilled row will be absent (the backfill runs without an authenticated principal), where the original write may have carried one. `id` is informational and unverified by design, so this is acceptable — but it means a backfilled row is no longer attributable to its writer in CloudTrail, and the milestone owner should agree that trade before Phase B runs.

## 5. What this does not close

- **The data-import ciphertext population** (§2.3). Out of scope; requires the external writer to adopt the schema.
- **`User.emailCipherText` / `User.tinCipherText`.** Columns exist with no reader or writer in this repository. Either dead or written elsewhere; worth resolving, but not by this plan.
- **Anything about the CMK itself.** Key policy, rotation, and grant constraints are unchanged. If the KMS key policy uses `kms:EncryptionContext:` condition keys, changing the context shape can break Encrypt calls at deploy — an ops check listed in §6, and the single most likely way this change fails in production.
- **Cross-CMK isolation.** Separating tax-return data and state-export tokens onto different CMKs would make substitution structurally impossible rather than checked. That is a stronger control than this one and a much larger change; it is not proposed here, and this plan does not preclude it.

## 6. Handback to the milestone owner

Items the implementation cannot perform:

1. **Confirm the KMS key policy does not constrain `kms:EncryptionContext:type`, `kms:EncryptionContext:system`, or `kms:EncryptionContext:purpose`.** This change drops `type` entirely, normalizes `system` to a single spelling present on every write (previously only system-triggered tax-return writes carried `system`; authenticated writes carried `{id}` alone), and adds `purpose` to every write. If the policy constrains any of these three keys, it must be updated before Phase A deploys, or Encrypt calls will begin failing.
2. **Confirm `generateAuthorizationToken` is genuinely unreachable in deployed environments** (§2.4). If some deployed configuration routes to it, the state-api ciphertext population is not empty and Phase B grows a third table.
3. **Decide the Phase C observation window** (§3.4) — bounded by how long a tax return can sit unread and still be loaded.
4. **Approve the loss of `id` attribution on backfilled rows** (§4).
5. **Confirm whether anything outside this repository reads `taxreturns.updated_at`** before Phase B does a full-table pass.
