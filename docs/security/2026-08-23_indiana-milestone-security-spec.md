# Indiana Milestone — Security Spec

**Date:** 2026-08-23
**Milestone:** Direct File supports tax filing for Indiana residents
**Scope decision:** Phase 1 — Indiana as a State API export partner (detailed below). Phase 2 — Direct File computing and filing the IN-40 (design-level, §7).
**Repo:** `direct-file` monorepo at commit `e0d5c84` (snapshot dated 2025-06-05)
**Companion document:** `docs/security/2026-08-22_codebase-security-review.md` (branch `claude/report-security-review-lb7lsz`) — the as-is review of the existing codebase. This spec does not restate its findings; §3 names the ones that gate this milestone.

---

## 1. Scope and method

### 1.1 What "handle taxes for Indiana residents" means here

The repo supports two materially different things, and the milestone was scoped to the first:

**Phase 1 — Indiana as an export partner.** Indiana joins the existing State API handoff: Direct File files the taxpayer's federal return, then hands an encrypted copy of the return data to Indiana's own tax tool so the taxpayer does not re-key it. This is what every currently-supported state does.

**Phase 2 — Direct File computes and files the IN-40.** Direct File would ask Indiana questions, compute Indiana tax including county income tax, and file to Indiana's e-file channel.

Phase 1 is reachable from the current codebase. Phase 2 is not an increment on it:

- The fact dictionary (`direct-file/backend/src/main/resources/tax/`, 36 modules) is entirely federal. There is no state tax module of any kind.
- The `submit` service has no state concept. It targets federal MeF only.
- `IN` already exists in `StateOrProvince` (`direct-file/libs/data-models/src/main/java/gov/irs/directfile/models/StateOrProvince.java:25`), alongside `AZ` at `:13` — the enum covers all states regardless of support status, so its presence indicates nothing about readiness.

Phase 1 is therefore the milestone. §7 records what changes in the threat model if Phase 2 is later undertaken, so that Phase 1 decisions are not made in ignorance of it.

### 1.2 The export flow as it stands

For orientation, the path Indiana would join:

1. The taxpayer, in the Direct File client, chooses to transfer their return to their state's tool.
2. The Direct File backend calls state-api `POST /state-api/authorization-code`, which verifies the return's submission status and mints a v4 UUID authorization code with a 600-second TTL (`authorization-code.expires-interval-seconds`, `application.yaml`).
3. The client redirects the taxpayer to the state's tool, carrying the authorization code as a query parameter.
4. The state's backend calls state-api `GET /state-api/export-return`, presenting a JWT signed by the state's private key and naming the authorization code.
5. State-api resolves the state's certificate, verifies the JWT signature, checks the code has not expired and belongs to that state, retrieves the return XML from S3, and returns it encrypted: AES-256-GCM over the payload, with the session key RSA-OAEP-wrapped to the state's public key.

The cryptographic construction here is sound and was confirmed as such in the companion review. The findings below are about the surrounding trust and process, which is where onboarding a new state actually lands.

### 1.3 Method, and a caveat that bounds it

Manual source review of `state-api`, the `backend` state-api integration, the `df-client` transfer screens, the state-api schema migrations, and the state-api configuration.

**Two functions central to this analysis are redacted in the public release.** Per `README.md`, code classified PII / FTI / SBU was removed or rewritten:

- `StateApiS3ClientImpl.getXmlString()` returns the literal `"<xml>"` (`direct-file/state-api/src/main/java/gov/irs/directfile/stateapi/repository/StateApiS3ClientImpl.java:110-111`). The real XML sanitization logic is absent.
- `StateApiService.getExportToStateFacts()` returns an empty `ExportableFacts()` (`direct-file/backend/src/main/java/gov/irs/directfile/api/stateapi/StateApiService.java:69-71`). The real exported-facts payload construction is absent.

These are exactly the two places where data-minimization findings would live — what federal return data a state actually receives. **No conclusion in this document should be read as clearing the export payload.** IN-6 exists to carry that question into the internal repository, where it can be answered.

---

## 2. The structural finding

Everything in §4 follows from one observation, so it is stated separately.

**Onboarding a state is a database data change, not a code change.**

The Liquibase changesets under `direct-file/state-api/src/main/resources/db/migrations/` only ever alter schema — `initial_schema`, `add-state-code-to-authorization-code`, `add-archived-to-state-profile`, `add-custom-cancel-urls`, `add-submission-id-to-auth-codes`, `enable-dynamic-language-links`, `add-filing-requirements-urls`, `add-department-of-revenue-urls`. Not one seeds a `state_profile` row. Adding Indiana consists of:

- a row in `state_profile` — `account_id`, `state_code`, `tax_system_name`, `landing_url`, `default_redirect_url`, `accepted_only`, `cert_location`, `cert_expiration_date`, the cancel URLs, `department_of_revenue_url`, `filing_requirements_url`, `custom_filing_deadline`, `archived`
- rows in `state_redirect` — the exact-match allowlist of URLs Indiana may redirect back to
- rows in `state_language` — language code mappings
- an X.509 certificate object in the cert S3 bucket at the path named by `cert_location`

Those values are security-load-bearing. `account_id` selects which certificate verifies Indiana's JWTs — it is the root of the authentication decision for the entire export. `accepted_only` governs whether returns not yet accepted by the IRS may be exported. `landing_url` and the cancel URLs become navigation targets in the authenticated taxpayer application. `cert_location` points at the trust anchor.

None of it passes through pull request review, CI, SpotBugs/FindSecBugs, PMD, or the ADR process. The controls the team has invested in for code do not apply to the artifact that actually onboards a state.

This is not a latent defect — it is the mechanism by which the Indiana milestone will be delivered. It is finding **IN-1**, and it is first in §4 because the assurance of IN-2, IN-3, and IN-6 all depend on their decisions having a reviewed, durable place to live.

---

## 3. Gating prerequisites from the companion review

Three findings in `2026-08-22_codebase-security-review.md` are load-bearing for this milestone. The analysis is not restated; what follows is why Indiana changes their standing.

### H-1 — Encryption context is never verified on decrypt
**Status for this milestone:** should be underway at go-live; does not block it.

Every encrypt path binds an encryption context; the decrypt path never inspects `CryptoResult.getEncryptionContext()`. Ciphertext produced under the CMK in any context decrypts cleanly in any other — including across services, so a state-API authorization token blob and a tax-return facts blob are mutually substitutable.

Indiana does not make this newly exploitable. What it does is enlarge the population of ciphertext living under one unverified context, and each state added after Indiana enlarges it again. The argument for starting now is that the fix requires context normalization plus a dual-read migration, so its lead time is the longest in this document and it only grows.

### M-3 — State-API authorization codes are not single-use
**Status for this milestone:** hard prerequisite. Must be closed before Indiana rows go live.

`StateApiServiceImpl.authorize()` (`:241`) checks the state code matches (`:266`) and that `expiresAt` is in the future (`:273`), then returns the entity. There is no redemption marker, and `AuthorizationCodeRepository` exposes only `getByAuthorizationCode`.

This is a prerequisite rather than a nice-to-have because of IN-4: the authorization code travels in a URL query string into Indiana's infrastructure. A code that reaches Indiana's access logs, and is replayable for its full 600-second TTL, is a materially worse position than a code that is spent on first use. The two findings compose, and M-3 is the cheaper half to fix.

### M-5 — HMAC signing key committed to the repository
**Status for this milestone:** hard prerequisite. Must be rotated before Indiana trusts tokens signed with it.

`direct-file/state-api/src/main/resources/application-development.yaml:6` carries `signing-key: GTc+SlI7C7ECPHAhAvIWqn2yAvzAGMVj`, the HS256 key `AuthorizationTokenService` uses to sign state export tokens. Onboarding a new partner is the natural point to rotate it: asking Indiana to rely on the integrity of tokens signed with a key published in a public repository is not defensible, and rotation is cheap relative to the conversation it avoids.

---

## 4. Net-new findings

### IN-1 — State onboarding bypasses every code-path control
**Severity:** High (process)
**Evidence:** `direct-file/state-api/src/main/resources/db/migrations/` — schema-only changesets, no row seeding anywhere in the tree.

Stated in full in §2. The condensed form: the artifact that onboards Indiana is a set of database rows and an S3 object, and it is subject to none of the review, static analysis, or architectural-decision controls that any code change would face. The values in those rows determine the trust anchor for Indiana's authentication, whether unaccepted returns are exportable, and where the authenticated client navigates taxpayers.

**Recommendation.** Make onboarding a reviewed, versioned artifact before Indiana's rows are written.

- Express state onboarding as a Liquibase changeset (or an equivalently reviewed, version-controlled configuration artifact) so it takes the same path as code.
- Add validation at the boundary where those values are consumed, so that a bad row fails closed rather than being trusted: URL scheme validation (see IN-5), `account_id` uniqueness and format, `cert_location` resolvability checked at onboarding rather than at first export.
- Publish an onboarding checklist (§6) and require it complete before the artifact merges.
- Record the per-state policy decisions (IN-3's `accepted_only`, IN-6's disclosure determination) in the same artifact, so the rationale lives with the value.

**Note on repo boundaries.** If state onboarding is already performed through a reviewed process in an internal repository not published here, this finding reduces to confirming that — but the confirmation is worth making explicit, because nothing in the public tree evidences it.

### IN-2 — Certificate trust and revocation lifecycle
**Severity:** Medium
**Evidence:**
- `direct-file/state-api/src/main/java/gov/irs/directfile/stateapi/service/CachedDataService.java:63-64`
- `direct-file/state-api/src/main/java/gov/irs/directfile/stateapi/service/StateApiServiceImpl.java:428-435`

Indiana's certificate is the sole authentication anchor for its exports. Three gaps in how it is handled:

**Revocation is not prompt.** The code carries its own warning:

```java
// NOTE: the cert is cached and expiration won't apply during the cache duration
@Cacheable(cacheNames = "publicKeyCache", key = "#certName")
public Mono<PublicKey> retrievePublicKeyFromCert(String certName, OffsetDateTime enforcedExpirationDate) {
```

Eviction is a scheduled sweep of all entries at `spring.cache.TTL-minutes` (default 120, `CachedDataService:50,58`). Both the certificate's own `notAfter` and the IRS-enforced `cert_expiration_date` are evaluated only on a cache miss. If Indiana reports a compromised private key, replacing the S3 object or updating `cert_expiration_date` has no effect for up to two hours. There is no targeted eviction path.

**Trust is bounded only by `notAfter`.** `retrievePublicKeyFromCert` parses the object with `CertificateFactory`, checks `notAfter` and the IRS-enforced date, and returns the public key. There is no chain validation, no CRL, no OCSP, and no pinning — a self-signed certificate is accepted so long as it is unexpired. Whether that is acceptable depends on the out-of-band process by which Indiana delivers its certificate to the IRS, which this repository does not describe.

**The override defeats all of it.** `StateApiServiceImpl.retrievePublicKeyFromCert` (`:428`):

```java
String certOverride = certProperties.getCertLocationOverride();
String cert = (StringUtils.isBlank(certOverride)) ? sp.getCertLocation() : certOverride;
OffsetDateTime expDate = (StringUtils.isBlank(certOverride))
        ? sp.getCertExpirationDate()
        : OffsetDateTime.now().plusYears(1);
```

When set, `direct-file.cert-location-override` replaces the certificate for *every* state simultaneously and synthesizes an expiration of `now + 1 year`, bypassing both the per-state expiration and the IRS-enforced date. This is a lower-environment convenience with no production guard. Anyone able to set it in a reachable environment holds the authentication anchor for every state at once.

**Recommendation.**
- Define and document a revocation SLA with Indiana, and add a targeted eviction path (evict by `certName`) so revocation does not wait out the TTL.
- Add a startup assertion that `cert-location-override` is unset when the production profile is active; fail to start otherwise.
- Record the certificate delivery and rotation process with Indiana as part of the onboarding artifact — who delivers, through what channel, verified how, and rotated on what cadence.
- Decide explicitly whether self-signed is acceptable, and if so, record why the out-of-band delivery channel carries the trust.

### IN-3 — The `accepted_only` decision for Indiana needs a recorded rationale
**Severity:** Medium (policy)
**Evidence:** `StateApiServiceImpl.getAcceptedOnlyFlag()` and the `submissionOk` computation in `createAuthorizationCode()` / `generateAuthorizationToken()`.

Both authorization paths compute:

```java
final boolean submissionOk = status.exists() && (isAccepted || (!acceptedOnly && isPending));
```

With `accepted_only = false`, Indiana receives return data for submissions the IRS has not yet accepted — a population that includes returns which will subsequently be rejected. Indiana then holds federal return data for a return that, federally, does not stand. The taxpayer corrects and resubmits; nothing in this flow retracts what Indiana already received.

Today this is a boolean in an unreviewed database row (IN-1). It is a disclosure-policy decision presented as a configuration flag.

**Recommendation.** Make it an explicit decision for Indiana, recorded with its rationale in the onboarding artifact. If `false` is chosen, confirm with Indiana what they do with data for a return later rejected federally, and confirm the taxpayer-facing content sets that expectation. The client already has the vocabulary for this — `WaitingForAcceptanceScreen` and `ReturnRejectedScreen` exist — so the question is which experience Indiana's taxpayers get, not whether the states of the world are representable.

### IN-4 — The authorization code travels in a URL query string
**Severity:** Medium
**Evidence:** `direct-file/df-client/df-client-app/src/screens/AuthorizeStateScreen/AuthorizeStateScreen.tsx:56`, `:249`

```js
redirectUrl.searchParams.append(AUTHORIZATION_CODE_PARAM_NAME, authorizationCode);
```

followed by `window.location.assign(redirectUrl)` (`:249`). The authorization code is therefore exposed to:

- Indiana's web server access logs, which conventionally record the full request line
- the browser's history and session restore
- the `Referer` header on any subresource or onward navigation from Indiana's landing page, including third-party analytics
- any intermediary at Indiana's edge that logs URLs

**What limits this.** The code alone is not sufficient to redeem. `GET /state-api/export-return` additionally requires a JWT signed by Indiana's registered private key, and `authorize()` rejects a code whose `state_code` does not match the requesting account's (`StateApiServiceImpl:266`). An attacker holding only a leaked code cannot exchange it. The realistic exposure is an attacker who already has some position within Indiana's infrastructure — for whom the log-resident code shortens the path.

**What worsens it.** M-3. Because codes are not spent on redemption, a code recovered from a log is replayable for its full 600-second life, and there is no server-side record distinguishing a replay from the legitimate exchange. Fixing M-3 collapses the useful window to the interval before Indiana's own backend redeems, which in practice is seconds.

**Recommendation.**
- Close M-3 first; it does most of the work.
- As part of onboarding, obtain confirmation from Indiana that their edge and application tiers do not log query strings or referrers for the landing path, and that no third-party analytics runs on it.
- Consider whether the handoff should move to a form POST rather than a query parameter. This changes Indiana's integration contract, so it is a decision to make at onboarding time rather than to retrofit across states later.
- Confirm the authorization code is not written to the client's own logging or analytics.

### IN-5 — State profile URLs are navigated and rendered without scheme validation
**Severity:** Medium
**Evidence:**
- `AuthorizeStateScreen.tsx:258` — `const cancelUrl = new URL(transferCancelUrl || landingUrl);`
- `AuthorizeStateScreen.tsx:276` — `const cancelUrl = new URL(waitingForAcceptanceCancelUrl || landingUrl);`
- `StateInfoCard.tsx:35` — `const landingUrl = new URL(stateProfile.landingUrl);`
- `StateTaxesButton.tsx:10` — `const asUrl = new URL(landingUrl);`

**The redirect allowlist itself is sound and should not be changed.** `determineRedirectUrl` (`AuthorizeStateScreen.tsx:53`) does exact string matching:

```js
const baseUrl = redirectParam && allowedRedirectUrls.includes(redirectParam) ? redirectParam : defaultRedirectUrl;
```

No prefix or substring matching, no origin comparison that could be tricked by a crafted authority component. A `redirect` query parameter that is not exactly present in `state_redirect` falls back to the default. This is the right construction.

The gap is the fields that are *not* subject to it. `landing_url`, `default_redirect_url`, `transfer_cancel_url`, and `waiting_for_acceptance_cancel_url` are read from `state_profile` and passed directly to `new URL(...)`, then to `window.location.assign` or rendered as an anchor through `CommonLinkRenderer`. No scheme check anywhere. `new URL('javascript:...')` parses successfully, and navigation to it executes.

**Consequence.** A `javascript:` value in Indiana's `state_profile` row is stored XSS in the authenticated taxpayer application — the context that renders federal tax return data. Reaching it requires either a write to the state-api database or a bad value at onboarding, so likelihood is low. But IN-1 establishes that onboarding is precisely an unreviewed database write, and Indiana onboarding is the next time these fields get populated. The cost of closing it is a few lines.

**Recommendation.** Validate at both ends. Reject any non-`https:` scheme when the onboarding artifact is written, and guard at the point of use in the client — a small helper that parses and asserts `protocol === 'https:'`, returning a safe fallback otherwise, applied to every state-profile URL field. Doing it in both places means neither a bad row nor a future consumer that forgets the check produces a navigable `javascript:` URL.

### IN-6 — Export payload minimization is undetermined and cannot be settled from this repository
**Severity:** High (undetermined — see caveat)
**Evidence:**
- `StateApiS3ClientImpl.java:110-111` — `getXmlString()` returns `"<xml>"`
- `backend/.../StateApiService.java:69-71` — `getExportToStateFacts()` returns an empty `ExportableFacts()`
- `direct-file/state-api/src/main/resources/application.yaml:89-91` — `xml-sanitized.allowed-headers` and `excluded-tags` are both empty

What federal return data Indiana receives is the most consequential security question in this milestone, and it is the one this repository cannot answer. The two functions that construct the payload are stubbed, and the configuration that would drive sanitization ships with no entries:

```yaml
xml-sanitized:
  allowed-headers:
  excluded-tags:
```

`StateApiS3ClientImpl.setExcludedPatterns()` compiles `excluded-tags` into regexes that strip matching elements from the return XML. With the list empty and its consumer stubbed, neither the mechanism nor the policy is observable here.

Severity is recorded as High-undetermined rather than assigned: the finding is that the determination has not been made *visible*, not that a specific over-disclosure exists.

**Recommendation.** Carry this into the internal repository as a blocking item for the milestone.

- Enumerate exactly which XML elements and which exported facts Indiana receives, and review that enumeration against the disclosure agreement with Indiana under 26 U.S.C. §6103(d).
- Confirm the disclosure is minimized to what Indiana needs to compute the IN-40 — Indiana's requirements differ from other states', so an enumeration inherited from another state's onboarding is not sufficient.
- Confirm `xml-sanitized.excluded-tags` is populated in the deployed configuration, and that its regex-based stripping is tested against the actual return XML shapes rather than assumed.
- Record the determination in the onboarding artifact (IN-1) so the value and its legal basis live together.

---

## 5. Findings deliberately not raised

Recorded so they are not re-examined without new cause.

- **Redirect allowlist construction.** Exact-match on a server-supplied list, with fallback to the default. Sound; see IN-5.
- **Export cryptography.** AES-256-GCM with a fresh 12-byte `SecureRandom` IV and 128-bit tag per export; session key RSA-OAEP-SHA256/MGF1 wrapped to the state's public key; authorization codes are v4 UUIDs stored SHA-256 hashed. No ECB, no static IVs, no home-rolled constructions.
- **The `getAccountId` pattern.** Reading the account id from the unverified JWT payload is correct here — it selects which certificate to load, and the signature is then verified against that certificate, with the resulting state code checked against the authorization code's state. A forged account id selects a certificate the attacker cannot sign for.
- **State-code mismatch check.** `E_MISMATCHED_STATE_CODE` (`StateApiServiceImpl:266`) prevents one onboarded state from redeeming another's authorization codes. This is the control that contains a compromised state partner, and it is present.

---

## 6. Onboarding security checklist

To be complete before Indiana's `state_profile` row is written. Intended to be carried in the onboarding artifact (IN-1) rather than tracked separately.

**Prerequisites closed**
- [ ] M-5 — signing key rotated out of the repository, no committed default, startup assertion against the historical literal
- [ ] M-3 — authorization codes redeemed atomically and single-use
- [ ] H-1 — encryption context normalization underway with a dated plan (not required complete)

**Certificate**
- [ ] Delivery channel from Indiana DOR to IRS documented, with verification method
- [ ] `cert_expiration_date` set, and shorter than the certificate's own `notAfter`
- [ ] Revocation SLA agreed with Indiana; targeted cache eviction path exists
- [ ] Rotation cadence and owner recorded
- [ ] Production startup assertion that `cert-location-override` is unset

**Profile data**
- [ ] Every URL field `https:` — validated at write and at point of use (IN-5)
- [ ] `state_redirect` rows are the complete and exact set Indiana will redirect to
- [ ] `accepted_only` decided, with rationale recorded (IN-3)
- [ ] `account_id` unique and format-checked
- [ ] `cert_location` resolves at onboarding time, not first export

**Disclosure**
- [ ] Exported XML elements and facts enumerated (IN-6)
- [ ] Enumeration reviewed against the §6103(d) agreement with Indiana
- [ ] `xml-sanitized.excluded-tags` populated in deployed config and tested against real return XML shapes
- [ ] Determination recorded in the onboarding artifact

**Handoff**
- [ ] Indiana confirms no query-string or referrer logging on the landing path (IN-4)
- [ ] Indiana confirms no third-party analytics on the landing path
- [ ] POST-vs-query-parameter handoff decided for this integration

**Review**
- [ ] Onboarding artifact reviewed as code, by someone other than its author
- [ ] Rollback path exercised — `archived = true` verified to fail closed

---

## 7. Phase 2 — trust boundary changes if Direct File computes and files the IN-40

Design-level, recorded so Phase 1 decisions are made with the destination in view. Not a review; there is no implementation to review.

**The fact dictionary gains its first non-federal module.** All 36 modules under `backend/src/main/resources/tax/` are federal. Adding Indiana tax logic makes correctness a security property rather than only a quality one: a defect in county-tax computation produces financial harm to a taxpayer with no compensating control downstream. The existing tax-logic testing strategy (`docs/adr/tax-logic-testing-strategy.md`) would need to be evaluated for whether it carries to state logic with the same assurance.

**A new outbound trust boundary.** Filing to Indiana requires a channel to Indiana's e-file system with its own credential, its own availability and failure modes, and its own submission audit trail. Today the only outbound tax-data path is federal MeF via `submit`, which has no state concept. This is a new integration of the same class as MeF, and warrants the same scrutiny.

**The data retention posture changes.** In Phase 1 Direct File passes federal data through to Indiana and holds no Indiana return. In Phase 2 Direct File holds Indiana state return data — a new category of records, with retention, disclosure, and breach-notification obligations under Indiana law in addition to federal ones. This is the single largest change and should be assessed before Phase 2 is committed to, not during it.

**County determination becomes attacker-influenceable input.** Indiana levies county income tax across 92 counties, assessed on county of residence and county of principal work as of a determination date. That makes a taxpayer-supplied answer directly determinative of liability, and makes the county rate table a security-relevant configuration artifact — one that changes annually and whose integrity would need the same treatment IN-1 argues for state profile data.

**Residency and part-year handling.** Part-year and non-resident Indiana filers, and the reciprocity agreements Indiana holds with neighboring states, expand the state space that tax logic must handle correctly. Correctness gaps here are the most likely source of taxpayer harm.

---

## 8. Sequencing

Ordered by dependency and lead time, not severity. The long poles are IN-6 (external legal determination) and IN-1 (organizational process), so both start immediately even though most code work is faster.

### Tranche 0 — start now, no dependencies
- **IN-5** — scheme validation at write and at point of use. Cheapest item here; closes the stored-XSS path before any Indiana rows exist.
- **M-5** — rotate the signing key, remove the committed default, assert against the historical literal at startup. Hard predecessor to onboarding.
- Companion review's **L-3** (`getStateCode()` substring bound) and **L-4** (`assert` for cryptographic length validation) opportunistically — both live in files Tranche 1 already touches.

### Tranche 1 — before any Indiana row goes live
- **IN-1** first within the tranche. Until onboarding data is a reviewed, versioned artifact, IN-2's and IN-3's decisions have nowhere durable to be recorded.
- **M-3** — atomic single-use redemption (`UPDATE ... WHERE redeemed_at IS NULL RETURNING *`). Hard predecessor to calling IN-4 mitigated.
- **IN-2** — revocation SLA, targeted cache eviction, production assertion on `cert-location-override`.

### Tranche 2 — needs the counterparty; start in parallel with Tranche 0
- **IN-6** — the §6103(d) determination with Indiana DOR. Longest external lead time in this document and not compressible later, which is why it starts first despite landing last.
- **IN-3** — the `accepted_only` decision with rationale. Cheap once IN-1 gives it a home.
- **IN-4** — Indiana's logging confirmations; POST-vs-query decision. Only closeable after M-3.

### Tranche 3 — longest code lead time, does not gate Indiana
- **H-1** — encryption context normalization and dual-read migration. Should be underway rather than complete at go-live. Every state added raises the cost of continuing to defer it.

> **Status as of 2026-08-25.** Tranches 0 and 1 are closed in code. H-1 is specified in
> `docs/security/2026-08-25_h1-encryption-context-spec.md`, with Phase A (normalize writes,
> verify reads, ship in `warn`) planned in
> `docs/superpowers/plans/2026-08-25-h1-encryption-context-tranche-3.md`. Phase B (backfill)
> and Phase C (enforce) are scoped there but not yet planned. Tranche 2 remains open and is
> not code work — it needs the counterparty.

**Critical path:** IN-6 → IN-1 → M-3 → IN-4. Everything else parallelizes around it.
