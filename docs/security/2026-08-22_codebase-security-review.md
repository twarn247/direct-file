# Direct File — Codebase Security Review

**Date:** 2026-08-22
**Scope:** `direct-file` monorepo at commit `e0d5c84` (snapshot dated 2025-06-05)
**Method:** Manual source review of the Spring Boot services (`backend`, `state-api`, `submit`, `status`, `email-service`), shared `libs/data-models`, build/dependency configuration, and the React client (`df-client`).

## Scope caveat — read this first

Per `README.md`, code classified as PII / FTI / SBU has been removed or rewritten for public release. This has a direct effect on what could be reviewed:

- The **pre-authentication filter is absent.** `RequestHeaderNames.PREAUTHENTICATED_AUTHENTICATION_HEADER_NAME` (`SM_UNIVERSALID`) is declared but referenced nowhere else in the tree, and there is no `AbstractPreAuthenticatedProcessingFilter` or equivalent. `SecurityConfiguration` builds a single filter chain that is `permitAll()` on `/**` with `SessionCreationPolicy.STATELESS`, so **authentication is enforced entirely outside this repository** (edge/SiteMinder). Nothing in this review validates that layer.
- `EmailAllowlistFeatureService` has had its key material loading stripped (see L-2), so its runtime behavior here is not the production behavior.

Findings below are therefore about the code that *is* present. Authentication itself, edge configuration, IAM/KMS key policy, and network segmentation are out of scope and need separate review.

---

## Summary

| ID | Severity | Finding |
|----|----------|---------|
| H-1 | High | AWS Encryption SDK encryption context is set on encrypt but never verified on decrypt |
| M-1 | Medium | Raw TIN (SSN) and email emitted to logs under the `local` and `debug` logback profiles |
| M-2 | Medium | Client-controlled IP headers trusted unconditionally for audit records |
| M-3 | Medium | State-API authorization codes are not single-use |
| M-4 | Medium | `server.error.include-message: always` returns exception messages to clients |
| M-5 | Medium | HMAC signing key for state authorization tokens committed to the repository |
| L-1 | Low | `MockDataImportController` is not profile-gated |
| L-2 | Low | `EmailAllowlistFeatureService` initializes its HMAC key to `null` |
| L-3 | Low | `getStateCode()` throws on a one-character `x-header` |
| L-4 | Low | `Encryptor` uses `assert` for key/IV length validation |
| L-5 | Low | Platform-default charset used for encrypting/decrypting taxpayer strings |
| L-6 | Low | No Content-Security-Policy on the authenticated client app |
| L-7 | Low | No dependency (SCA) vulnerability scanning in the build |
| L-8 | Low | Test-data hooks compiled into the client bundle behind a build flag |

---

## H-1 — Encryption context is never verified on decrypt

**Files:**
- `direct-file/libs/data-models/src/main/java/gov/irs/directfile/models/encryption/DataEncryptDecrypt.java:27`
- `direct-file/libs/data-models/src/main/java/gov/irs/directfile/models/encryption/FactsEncryptor.java:40`
- `direct-file/libs/data-models/src/main/java/gov/irs/directfile/models/encryption/GenericStringEncryptor.java:23`
- `direct-file/backend/src/main/java/gov/irs/directfile/api/taxreturn/models/TaxReturnEntityListener.java:45`

Every encrypt path supplies an encryption context. `TaxReturnEntityListener.encryptColumns` binds each taxpayer's ciphertext to their identity:

```java
encryptionContext.put("id", identityAttributes.externalId().toString());
```

and `AuthorizationTokenService.encryptToken` binds state-export tokens with `system=DIRECT-FILE, type=STATE-API`.

The decrypt path discards all of it:

```java
public byte[] decrypt(byte[] ciphertext) {
    CryptoResult<byte[], ?> decryptResult = awsCrypto.decryptData(cryptoMaterialsManager, ciphertext);
    return decryptResult.getResult();   // getEncryptionContext() never inspected
}
```

`getEncryptionContext` does not appear anywhere in the repository outside of tests. The AWS Encryption SDK returns the context on `CryptoResult` precisely so the caller can assert it; without that assertion the context is authenticated but unchecked, which provides no authorization value.

**Consequence.** Any ciphertext produced under the same CMK decrypts successfully in any other context. The `id=<externalId>` binding — the control that would stop one taxpayer's `facts_cipher_text` from being decrypted as another's — does nothing. A row-swap reached by any means (a restored backup, a data-migration defect, a compromised DB account, an ORM bug) yields a clean decrypt and taxpayer A being served taxpayer B's return. The same holds across services: a state-API authorization token blob and a tax-return facts blob are mutually substitutable.

**Complication for the fix.** The context is currently derived from *who is writing*, not from the record's owner:

```java
try {
    IdentityAttributes identityAttributes = identitySupplier.get();
    encryptionContext.put("id", identityAttributes.externalId().toString());
} catch (NullAuthenticationException e) {
    // this write was triggered by a system event (e.g. sqs message handler)
    encryptionContext.put("system", "DIRECTFILE");
    encryptionContext.put("type", "API");
}
```

A single tax return therefore carries `id=<externalId>` after a user edit and `system=DIRECTFILE` after an SQS-driven write. The context is not stable per record, so validation cannot simply be switched on. The context must first be normalized to something derived from the *record* (the owning `externalId`, plus a purpose discriminator) regardless of which actor triggers the write.

**Recommendation.**
1. Normalize the encryption context to be a property of the record, not the writer.
2. Add a `decrypt(byte[] ciphertext, Map<String,String> expectedContext)` overload that asserts every expected pair is present in `CryptoResult.getEncryptionContext()` and fails closed otherwise; thread the expected context through `FactsEncryptor` / `GenericStringEncryptor` and their callers.
3. Because existing ciphertext carries the old inconsistent context, plan this as a dual-read migration (accept old-or-new during re-encryption, then enforce).

---

## M-1 — Raw TIN and email reach logs under two logback profiles

**Files:**
- `direct-file/backend/src/main/java/gov/irs/directfile/api/user/UserService.java:32`
- `direct-file/backend/src/main/java/gov/irs/directfile/api/audit/AuditService.java:38`
- `direct-file/backend/src/main/resources/logback-local.xml`, `logback-debug.xml`, `logback-minimal.xml`

The taxpayer's TIN is added to the audit event map unmodified:

```java
auditService.addEventProperty(AuditLogElement.USER_TIN, attributes.tin());
```

`AuditService.performLog()` serializes every property in that map as a structured key-value pair (`AuditLogElement.USER_TIN.toString()` → `userTin`). Whether it lands in log output depends entirely on the encoder:

- `logback-minimal.xml` — allowlists exactly three keys (`eventTimestamp`, `eventStatus`, `eventId`). Safe.
- `logback-local.xml` and `logback-debug.xml` — `LogstashEncoder` with **no** `includeKeyValueKeyName` entries, so *all* key-value pairs are serialized, `userTin` and `email` included.
- `logback.xml` — Spring Boot's default pattern appenders, which do not render fluent key-value pairs.

Local development is partly insulated because `FakePIIService` supplies a fixed fake TIN (`123001234`). The real exposure is `logback-debug.xml` — a configuration whose purpose is to be switched on in a deployed environment during troubleshooting, which is exactly when live TINs are flowing.

**Recommendation.** Apply the `includeKeyValueKeyName` allowlist to every encoder rather than opting one in; and stop putting a raw TIN in the audit map at all — log a salted hash or a last-4 fragment, which serves the same correlation purpose.

---

## M-2 — Client-controlled IP headers are trusted unconditionally

**File:** `direct-file/backend/src/main/java/gov/irs/directfile/api/config/IPAddressUtil.java:15`

```java
String trueClientIpHeaderValue = request.getHeader(RequestHeaderNames.TRUE_CLIENT_IP);
if (StringUtils.isNotBlank(trueClientIpHeaderValue)) {
    return trueClientIpHeaderValue.strip();
}
String addr = request.getHeader(RequestHeaderNames.X_FORWARDED_FOR);
...
return getFirstIpAddress(addrs);   // first entry — the client-supplied one
```

There is no trusted-proxy check, and `X-Forwarded-For` is read left-to-right, taking the entry a client can set freely. The returned value is recorded against tax return creation, submission, and signing (`TaxReturnController.create/submit/sign`).

If the edge proxy overwrites both headers this is inert. If it appends — the common default — a caller controls the recorded origin IP for every filing event. For a service whose audit trail supports fraud investigation, that is a meaningful integrity gap.

**Recommendation.** Parse `X-Forwarded-For` right-to-left, discarding entries until the first address that is not a known proxy; accept `True-Client-IP` only when the immediate peer is a trusted edge node. Verify the edge actually strips inbound copies of both headers.

---

## M-3 — State-API authorization codes are not single-use

**File:** `direct-file/state-api/src/main/java/gov/irs/directfile/stateapi/service/StateApiServiceImpl.java:240`

`authorize()` performs two checks — that the requesting state's code matches the code's state, and that `expiresAt` is in the future — and then returns the entity. There is no redemption marker, no delete, and `AuthorizationCodeRepository` exposes only `getByAuthorizationCode`. A code can be exchanged for the taxpayer's full federal return XML repeatedly for its entire lifetime (default 600s).

The surrounding design is otherwise sound: codes are random v4 UUIDs stored SHA-256 hashed (`AuthorizationCode.setAuthorizationCode`), and redemption additionally requires a JWT signed by the state's registered certificate. So this is defense-in-depth rather than a directly exploitable hole — an attacker holding only the code cannot redeem it. It does mean a leaked-and-replayed code is indistinguishable from legitimate use, and there is no server-side record that a code was already spent.

**Recommendation.** Mark codes redeemed atomically (conditional `UPDATE ... WHERE redeemed_at IS NULL RETURNING *`) and reject a second exchange. Consider also requiring `exp` on the client JWT — `NimbusJwtDecoder`'s default validators check `exp` when present but do not require it.

---

## M-4 — Exception messages returned to clients

**File:** `direct-file/backend/src/main/resources/application.yaml:58`

```yaml
include-message: always
```

Spring will include the exception message in the JSON error body. `TaxReturnController.create` funnels unexpected failures through `throw new RuntimeException(e)`, so driver-level, persistence-level, and third-party messages can surface to unauthenticated-adjacent callers.

**Recommendation.** Set `include-message: never` (or `on-param` for non-prod) and return only the curated `StateApiErrorCode` / `TaxReturnApi` codes the application already defines.

---

## M-5 — Signing key committed to the repository

**File:** `direct-file/state-api/src/main/resources/application-development.yaml:6`

```yaml
authorization-token:
  signing-key: GTc+SlI7C7ECPHAhAvIWqn2yAvzAGMVj
```

This is the HMAC key `AuthorizationTokenService` uses to sign state export tokens (`MACSigner`, HS256). It is a development profile, and every other credential in the tree is a LocalStack placeholder (`accessKey`/`secretKey`/`postgres`) — but unlike those, this one is a real 32-byte secret and it is the sole integrity control on the token's claims. Anyone who can cause the `development` profile to load in a reachable environment can mint arbitrary export token claims.

**Recommendation.** Move it to an environment variable with no committed default, rotate it, and add a startup assertion that the key is not the historical literal. A repository-history secret scan for other instances is worth doing at the same time.

---

## Low-severity findings

**L-1 — `MockDataImportController` is not profile-gated.**
`direct-file/backend/src/main/java/gov/irs/directfile/api/taxreturn/MockDataImportController.java:19`. It extends `TaxReturnController`, which carries `@Profile("!mock")`, but declares no `@Profile` of its own. It overrides `getPopulatedData` to take the import profile and date of birth straight from attacker-controllable headers (`x-data-import-profile`, `x-data-import-dob`). Today this is fail-closed: outside the `mock` profile the constructor's unchecked cast `(MockDataImportService) dataImportService` raises `ClassCastException`, and the duplicate inherited `@RequestMapping` would be an ambiguous mapping — the application refuses to start rather than serving mock data. The problem is that the gating is implicit in a cast rather than declared. Add `@Profile("mock")`.

**L-2 — `EmailAllowlistFeatureService` HMAC key is `null`.**
`.../authorization/EmailAllowlistFeatureService.java:37` sets `this.hexKey = null`, and `emailMac()` passes it to `new KeyParameter(hexKey)` — an NPE whenever the allowlist is enabled. This is residue from the key-loading code being stripped for release. Worth confirming the internal version fails closed on a key-load failure; `loadAllowlist()` correctly does (empty set on exception), but `emailMac` throwing from inside `emailOnAllowlist` propagates rather than denying.

**L-3 — Unhandled `StringIndexOutOfBoundsException`.**
`.../stateapi/controller/StateApiController.java` `getStateCode()` does `stateInfo.substring(0, 2)` after only an `isNotBlank` check. A one-character `x-header` throws. Use a length check.

**L-4 — `assert` used for cryptographic length validation.**
`.../stateapi/encryption/Encryptor.java:59-61` validates AES key and IV lengths with `assert`, which the JVM disables unless run with `-ea`. In production these checks do not execute. Use explicit `if (...) throw`.

**L-5 — Platform-default charset for taxpayer data.**
`GenericStringEncryptor` uses `attribute.getBytes()` and `new String(decrypted)` with no charset (the `DM_DEFAULT_ENCODING` SpotBugs warning is suppressed as "Initial Spotbugs Setup"). Non-ASCII names round-trip incorrectly if the encrypting and decrypting JVMs differ in default charset. Specify `StandardCharsets.UTF_8`.

**L-6 — No CSP on the authenticated client.**
`df-client/df-static-site/index.html` ships a detailed `Content-Security-Policy` meta tag; `df-client/df-client-app/index.html` — the app that renders taxpayer data — ships none, and loads Google Tag Manager via an inline bootstrap script. No `dangerouslySetInnerHTML` or other injection sink was found in the app source, so this is hardening rather than an active vulnerability. If CSP is applied at the CDN/edge for this app, confirm it; otherwise port the static site's policy across.

**L-7 — No dependency vulnerability scanning.**
The build is well equipped for static analysis — SpotBugs 4.8.6 with FindSecBugs 1.12.0, PMD, and CycloneDX SBOM generation — but nothing consumes the SBOM. There is no OWASP Dependency-Check, Trivy, or equivalent, and no CI configuration in the repository to run one. Some pins are notably stale relative to Spring Boot 3.3.10: `springdoc 2.1.0` (2023), `jaxb-api 2.3.1` (2018). Specific CVE exposure was not assessed offline and should be established by an actual SCA run rather than assumed.

**L-8 — Test-data hooks in the client bundle.**
`df-client/df-client-app/src/App.tsx:57` reads `?testEmail=` into `sessionStorage.email` and `?generateUUID` into `localStorage.preauthUuid` when `VITE_ALLOW_LOADING_TEST_DATA` is set. The flag appears only in `.env.development`, so this is currently a build-hygiene note: confirm production builds cannot set it, and consider asserting the flag is off at build time.

---

## Reviewed and found sound

Stated explicitly so these areas are not re-reviewed without cause:

- **Object-level authorization.** Every `TaxReturnController` endpoint resolves the caller via `userService.getCurrentUserInfo()` and scopes the lookup — `findByIdAndUserId`, `getStatus(id, userInfo.id())`, `update(..., userInfo.id())`. `TaxReturnRepository` joins through `t.owners` rather than accepting a bare id. No IDOR was found on the tax return surface.
- **SQL injection.** All `@Query` and `nativeQuery` declarations across the backend, state-api, status, and submit services use named parameters. No string concatenation into SQL.
- **XXE.** `XmlProcessor` sets `disallow-doctype-decl=true` and `setXIncludeAware(false)` before parsing, and its inputs are classpath resources rather than user data.
- **XSS.** No `dangerouslySetInnerHTML`, `innerHTML`, `eval`, or `document.write` in `df-client-app` source (the single `innerHTML` hit is in a test file).
- **Cryptographic primitives.** AES-256-GCM with a fresh 12-byte `SecureRandom` IV per operation and a 128-bit tag; RSA `OAEPWITHSHA-256ANDMGF1PADDING`; authorization codes are v4 UUIDs stored SHA-256 hashed. No ECB, no static IVs, no home-rolled constructions.
- **State export authorization chain.** `getAccountId()` reads the account id from an unverified JWT payload, which is the right pattern here: the id is used only to select which state's certificate to load, and the signature is then verified against that certificate (`verifyJwtSignature`), with the resulting state code checked against the authorization code's state (`E_MISMATCHED_STATE_CODE`). A forged account id selects a certificate the attacker cannot sign for.
- **Error-code suppression.** `StateApiController.handleErrors` deliberately collapses `E_CERTIFICATE_NOT_FOUND` and `E_TAX_RETURN_NOT_FOUND` into `E_INTERNAL_SERVER_ERROR` to avoid an enumeration oracle.

## Suggested sequencing

1. **H-1** first — it is the only finding that defeats a control the system already pays for, and the context-normalization work it requires is a prerequisite for any later hardening of at-rest data. It needs a migration plan, so it has the longest lead time.
2. **M-1, M-4** — small, self-contained configuration changes.
3. **M-2, M-3, M-5** — each needs a decision (trusted-proxy topology; redemption semantics; secret management) but limited code.
4. **L-7** — standing up SCA is what turns the dependency-hygiene question from a guess into data.
5. Remaining low findings as cleanup.
