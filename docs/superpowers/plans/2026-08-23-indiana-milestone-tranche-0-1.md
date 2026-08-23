# Indiana Milestone — Tranche 0 & 1 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Close the code-side security prerequisites that must be complete before Indiana's state profile row goes live, so that onboarding a new export partner does not inherit known weaknesses in the export authorization flow.

**Architecture:** All changes are confined to the `state-api` Spring Boot service, the `df-client` React app's state-transfer screens, and one enum in `libs/data-models`. Nothing changes the export protocol itself — the wire format, the JWT exchange, and the AES-GCM/RSA-OAEP construction are unchanged, so no state partner integration breaks. The work divides into: making state-supplied URLs unable to become script execution or non-TLS navigation (Tasks 1–2), removing a published secret from the trust chain (Task 3), making certificate trust decisions prompt and un-overridable in production (Tasks 4–5), making authorization codes single-use (Task 6), two small robustness fixes (Task 7), and turning state onboarding into a reviewed artifact (Task 8).

**Tech Stack:** Java 21, Spring Boot 3.3.10 (WebFlux + R2DBC), Project Reactor, Liquibase, Maven (`./mvnw`), JUnit 5 + Mockito + `reactor-test` StepVerifier, Spotless with palantir-java-format. Client: React + TypeScript, Vitest, `@testing-library/react`.

**Spec:** `docs/security/2026-08-23_indiana-milestone-security-spec.md`

## Global Constraints

- **Java 21** (`java.version` in `direct-file/boms/irs-spring-boot-starter-parent/pom.xml:19`). Do not use preview features.
- **Format before every commit:** run `./mvnw spotless:apply` from `direct-file/state-api/` for Java changes. CI enforces palantir-java-format 2.39.0; an unformatted commit fails the build.
- **State-api tests run from `direct-file/state-api/`** with `./mvnw test`. Integration tests are gated behind `-DrunIntegrationTests=true` and require Docker (`integrationtest.sh`); the unit tests in this plan do not need it.
- **Client tests run from `direct-file/df-client/df-client-app/`** with `npx vitest --run <path>`.
- **Do not change the export wire protocol.** Response headers (`SESSION-KEY`, `INITIALIZATION-VECTOR`, `AUTHENTICATION-TAG`), the `ExportResponse` body shape, and the `GET /state-api/export-return` contract are consumed by already-onboarded state partners. New error codes are additive and acceptable; changed or removed ones are not.
- **All error codes returned to state partners come from `gov.irs.directfile.error.StateApiErrorCode`.** Never return a raw exception message.
- **Backticks in TypeScript:** this codebase uses backtick string literals nearly everywhere (`const x = \`value\`;`). Match it — ESLint enforces it via `lint:ts`.

## Scope note

Task 8 delivers the *code and document* half of spec finding IN-1 (a reviewed, versioned onboarding artifact plus its checklist). The organizational half — requiring that artifact be used, and who approves it — is a process decision outside what this plan can implement. Task 8 flags it for the owner rather than pretending to solve it.

Spec findings **IN-3**, **IN-4**, and **IN-6** are not in this plan. They are gated on decisions with Indiana DOR (Tranche 2 in the spec) and have no code deliverable until those land. Spec finding **H-1** is Tranche 3 and needs its own plan — it requires a dual-read data migration.

---

## Task 1: Client refuses to navigate to non-HTTPS state URLs

Spec finding IN-5, client half. Four call sites pass a state-supplied string straight to `new URL(...)` and then to `window.location.assign` or an anchor. `new URL('javascript:alert(1)')` parses successfully and navigating to it executes. This task adds one guard and applies it at every site.

**Files:**
- Modify: `direct-file/df-client/df-client-app/src/utils/urlUtils.ts`
- Modify: `direct-file/df-client/df-client-app/src/screens/AuthorizeStateScreen/AuthorizeStateScreen.tsx:258,276`
- Modify: `direct-file/df-client/df-client-app/src/components/StateInfoCard/StateInfoCard.tsx:35`
- Modify: `direct-file/df-client/df-client-app/src/components/StateTaxesButton/StateTaxesButton.tsx:9-13`
- Test: `direct-file/df-client/df-client-app/src/utils/urlUtils.test.ts`

**Interfaces:**
- Consumes: nothing from earlier tasks.
- Produces: `parseHttpsUrl(urlString: string | null | undefined): URL | null` exported from `utils/urlUtils.ts`. Returns a parsed `URL` only when the string parses and its protocol is exactly `https:`; returns `null` otherwise. Task 2 mirrors this rule server-side.

- [ ] **Step 1: Write the failing tests**

Append to `direct-file/df-client/df-client-app/src/utils/urlUtils.test.ts`. Add `parseHttpsUrl` to the existing import on line 1 so it reads:

```ts
import { getTranslatedLink, parseHttpsUrl, urlHasLanguagePlaceholder } from './urlUtils.js';
```

Then add this block inside the existing top-level `describe(\`urlUtils\`, ...)`:

```ts
  describe(`parseHttpsUrl`, () => {
    it(`returns a URL for an https url`, () => {
      const result = parseHttpsUrl(`https://www.in.gov/dor/`);

      expect(result).not.toBeNull();
      expect(result?.protocol).toBe(`https:`);
      expect(result?.host).toBe(`www.in.gov`);
    });

    it(`returns null for a javascript: url`, () => {
      expect(parseHttpsUrl(`javascript:alert(1)`)).toBeNull();
    });

    it(`returns null for a data: url`, () => {
      expect(parseHttpsUrl(`data:text/html,<script>alert(1)</script>`)).toBeNull();
    });

    it(`returns null for an http url`, () => {
      expect(parseHttpsUrl(`http://www.in.gov/dor/`)).toBeNull();
    });

    it(`returns null for an unparseable string`, () => {
      expect(parseHttpsUrl(`not a url`)).toBeNull();
    });

    it(`returns null for null, undefined, and empty string`, () => {
      expect(parseHttpsUrl(null)).toBeNull();
      expect(parseHttpsUrl(undefined)).toBeNull();
      expect(parseHttpsUrl(``)).toBeNull();
    });

    it(`returns a distinct URL object the caller can mutate safely`, () => {
      const result = parseHttpsUrl(`https://www.in.gov/dor/`);
      result?.searchParams.append(`ref`, `df`);

      expect(result?.toString()).toBe(`https://www.in.gov/dor/?ref=df`);
    });
  });
```

- [ ] **Step 2: Run the tests to verify they fail**

Run from `direct-file/df-client/df-client-app/`:

```bash
npx vitest --run src/utils/urlUtils.test.ts
```

Expected: FAIL. The import of `parseHttpsUrl` does not resolve, so every test in the new block errors.

- [ ] **Step 3: Implement `parseHttpsUrl`**

Append to `direct-file/df-client/df-client-app/src/utils/urlUtils.ts`:

```ts
/**
 * Parses a URL supplied by a state partner's profile.
 *
 * State profile URLs (landingUrl, cancel URLs, redirect URLs) arrive from the
 * state-api database and are navigated to or rendered as links inside the
 * authenticated app. `new URL()` alone is not a safety check: it parses
 * `javascript:` and `data:` URLs, and navigating to those executes them.
 *
 * Returns null rather than throwing so callers degrade to not rendering the
 * link, instead of crashing the screen.
 */
export const parseHttpsUrl = (urlString: string | null | undefined): URL | null => {
  if (!urlString) {
    return null;
  }

  let url: URL;
  try {
    url = new URL(urlString);
  } catch {
    return null;
  }

  return url.protocol === `https:` ? url : null;
};
```

- [ ] **Step 4: Run the tests to verify they pass**

```bash
npx vitest --run src/utils/urlUtils.test.ts
```

Expected: PASS, all tests in the file.

- [ ] **Step 5: Commit the helper**

```bash
git add direct-file/df-client/df-client-app/src/utils/urlUtils.ts direct-file/df-client/df-client-app/src/utils/urlUtils.test.ts
git commit -m "feat(client): add parseHttpsUrl guard for state-supplied URLs"
```

- [ ] **Step 6: Apply the guard in `AuthorizeStateScreen`**

In `direct-file/df-client/df-client-app/src/screens/AuthorizeStateScreen/AuthorizeStateScreen.tsx`, add to the existing import block near the top (alongside the other `../../utils/` imports):

```ts
import { parseHttpsUrl } from '../../utils/urlUtils.js';
```

Replace line 258:

```ts
    const cancelUrl = new URL(transferCancelUrl || landingUrl);
```

with:

```ts
    const cancelUrl = parseHttpsUrl(transferCancelUrl) ?? parseHttpsUrl(landingUrl);
    if (cancelUrl === null) {
      // Both the state's cancel URL and its landing URL are unusable. Rather than
      // navigate somewhere unsafe, treat this as a state profile error.
      return <ErrorScreen taxYear={taxYear} />;
    }
```

Replace line 276:

```ts
    const cancelUrl = new URL(waitingForAcceptanceCancelUrl || landingUrl);
```

with:

```ts
    const cancelUrl = parseHttpsUrl(waitingForAcceptanceCancelUrl) ?? parseHttpsUrl(landingUrl);
    if (cancelUrl === null) {
      return <ErrorScreen taxYear={taxYear} />;
    }
```

`ErrorScreen` is already imported in this file (`./ErrorScreen/ErrorScreen.js`). Check its required props before finalizing — if its signature differs from `taxYear`, match the call the file already makes to it elsewhere rather than inventing props.

- [ ] **Step 7: Apply the guard in `StateInfoCard`**

In `direct-file/df-client/df-client-app/src/components/StateInfoCard/StateInfoCard.tsx`, add the import:

```ts
import { parseHttpsUrl } from '../../utils/urlUtils.js';
```

Replace the body of `renderStateProfileInformation` (currently lines 34-50) so the link renders as plain text when the URL is unusable:

```tsx
    const renderStateProfileInformation = (stateProfile: StateProfile) => {
      const landingUrl = parseHttpsUrl(stateProfile.landingUrl);
      if (landingUrl !== null) {
        appendQueryParams(landingUrl);
      }

      return (
        <Translation
          i18nKey={`info.${stateLinki18nKey}`}
          collectionId={null}
          context={context}
          components={{
            StateLink:
              landingUrl === null ? (
                <span>{stateProfile.taxSystemName}</span>
              ) : (
                <CommonLinkRenderer url={landingUrl.toString()}>{stateProfile.taxSystemName}</CommonLinkRenderer>
              ),
          }}
        />
      );
    };
```

- [ ] **Step 8: Apply the guard in `StateTaxesButton`**

In `direct-file/df-client/df-client-app/src/components/StateTaxesButton/StateTaxesButton.tsx`, add the import:

```ts
import { parseHttpsUrl } from '../../utils/urlUtils.js';
```

Replace `addQueryParams` (lines 9-13):

```ts
const addQueryParams = (landingUrl: string): string | null => {
  const asUrl = parseHttpsUrl(landingUrl);
  if (asUrl === null) {
    return null;
  }
  asUrl.searchParams.append(REF_LOCATION, REF_LOCATION_VALUE.SUBMISSION);
  return asUrl.toString();
};
```

Then inside `if (stateProfile) {`, immediately after `const landingUrlWithQueryParams = addQueryParams(landingUrl);`, add:

```ts
    if (landingUrlWithQueryParams === null) {
      return null;
    }
```

The component already returns `null` in its `else` branch, so rendering nothing is an established outcome for this component.

- [ ] **Step 9: Run the full client test suite for the touched areas**

```bash
npx vitest --run src/utils/urlUtils.test.ts src/screens/AuthorizeStateScreen src/components/StateInfoCard src/components/StateTaxesButton
```

Expected: PASS. If an existing test fails because it supplied a non-https URL in a fixture (several fixtures use bare hostnames like `www.directfile.gov/home/`), that is the guard working — update the fixture to a full `https://` URL rather than weakening the guard.

- [ ] **Step 10: Lint and commit**

```bash
npm run lint:ts
git add direct-file/df-client/df-client-app/src/
git commit -m "fix(client): refuse non-https state profile URLs at every navigation site

State profile URLs are database values rendered as links and passed to
window.location.assign. new URL() parses javascript: and data: URLs, so a
bad row was executable script in the authenticated app.

Refs IN-5."
```

---

## Task 2: State-api rejects state profiles carrying non-HTTPS URLs

Spec finding IN-5, server half. Task 1 guards the consumer; this guards the source, so a bad row fails closed regardless of which client reads it.

**Files:**
- Modify: `direct-file/state-api/src/main/java/gov/irs/directfile/stateapi/service/StateApiServiceImpl.java` (the `lookupStateProfile` method, currently at `:384`)
- Test: `direct-file/state-api/src/test/java/gov/irs/directfile/stateapi/service/StateApiServiceImplTest.java`

**Interfaces:**
- Consumes: the `parseHttpsUrl` *rule* from Task 1 (protocol must be exactly `https:`), reimplemented in Java. No code dependency.
- Produces: `lookupStateProfile(String stateCode)` now errors with `StateApiException(E_INTERNAL_SERVER_ERROR)` when any required URL field on the profile is not `https:`. Behavior for valid profiles is unchanged.

**Design note.** `lookupStateProfile` already fails closed on `archived` (`:387-390`), so this follows an established pattern in the same method. Required URL fields (`landingUrl`, `defaultRedirectUrl`) fail the whole lookup — a state whose landing URL is malformed is misconfigured and serving it partially is worse than failing. The `redirectUrls` list is filtered rather than fatal, because it is an allowlist and dropping a bad entry is strictly safer than dropping the whole profile.

- [ ] **Step 1: Write the failing tests**

Add to `direct-file/state-api/src/test/java/gov/irs/directfile/stateapi/service/StateApiServiceImplTest.java`. The file already has `@Mock private CachedDataService cachedDS;` wired via `@InjectMocks` — reuse it, and follow the existing `StepVerifier` style used by the other `lookupStateProfile` tests in this class.

```java
    private StateProfileDTO stateProfileDtoWith(String landingUrl, String defaultRedirectUrl, List<String> redirects) {
        return new StateProfileDTO(
                "IN",
                "INfreefile",
                landingUrl,
                defaultRedirectUrl,
                "https://www.in.gov/dor/",
                "https://www.in.gov/dor/individual-income-taxes/",
                "https://www.in.gov/dor/cancel",
                "https://www.in.gov/dor/cancel",
                redirects,
                Map.of("en", "en"),
                true,
                null,
                false);
    }

    @Test
    public void lookupStateProfile_rejectsJavascriptLandingUrl() {
        StateProfileDTO dto = stateProfileDtoWith(
                "javascript:alert(1)", "https://www.in.gov/dor/redirect", List.of("https://www.in.gov/dor/redirect"));
        when(cachedDS.getStateProfileByStateCode("IN")).thenReturn(Mono.just(dto));

        StepVerifier.create(service.lookupStateProfile("IN"))
                .expectErrorMatches(e -> e instanceof StateApiException sae
                        && sae.getErrorCode() == StateApiErrorCode.E_INTERNAL_SERVER_ERROR)
                .verify();
    }

    @Test
    public void lookupStateProfile_rejectsHttpDefaultRedirectUrl() {
        StateProfileDTO dto = stateProfileDtoWith(
                "https://www.in.gov/dor/", "http://www.in.gov/dor/redirect", List.of("https://www.in.gov/dor/redirect"));
        when(cachedDS.getStateProfileByStateCode("IN")).thenReturn(Mono.just(dto));

        StepVerifier.create(service.lookupStateProfile("IN"))
                .expectErrorMatches(e -> e instanceof StateApiException sae
                        && sae.getErrorCode() == StateApiErrorCode.E_INTERNAL_SERVER_ERROR)
                .verify();
    }

    @Test
    public void lookupStateProfile_dropsNonHttpsRedirectUrlsButKeepsProfile() {
        StateProfileDTO dto = stateProfileDtoWith(
                "https://www.in.gov/dor/",
                "https://www.in.gov/dor/redirect",
                List.of("https://www.in.gov/dor/redirect", "javascript:alert(1)", "http://www.in.gov/dor/other"));
        when(cachedDS.getStateProfileByStateCode("IN")).thenReturn(Mono.just(dto));

        StepVerifier.create(service.lookupStateProfile("IN"))
                .assertNext(result -> assertThat(result.redirectUrls()).containsExactly("https://www.in.gov/dor/redirect"))
                .verifyComplete();
    }

    @Test
    public void lookupStateProfile_acceptsAllHttpsProfile() {
        StateProfileDTO dto = stateProfileDtoWith(
                "https://www.in.gov/dor/", "https://www.in.gov/dor/redirect", List.of("https://www.in.gov/dor/redirect"));
        when(cachedDS.getStateProfileByStateCode("IN")).thenReturn(Mono.just(dto));

        StepVerifier.create(service.lookupStateProfile("IN"))
                .assertNext(result -> assertThat(result.stateCode()).isEqualTo("IN"))
                .verifyComplete();
    }
```

Confirm the `StateProfileDTO` constructor argument order against `direct-file/state-api/src/main/java/gov/irs/directfile/stateapi/dto/StateProfileDTO.java` before running — it is a 13-component record and the compiler will not catch a swap between two `String` fields.

- [ ] **Step 2: Run the tests to verify they fail**

From `direct-file/state-api/`:

```bash
./mvnw test -Dtest=StateApiServiceImplTest
```

Expected: FAIL. The three rejection/filter tests fail because no validation exists yet; `lookupStateProfile_acceptsAllHttpsProfile` passes already.

- [ ] **Step 3: Implement the validation**

In `StateApiServiceImpl.java`, add this private helper next to the other private helpers at the bottom of the class:

```java
    private static boolean isHttpsUrl(String url) {
        if (StringUtils.isBlank(url)) {
            return false;
        }
        try {
            return "https".equalsIgnoreCase(new java.net.URI(url).getScheme());
        } catch (java.net.URISyntaxException e) {
            return false;
        }
    }
```

Then replace the body of `lookupStateProfile` (currently at `:384`):

```java
    @Override
    public Mono<StateProfileDTO> lookupStateProfile(String stateCode) {
        return cachedDS.getStateProfileByStateCode(stateCode).map(dto -> {
            if (dto.archived()) {
                log.error("State {} is archived", stateCode);
                throw new StateApiException(StateApiErrorCode.E_ACCOUNT_ARCHIVED);
            }

            // State profile URLs are rendered as links and navigated to inside the
            // authenticated client. A non-https value (javascript:, data:, http:) is a
            // misconfigured profile; fail closed rather than serve it.
            if (!isHttpsUrl(dto.landingUrl())) {
                log.error("State {} has a non-https landing_url; refusing to serve profile", stateCode);
                throw new StateApiException(StateApiErrorCode.E_INTERNAL_SERVER_ERROR);
            }
            if (!isHttpsUrl(dto.defaultRedirectUrl())) {
                log.error("State {} has a non-https default_redirect_url; refusing to serve profile", stateCode);
                throw new StateApiException(StateApiErrorCode.E_INTERNAL_SERVER_ERROR);
            }

            // The redirect allowlist is filtered rather than fatal: dropping a bad entry
            // is strictly safer than dropping the whole profile.
            List<String> safeRedirects =
                    dto.redirectUrls().stream().filter(StateApiServiceImpl::isHttpsUrl).toList();
            if (safeRedirects.size() != dto.redirectUrls().size()) {
                log.error(
                        "State {} has {} non-https redirect url(s); they were dropped from the allowlist",
                        stateCode,
                        dto.redirectUrls().size() - safeRedirects.size());
            }

            return new StateProfileDTO(
                    dto.stateCode(),
                    dto.taxSystemName(),
                    dto.landingUrl(),
                    dto.defaultRedirectUrl(),
                    dto.departmentOfRevenueUrl(),
                    dto.filingRequirementsUrl(),
                    dto.transferCancelUrl(),
                    dto.waitingForAcceptanceCancelUrl(),
                    safeRedirects,
                    dto.languages(),
                    dto.acceptedOnly(),
                    dto.customFilingDeadline(),
                    dto.archived());
        });
    }
```

Add `import java.util.List;` if the file does not already have it — it currently imports `java.util.HashMap`, `java.util.Map`, and `java.util.UUID` individually.

- [ ] **Step 4: Run the tests to verify they pass**

```bash
./mvnw test -Dtest=StateApiServiceImplTest
```

Expected: PASS, all tests in the class.

- [ ] **Step 5: Format and commit**

```bash
./mvnw spotless:apply
git add direct-file/state-api/src/
git commit -m "fix(state-api): fail closed on non-https state profile URLs

Required URL fields reject the whole profile; the redirect allowlist drops
bad entries. Complements the client-side guard so a bad row is unusable
regardless of which consumer reads it.

Refs IN-5."
```

---

## Task 3: Rotate the state authorization token signing key out of the repository

Spec finding M-5. `application-development.yaml:6` contains a real 32-byte HS256 key, published in a public repository, which is the sole integrity control on state export token claims.

**Files:**
- Modify: `direct-file/state-api/src/main/resources/application-development.yaml:5-6`
- Modify: `direct-file/state-api/src/main/java/gov/irs/directfile/stateapi/authorization/AuthorizationTokenService.java:26-34`
- Test: `direct-file/state-api/src/test/java/gov/irs/directfile/stateapi/authorization/AuthorizationTokenServiceTest.java`

**Interfaces:**
- Consumes: nothing from earlier tasks.
- Produces: `AuthorizationTokenService`'s constructor now throws `IllegalStateException` at bean creation when the signing key is blank, shorter than 32 bytes, or equal to the historical published literal. No method signatures change.

**Operational note for the owner, not the implementer:** this task makes the application refuse to start without a supplied key. Before it merges, confirm the deployment sets `STATE_API_AUTHORIZATION_TOKEN_SIGNING_KEY` in every environment, and confirm the production key has been rotated to a value that was never in git. The startup assertion is the safety net, not the rotation.

- [ ] **Step 1: Write the failing tests**

Add to `direct-file/state-api/src/test/java/gov/irs/directfile/stateapi/authorization/AuthorizationTokenServiceTest.java`:

```java
    private static final String VALID_KEY = "0123456789abcdef0123456789abcdef";
    private static final String PUBLISHED_KEY = "GTc+SlI7C7ECPHAhAvIWqn2yAvzAGMVj";

    @Test
    public void constructor_rejectsBlankSigningKey() {
        assertThrows(
                IllegalStateException.class,
                () -> new AuthorizationTokenService(mock(DataEncryptDecrypt.class), "   ", 600));
    }

    @Test
    public void constructor_rejectsShortSigningKey() {
        assertThrows(
                IllegalStateException.class,
                () -> new AuthorizationTokenService(mock(DataEncryptDecrypt.class), "tooshort", 600));
    }

    @Test
    public void constructor_rejectsThePublishedDevelopmentKey() {
        assertThrows(
                IllegalStateException.class,
                () -> new AuthorizationTokenService(mock(DataEncryptDecrypt.class), PUBLISHED_KEY, 600));
    }

    @Test
    public void constructor_acceptsAValidKey() {
        assertDoesNotThrow(() -> new AuthorizationTokenService(mock(DataEncryptDecrypt.class), VALID_KEY, 600));
    }
```

Add whatever of these imports the file lacks:

```java
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.Mockito.mock;

import gov.irs.directfile.models.encryption.DataEncryptDecrypt;
```

- [ ] **Step 2: Run the tests to verify they fail**

```bash
./mvnw test -Dtest=AuthorizationTokenServiceTest
```

Expected: FAIL on the three rejection tests — the constructor currently accepts anything.

- [ ] **Step 3: Add the startup assertion**

In `AuthorizationTokenService.java`, replace the constructor (`:26-34`):

```java
    /**
     * The HS256 key that signs state export tokens. This value was published in this
     * repository's git history (application-development.yaml). Any deployment still
     * using it must rotate before serving traffic, so the constructor refuses it.
     */
    private static final String PUBLISHED_DEVELOPMENT_KEY = "GTc+SlI7C7ECPHAhAvIWqn2yAvzAGMVj";

    private static final int MIN_SIGNING_KEY_BYTES = 32; // HS256 requires >= 256 bits

    public AuthorizationTokenService(
            DataEncryptDecrypt dataEncryptDecrypt,
            @Value("${authorization-token.signing-key}") String signingKey,
            @Value("${authorization-code.expires-interval-seconds: 600}") int authorizationCodeExpiresInterval) {
        if (signingKey == null || signingKey.isBlank()) {
            throw new IllegalStateException(
                    "authorization-token.signing-key is not set. Set STATE_API_AUTHORIZATION_TOKEN_SIGNING_KEY.");
        }
        if (signingKey.getBytes(StandardCharsets.UTF_8).length < MIN_SIGNING_KEY_BYTES) {
            throw new IllegalStateException("authorization-token.signing-key must be at least "
                    + MIN_SIGNING_KEY_BYTES + " bytes for HS256.");
        }
        if (PUBLISHED_DEVELOPMENT_KEY.equals(signingKey)) {
            throw new IllegalStateException(
                    "authorization-token.signing-key is the key published in this repository's git history. Rotate it.");
        }

        this.dataEncryptDecrypt = dataEncryptDecrypt;
        this.signingKey = signingKey;
        this.authorizationCodeExpiresInterval = authorizationCodeExpiresInterval;
    }
```

Add `import java.nio.charset.StandardCharsets;` to the file.

- [ ] **Step 4: Run the tests to verify they pass**

```bash
./mvnw test -Dtest=AuthorizationTokenServiceTest
```

Expected: PASS.

- [ ] **Step 5: Remove the key from the committed config**

In `direct-file/state-api/src/main/resources/application-development.yaml`, replace:

```yaml
authorization-token:
  signing-key: GTc+SlI7C7ECPHAhAvIWqn2yAvzAGMVj
```

with:

```yaml
authorization-token:
  # No default. Set STATE_API_AUTHORIZATION_TOKEN_SIGNING_KEY (>= 32 bytes).
  # AuthorizationTokenService refuses to start without it.
  signing-key: ${STATE_API_AUTHORIZATION_TOKEN_SIGNING_KEY}
```

- [ ] **Step 6: Confirm the local development path still works**

Local development needs a key supplied from outside the repo. Check `direct-file/docker-compose.yaml` and `direct-file/state-api/localrun.sh` for where state-api's environment is set, and add `STATE_API_AUTHORIZATION_TOKEN_SIGNING_KEY` there with a **freshly generated** value (`openssl rand -hex 16` gives 32 characters) — not the removed literal, or the startup assertion will reject it. If neither file sets state-api environment variables, document the required variable in `direct-file/state-api/README.md` instead.

- [ ] **Step 7: Run the whole state-api suite**

```bash
./mvnw test
```

Expected: PASS. Any Spring context test that loads the `development` profile now needs the variable — if one fails to start, supply the key via `@DynamicPropertySource` in that test, following the pattern in `StateApiAppNoOverrideTest.java:56-60`.

- [ ] **Step 8: Format and commit**

```bash
./mvnw spotless:apply
git add direct-file/state-api/
git commit -m "fix(state-api): remove published signing key, assert on startup

The HS256 key signing state export tokens was committed to a public repo.
Move to an env var with no default and refuse to start on a blank, short,
or published key.

Rotation of the deployed key is an operational step this does not perform.

Refs M-5."
```

---

## Task 4: Refuse to start in production with a certificate override set

Spec finding IN-2, third part. `direct-file.cert-location-override` replaces every state's certificate at once and synthesizes an expiration of `now + 1 year`, bypassing both the certificate's `notAfter` and the IRS-enforced `cert_expiration_date`.

**Files:**
- Create: `direct-file/state-api/src/main/java/gov/irs/directfile/stateapi/configuration/CertificationOverrideGuard.java`
- Test: `direct-file/state-api/src/test/java/gov/irs/directfile/stateapi/configuration/CertificationOverrideGuardTest.java`

**Interfaces:**
- Consumes: `CertificationOverrideProperties.getCertLocationOverride()` (existing, returns `String`).
- Produces: a `@Component` bean whose `@PostConstruct` throws `IllegalStateException` when the override is non-blank and a production profile is active. Nothing else consumes it.

**Design note.** A separate guard bean rather than a check inside `StateApiServiceImpl` — the check is a startup concern, not a request-path concern, and isolating it keeps it independently testable without standing up the service.

- [ ] **Step 1: Confirm the production profile name**

Before writing code, find what the deployed profile is actually called:

```bash
cd /Users/thomaswarn/repo/direct-file
ls direct-file/state-api/src/main/resources/application-*.yaml
grep -rn "SPRING_PROFILES_ACTIVE\|spring.profiles.active" direct-file/docker-compose.yaml direct-file/state-api/ 2>/dev/null | head
```

The repo ships `development`, `docker`, and `debug` profiles; the production profile name is likely supplied by deployment configuration outside this repo. **Use the name you find.** If you cannot determine it, invert the check — fail when the override is set and the active profiles do *not* include one of the known non-production names (`development`, `docker`, `debug`, `test`, `integration-test`). The inverted form fails safe for an unknown profile, which is the behavior you want. The code below uses the inverted form; keep it unless you positively identify the production profile name.

- [ ] **Step 2: Write the failing tests**

Create `direct-file/state-api/src/test/java/gov/irs/directfile/stateapi/configuration/CertificationOverrideGuardTest.java`:

```java
package gov.irs.directfile.stateapi.configuration;

import org.junit.jupiter.api.Test;
import org.springframework.mock.env.MockEnvironment;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertThrows;

public class CertificationOverrideGuardTest {

    private CertificationOverrideGuard guard(String override, String... activeProfiles) {
        MockEnvironment env = new MockEnvironment();
        env.setActiveProfiles(activeProfiles);
        return new CertificationOverrideGuard(new CertificationOverrideProperties(override), env);
    }

    @Test
    public void allowsOverrideInDevelopment() {
        assertDoesNotThrow(() -> guard("fakestate.cer", "development").verifyOverrideNotSetInProduction());
    }

    @Test
    public void allowsOverrideInIntegrationTest() {
        assertDoesNotThrow(
                () -> guard("fakestate.cer", "development", "integration-test").verifyOverrideNotSetInProduction());
    }

    @Test
    public void rejectsOverrideUnderAnUnrecognizedProfile() {
        assertThrows(
                IllegalStateException.class, () -> guard("fakestate.cer", "prod").verifyOverrideNotSetInProduction());
    }

    @Test
    public void rejectsOverrideWithNoActiveProfile() {
        assertThrows(IllegalStateException.class, () -> guard("fakestate.cer").verifyOverrideNotSetInProduction());
    }

    @Test
    public void allowsBlankOverrideAnywhere() {
        assertDoesNotThrow(() -> guard("", "prod").verifyOverrideNotSetInProduction());
        assertDoesNotThrow(() -> guard(null, "prod").verifyOverrideNotSetInProduction());
    }
}
```

- [ ] **Step 3: Run the tests to verify they fail**

```bash
./mvnw test -Dtest=CertificationOverrideGuardTest
```

Expected: FAIL to compile — `CertificationOverrideGuard` does not exist.

- [ ] **Step 4: Implement the guard**

Create `direct-file/state-api/src/main/java/gov/irs/directfile/stateapi/configuration/CertificationOverrideGuard.java`:

```java
package gov.irs.directfile.stateapi.configuration;

import java.util.Arrays;
import java.util.List;

import jakarta.annotation.PostConstruct;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.StringUtils;
import org.springframework.core.env.Environment;
import org.springframework.stereotype.Component;

/**
 * direct-file.cert-location-override replaces the certificate for EVERY state at once
 * and synthesizes an expiration of now + 1 year, bypassing both the certificate's own
 * notAfter and the IRS-enforced cert_expiration_date. It is a lower-environment
 * convenience. This guard refuses to start the application if it is set anywhere the
 * profile is not recognizably non-production.
 */
@Component
@Slf4j
public class CertificationOverrideGuard {

    private static final List<String> NON_PRODUCTION_PROFILES =
            List.of("development", "docker", "debug", "test", "integration-test");

    private final CertificationOverrideProperties properties;
    private final Environment environment;

    public CertificationOverrideGuard(CertificationOverrideProperties properties, Environment environment) {
        this.properties = properties;
        this.environment = environment;
    }

    @PostConstruct
    public void verifyOverrideNotSetInProduction() {
        String override = properties.getCertLocationOverride();
        if (StringUtils.isBlank(override)) {
            return;
        }

        String[] activeProfiles = environment.getActiveProfiles();
        boolean recognisedNonProduction =
                Arrays.stream(activeProfiles).anyMatch(NON_PRODUCTION_PROFILES::contains);

        if (!recognisedNonProduction) {
            throw new IllegalStateException("direct-file.cert-location-override is set (" + override
                    + ") but no non-production profile is active (active: " + Arrays.toString(activeProfiles)
                    + "). This override replaces every state's certificate and bypasses expiration. Refusing to start.");
        }

        log.warn(
                "direct-file.cert-location-override is set to {}. Every state's certificate is overridden and expiration is bypassed. This must never be set in production.",
                override);
    }
}
```

- [ ] **Step 5: Run the tests to verify they pass**

```bash
./mvnw test -Dtest=CertificationOverrideGuardTest
```

Expected: PASS.

- [ ] **Step 6: Run the whole suite**

```bash
./mvnw test
```

Expected: PASS. `StateApiAppNoOverrideTest` sets the override to `""` so it is unaffected; any Spring context test that sets a non-blank override must also activate one of the recognized profiles. `StateApiAppTest` likely does — check its `@ActiveProfiles`.

- [ ] **Step 7: Format and commit**

```bash
./mvnw spotless:apply
git add direct-file/state-api/src/
git commit -m "feat(state-api): refuse to start with cert override outside dev profiles

cert-location-override replaces every state's certificate and fakes a
one-year expiry. Fail closed when no recognized non-production profile is
active.

Refs IN-2."
```

---

## Task 5: Enforce certificate expiration on every access, not only on cache miss

Spec finding IN-2, first part. `CachedDataService:63` carries the comment *"the cert is cached and expiration won't apply during the cache duration"*. Both the certificate's `notAfter` and the IRS-enforced `cert_expiration_date` are evaluated only when the cache misses, so a certificate that expires — or is administratively expired in response to a compromise — keeps working for up to the full TTL (default 120 minutes).

**Files:**
- Create: `direct-file/state-api/src/main/java/gov/irs/directfile/stateapi/service/CertificateLoader.java`
- Modify: `direct-file/state-api/src/main/java/gov/irs/directfile/stateapi/service/CachedDataService.java:53-100`
- Test: `direct-file/state-api/src/test/java/gov/irs/directfile/stateapi/service/CachedDataServiceTest.java`

**Interfaces:**
- Consumes: `StateApiS3Client.getCert(String certName)` returning `Mono<InputStream>` (existing).
- Produces:
  - `CertificateLoader.loadCertificate(String certName): Mono<X509Certificate>` — `@Cacheable(cacheNames = "certificateCache", key = "#certName")`. Parses only; performs no expiry check.
  - `CachedDataService.retrievePublicKeyFromCert(String certName, OffsetDateTime enforcedExpirationDate): Mono<PublicKey>` — signature **unchanged**, so `StateApiServiceImpl:435` needs no edit. Now uncached, and evaluates both expiry checks on every call.

**Design note — read this before implementing.** Spring's `@Cacheable` works through a proxy. Calling a `@Cacheable` method from another method *on the same bean* bypasses the proxy entirely and the cache silently does nothing. That is why the caching moves to a separate `CertificateLoader` bean rather than staying as a second method on `CachedDataService`. Do not collapse them back into one class.

- [ ] **Step 1: Write the failing tests**

Add to `direct-file/state-api/src/test/java/gov/irs/directfile/stateapi/service/CachedDataServiceTest.java`. Read the file's existing setup first and reuse its mocking style and its fixture certificate paths (`src/test/resources/certificates/`).

```java
    @Test
    public void retrievePublicKeyFromCert_rejectsWhenEnforcedDateHasPassed() throws Exception {
        X509Certificate validCert = loadFixtureCertificate("fakestate.cer");
        when(certificateLoader.loadCertificate("fakestate.cer")).thenReturn(Mono.just(validCert));

        OffsetDateTime enforcedInThePast = OffsetDateTime.now(ZoneOffset.UTC).minusDays(1);

        StepVerifier.create(cachedDS.retrievePublicKeyFromCert("fakestate.cer", enforcedInThePast))
                .expectErrorMatches(e -> e instanceof StateApiException sae
                        && sae.getErrorCode() == StateApiErrorCode.E_CERTIFICATE_EXPIRED)
                .verify();
    }

    @Test
    public void retrievePublicKeyFromCert_reevaluatesEnforcedDateOnEveryCall() throws Exception {
        X509Certificate validCert = loadFixtureCertificate("fakestate.cer");
        when(certificateLoader.loadCertificate("fakestate.cer")).thenReturn(Mono.just(validCert));

        OffsetDateTime future = OffsetDateTime.now(ZoneOffset.UTC).plusDays(1);
        OffsetDateTime past = OffsetDateTime.now(ZoneOffset.UTC).minusDays(1);

        // First call succeeds with a future enforced date.
        StepVerifier.create(cachedDS.retrievePublicKeyFromCert("fakestate.cer", future))
                .assertNext(key -> assertThat(key).isNotNull())
                .verifyComplete();

        // Second call with a past enforced date must fail even though the certificate
        // itself is cached. This is the regression this task exists to prevent.
        StepVerifier.create(cachedDS.retrievePublicKeyFromCert("fakestate.cer", past))
                .expectErrorMatches(e -> e instanceof StateApiException sae
                        && sae.getErrorCode() == StateApiErrorCode.E_CERTIFICATE_EXPIRED)
                .verify();
    }

    @Test
    public void retrievePublicKeyFromCert_returnsKeyWhenBothDatesAreInTheFuture() throws Exception {
        X509Certificate validCert = loadFixtureCertificate("fakestate.cer");
        when(certificateLoader.loadCertificate("fakestate.cer")).thenReturn(Mono.just(validCert));

        StepVerifier.create(cachedDS.retrievePublicKeyFromCert(
                        "fakestate.cer", OffsetDateTime.now(ZoneOffset.UTC).plusDays(1)))
                .assertNext(key -> assertThat(key).isNotNull())
                .verifyComplete();
    }
```

Add a fixture helper to the test class:

```java
    private X509Certificate loadFixtureCertificate(String name) throws Exception {
        try (InputStream is = new FileInputStream("src/test/resources/certificates/" + name)) {
            return (X509Certificate) CertificateFactory.getInstance("X.509").generateCertificate(is);
        }
    }
```

The `fakestate.cer` fixture must be unexpired for these tests. `direct-file/state-api/docker/localstack/` ships both `fakestate.cer` and `fakestate_expired.cer`. Check `src/test/resources/certificates/` for what is available and verify with `openssl x509 -enddate -noout -in <path>`. If the only available fixture has expired, use `fakestate_expired.cer` for a `notAfter`-rejection test and generate a fresh self-signed cert for the passing cases:

```bash
openssl req -x509 -newkey rsa:2048 -keyout /tmp/t.key -out src/test/resources/certificates/unexpired.cer \
  -days 3650 -nodes -subj "/CN=test"
```

- [ ] **Step 2: Run the tests to verify they fail**

```bash
./mvnw test -Dtest=CachedDataServiceTest
```

Expected: FAIL to compile — `certificateLoader` is not a field on the test yet and `CertificateLoader` does not exist.

- [ ] **Step 3: Create the `CertificateLoader` bean**

Create `direct-file/state-api/src/main/java/gov/irs/directfile/stateapi/service/CertificateLoader.java`:

```java
package gov.irs.directfile.stateapi.service;

import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;

import lombok.extern.slf4j.Slf4j;
import org.springframework.cache.annotation.Cacheable;
import org.springframework.stereotype.Component;
import reactor.core.publisher.Mono;

import gov.irs.directfile.error.StateApiErrorCode;
import gov.irs.directfile.stateapi.exception.StateApiException;
import gov.irs.directfile.stateapi.repository.StateApiS3Client;

/**
 * Fetches and parses state certificates from S3.
 *
 * Deliberately a separate bean from CachedDataService: @Cacheable works through a
 * Spring proxy, and a self-invocation from another method on the same bean bypasses
 * the proxy and silently disables caching. Keeping the cached parse here lets
 * CachedDataService evaluate expiration on every call while still avoiding an S3
 * round trip per export.
 *
 * This class performs NO expiration checking. That is CachedDataService's job, and it
 * must stay outside the cache.
 */
@Component
@Slf4j
@SuppressWarnings("PMD.PreserveStackTrace")
public class CertificateLoader {

    private final StateApiS3Client s3Client;

    public CertificateLoader(StateApiS3Client s3Client) {
        this.s3Client = s3Client;
    }

    @Cacheable(cacheNames = "certificateCache", key = "#certName")
    public Mono<X509Certificate> loadCertificate(String certName) {
        log.info("enter loadCertificate()...for {}", certName);

        return s3Client.getCert(certName)
                .flatMap(is -> {
                    try {
                        CertificateFactory certFactory = CertificateFactory.getInstance("X.509");
                        return Mono.just((X509Certificate) certFactory.generateCertificate(is));
                    } catch (CertificateException e) {
                        log.error(
                                "loadCertificate failed, {}, {}",
                                e.getClass().getName(),
                                e.getMessage());
                        return Mono.error(new StateApiException(StateApiErrorCode.E_INTERNAL_SERVER_ERROR));
                    }
                })
                .cache(); // required for @Cacheable over a Mono
    }
}
```

- [ ] **Step 4: Rewrite `retrievePublicKeyFromCert` to check expiry outside the cache**

In `CachedDataService.java`, inject the loader by adding a field alongside the existing `@Autowired` fields:

```java
    @Autowired
    private CertificateLoader certificateLoader;
```

Replace the whole `retrievePublicKeyFromCert` method (currently `:63-100`) with:

```java
    /**
     * Resolves a state's public key.
     *
     * The parsed certificate is cached (CertificateLoader); the expiration checks are
     * NOT. Both the certificate's own notAfter and the IRS-enforced expiration date are
     * evaluated on every call, so administratively expiring a compromised certificate
     * takes effect immediately rather than after the cache TTL.
     */
    public Mono<PublicKey> retrievePublicKeyFromCert(String certName, OffsetDateTime enforcedExpirationDate) {
        log.info("enter retrievePublicKeyFromCert()...for {}", certName);

        return certificateLoader.loadCertificate(certName).map(cert -> {
            Date currentDate = new Date();
            if (currentDate.after(cert.getNotAfter())) {
                log.error("The certificate {} has expired", certName);
                throw new StateApiException(StateApiErrorCode.E_CERTIFICATE_EXPIRED);
            }

            if (enforcedExpirationDate != null) {
                OffsetDateTime currentDateTime = OffsetDateTime.now(ZoneOffset.UTC);
                if (currentDateTime.isAfter(enforcedExpirationDate)) {
                    log.error("The certificate {} has passed the IRS enforced expiration date", certName);
                    throw new StateApiException(StateApiErrorCode.E_CERTIFICATE_EXPIRED);
                }
            }

            return cert.getPublicKey();
        });
    }
```

Update the `@CacheEvict` on `emptyCaches()` (`:54-57`) to include the new cache and drop the retired one:

```java
    @CacheEvict(
            value = {"certificateCache", "stateProfileCache"},
            allEntries = true)
    @Scheduled(fixedRateString = "${spring.cache.TTL-minutes}", timeUnit = TimeUnit.MINUTES)
    public void emptyCaches() {
        log.info("caches (certificateCache, stateProfileCache) were evicted after {} minutes", cacheTTL);
    }
```

Remove the now-stale comment on `:63` (`// NOTE: the cert is cached and expiration won't apply during the cache duration`) — the behavior it warned about is what this task fixes.

Then check whether `publicKeyCache` is registered anywhere by name:

```bash
grep -rn "publicKeyCache" direct-file/state-api/src/
```

Update every hit — including `CacheConfiguration.java` and `CachedDataServiceConfigurationTest.java` if they enumerate cache names.

- [ ] **Step 5: Wire the mock into the test class**

In `CachedDataServiceTest.java`, add:

```java
    @Mock
    private CertificateLoader certificateLoader;
```

and confirm it is injected — if the class constructs `CachedDataService` manually rather than via `@InjectMocks`, use `ReflectionTestUtils.setField(cachedDS, "certificateLoader", certificateLoader)`, which this codebase already uses in `StateApiServiceImplTest`.

- [ ] **Step 6: Run the tests to verify they pass**

```bash
./mvnw test -Dtest=CachedDataServiceTest
```

Expected: PASS, including `retrievePublicKeyFromCert_reevaluatesEnforcedDateOnEveryCall`.

- [ ] **Step 7: Run the whole suite**

```bash
./mvnw test
```

Expected: PASS.

- [ ] **Step 8: Format and commit**

```bash
./mvnw spotless:apply
git add direct-file/state-api/src/
git commit -m "fix(state-api): evaluate cert expiration on every access

Cache the parsed certificate, not the expiry decision. Administratively
expiring a compromised state certificate now takes effect immediately
instead of after the 120-minute cache TTL.

Refs IN-2."
```

---

## Task 6: Make authorization codes single-use

Spec finding M-3, and the hard prerequisite for calling IN-4 mitigated. `authorize()` checks the state code and the expiry, then returns the entity — with no redemption marker, a code can be exchanged for the full federal return XML repeatedly for its whole 600-second life.

**Files:**
- Create: `direct-file/state-api/src/main/resources/db/migrations/202608231200-add-redeemed-at-to-authorization-code.yaml`
- Modify: `direct-file/libs/data-models/src/main/java/gov/irs/directfile/error/StateApiErrorCode.java`
- Modify: `direct-file/state-api/src/main/java/gov/irs/directfile/stateapi/model/AuthorizationCode.java`
- Modify: `direct-file/state-api/src/main/java/gov/irs/directfile/stateapi/repository/AuthorizationCodeRepository.java`
- Modify: `direct-file/state-api/src/main/java/gov/irs/directfile/stateapi/service/StateApiServiceImpl.java:241-280` (the `authorize` method)
- Test: `direct-file/state-api/src/test/java/gov/irs/directfile/stateapi/service/StateApiServiceImplTest.java`

**Interfaces:**
- Consumes: `AuthorizationCodeRepository.getByAuthorizationCode(String authDigest)` returning `Mono<AuthorizationCode>` (existing). Note the parameter is the **SHA-256 hex digest**, not the raw UUID — `AuthorizationCode.setAuthorizationCode(UUID)` hashes on assignment.
- Produces:
  - `AuthorizationCodeRepository.markRedeemed(String authDigest): Mono<Integer>` — atomically sets `redeemed_at` where it is currently null; returns rows affected (1 on success, 0 if already redeemed or absent).
  - `StateApiErrorCode.E_AUTHORIZATION_CODE_ALREADY_REDEEMED(HttpStatus.UNAUTHORIZED)` — new constant, additive.
  - `StateApiServiceImpl.authorize(StateAndAuthCode)` — signature unchanged; now errors with the new code on a second exchange.

**Design note.** The redemption must be the atomic step, not a read-then-write. Two concurrent exports presenting the same code must not both succeed, and a `SELECT ... WHERE redeemed_at IS NULL` followed by an `UPDATE` loses that race. The conditional `UPDATE` returning an affected-row count is the whole control — validate first for good error messages, then let the update decide.

- [ ] **Step 1: Write the migration**

Create `direct-file/state-api/src/main/resources/db/migrations/202608231200-add-redeemed-at-to-authorization-code.yaml`, following the shape of the existing migrations in that directory:

```yaml
databaseChangeLog:
  - changeSet:
      id: authorization-code-add-redeemed-at
      author: directfile
      changes:
        - addColumn:
            tableName: authorization_code
            columns:
              - column:
                  name: redeemed_at
                  type: timestamp
                  constraints:
                    nullable: true
      rollback:
        - dropColumn:
            tableName: authorization_code
            columnName: redeemed_at
```

The changelog picks this up automatically — `db/changelog.yaml` uses `includeAll` over `migrations/`, so no registration step is needed.

- [ ] **Step 2: Add the error code**

In `direct-file/libs/data-models/src/main/java/gov/irs/directfile/error/StateApiErrorCode.java`, add after `E_AUTHORIZATION_CODE_EXPIRED`:

```java
    E_AUTHORIZATION_CODE_ALREADY_REDEEMED(HttpStatus.UNAUTHORIZED),
```

This is additive and safe: existing partners never receive it unless they replay.

- [ ] **Step 3: Add the field to the model**

In `direct-file/state-api/src/main/java/gov/irs/directfile/stateapi/model/AuthorizationCode.java`, add after `private Timestamp expiresAt;`:

```java
    private Timestamp redeemedAt;
```

No annotation needed — it is nullable and Lombok's `@Data` generates the accessors.

- [ ] **Step 4: Add the atomic redemption query**

Replace `direct-file/state-api/src/main/java/gov/irs/directfile/stateapi/repository/AuthorizationCodeRepository.java`:

```java
package gov.irs.directfile.stateapi.repository;

import org.springframework.data.r2dbc.repository.Modifying;
import org.springframework.data.r2dbc.repository.Query;
import org.springframework.data.r2dbc.repository.R2dbcRepository;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;
import reactor.core.publisher.Mono;

import gov.irs.directfile.stateapi.model.AuthorizationCode;

@Repository
public interface AuthorizationCodeRepository extends R2dbcRepository<AuthorizationCode, Integer> {
    Mono<AuthorizationCode> getByAuthorizationCode(@Param("authorizationCode") String authDigest);

    /**
     * Atomically marks a code redeemed. Returns the number of rows updated: 1 when this
     * caller won the redemption, 0 when the code was already redeemed or does not exist.
     *
     * The conditional WHERE is the concurrency control — a read-then-write would let two
     * simultaneous exports both succeed.
     */
    @Modifying
    @Query("UPDATE authorization_code SET redeemed_at = now() "
            + "WHERE authorization_code = :authDigest AND redeemed_at IS NULL")
    Mono<Integer> markRedeemed(@Param("authDigest") String authDigest);
}
```

- [ ] **Step 5: Write the failing tests**

Add to `StateApiServiceImplTest.java`. Match the existing `authorize` tests in the class for fixture style — in particular, note that the stored `authorizationCode` field is a hex digest, so build fixtures via `setAuthorizationCode(uuid)` rather than assigning a raw string.

```java
    private AuthorizationCode unexpiredCodeFor(UUID code, String stateCode) {
        AuthorizationCode ac = new AuthorizationCode();
        ac.setAuthorizationCode(code);
        ac.setStateCode(stateCode);
        ac.setTaxYear(2024);
        ac.setTaxReturnUuid(UUID.randomUUID());
        ac.setSubmissionId(SUBMISSION_ID);
        ac.setExpiresAt(Timestamp.from(Instant.now().plusSeconds(600)));
        return ac;
    }

    @Test
    public void authorize_marksCodeRedeemedOnSuccess() {
        UUID code = UUID.randomUUID();
        AuthorizationCode ac = unexpiredCodeFor(code, "IN");
        when(acRepo.getByAuthorizationCode(ac.getAuthorizationCode())).thenReturn(Mono.just(ac));
        when(acRepo.markRedeemed(ac.getAuthorizationCode())).thenReturn(Mono.just(1));

        StepVerifier.create(service.authorize(new StateAndAuthCode(code.toString(), "IN")))
                .assertNext(result -> assertThat(result.getStateCode()).isEqualTo("IN"))
                .verifyComplete();

        Mockito.verify(acRepo).markRedeemed(ac.getAuthorizationCode());
    }

    @Test
    public void authorize_rejectsAlreadyRedeemedCode() {
        UUID code = UUID.randomUUID();
        AuthorizationCode ac = unexpiredCodeFor(code, "IN");
        when(acRepo.getByAuthorizationCode(ac.getAuthorizationCode())).thenReturn(Mono.just(ac));
        // 0 rows updated: another exchange already redeemed it.
        when(acRepo.markRedeemed(ac.getAuthorizationCode())).thenReturn(Mono.just(0));

        StepVerifier.create(service.authorize(new StateAndAuthCode(code.toString(), "IN")))
                .expectErrorMatches(e -> e instanceof StateApiException sae
                        && sae.getErrorCode() == StateApiErrorCode.E_AUTHORIZATION_CODE_ALREADY_REDEEMED)
                .verify();
    }

    @Test
    public void authorize_doesNotRedeemOnStateCodeMismatch() {
        UUID code = UUID.randomUUID();
        AuthorizationCode ac = unexpiredCodeFor(code, "AZ");
        when(acRepo.getByAuthorizationCode(ac.getAuthorizationCode())).thenReturn(Mono.just(ac));

        StepVerifier.create(service.authorize(new StateAndAuthCode(code.toString(), "IN")))
                .expectErrorMatches(e -> e instanceof StateApiException sae
                        && sae.getErrorCode() == StateApiErrorCode.E_MISMATCHED_STATE_CODE)
                .verify();

        Mockito.verify(acRepo, Mockito.never()).markRedeemed(any());
    }

    @Test
    public void authorize_doesNotRedeemAnExpiredCode() {
        UUID code = UUID.randomUUID();
        AuthorizationCode ac = unexpiredCodeFor(code, "IN");
        ac.setExpiresAt(Timestamp.from(Instant.now().minusSeconds(1)));
        when(acRepo.getByAuthorizationCode(ac.getAuthorizationCode())).thenReturn(Mono.just(ac));

        StepVerifier.create(service.authorize(new StateAndAuthCode(code.toString(), "IN")))
                .expectErrorMatches(e -> e instanceof StateApiException sae
                        && sae.getErrorCode() == StateApiErrorCode.E_AUTHORIZATION_CODE_EXPIRED)
                .verify();

        Mockito.verify(acRepo, Mockito.never()).markRedeemed(any());
    }
```

Add `import java.time.Instant;` if absent.

- [ ] **Step 6: Run the tests to verify they fail**

```bash
./mvnw test -Dtest=StateApiServiceImplTest
```

Expected: FAIL — `markRedeemed` is never called and the new error code is never raised.

- [ ] **Step 7: Redeem inside `authorize`**

In `StateApiServiceImpl.java`, replace the `flatMap` body of `authorize` (currently `:257-279`) so redemption is the last step before returning:

```java
        // Returns authorization-code entity if authorizationCode exists and is valid
        // otherwise exception
        return getAuthorizationCode(authorizationCode).flatMap(ac -> {
            // The state code used to generate the authorization code must match the state
            // code associated with the requester's accountId
            String authorizationCodeStateCode = ac.getStateCode();
            String stateProfileStateCode = saCode.getStateCode();
            if (!stateProfileStateCode.equals(authorizationCodeStateCode)) {
                log.error(
                        "authorize() failed, mismatched state code, state_profile state code : {}, authorization_code state code: {}",
                        stateProfileStateCode,
                        authorizationCodeStateCode);
                throw new StateApiException(StateApiErrorCode.E_MISMATCHED_STATE_CODE);
            }

            // The authorization code must not be expired
            Timestamp expiresAt = ac.getExpiresAt();
            if (expiresAt.getTime() < System.currentTimeMillis()) {
                log.error("authorize() failed, authorization code has expired");
                throw new StateApiException(StateApiErrorCode.E_AUTHORIZATION_CODE_EXPIRED);
            }

            // Redeem atomically. The conditional UPDATE is the concurrency control: exactly
            // one caller can observe a row count of 1 for a given code.
            return acRepo.markRedeemed(ac.getAuthorizationCode()).flatMap(rowsUpdated -> {
                if (rowsUpdated == 0) {
                    log.error("authorize() failed, authorization code has already been redeemed");
                    return Mono.error(
                            new StateApiException(StateApiErrorCode.E_AUTHORIZATION_CODE_ALREADY_REDEEMED));
                }
                return Mono.just(ac);
            });
        });
```

- [ ] **Step 8: Run the tests to verify they pass**

```bash
./mvnw test -Dtest=StateApiServiceImplTest
```

Expected: PASS, all four new tests plus the pre-existing ones.

- [ ] **Step 9: Verify the migration applies**

```bash
./mvnw liquibase:update -Dliquibase.url=jdbc:postgresql://localhost:5433/stateapi \
  -Dliquibase.username=postgres -Dliquibase.password=postgres
```

This needs the local Postgres from `docker-compose.yaml` running. If you cannot start it, at minimum confirm the YAML parses by running the full test suite — the Spring context runs Liquibase on startup for integration-profile tests.

Then confirm the rollback works, because an un-rollbackable migration is a deployment hazard:

```bash
./mvnw liquibase:rollback -Dliquibase.rollbackCount=1 \
  -Dliquibase.url=jdbc:postgresql://localhost:5433/stateapi \
  -Dliquibase.username=postgres -Dliquibase.password=postgres
```

Re-apply afterwards.

- [ ] **Step 10: Run the whole suite**

```bash
./mvnw test
```

Expected: PASS. `StateApiControllerTest` and the integration tests exercise the export path — if an integration test replays a code across two test methods, it will now correctly fail on the second. Give each such test its own code rather than relaxing the control.

- [ ] **Step 11: Format and commit**

```bash
./mvnw spotless:apply
git add direct-file/state-api/ direct-file/libs/data-models/
git commit -m "fix(state-api): make authorization codes single-use

Redeem atomically via a conditional UPDATE so a code cannot be exchanged
twice for the federal return XML. Adds redeemed_at and a new
E_AUTHORIZATION_CODE_ALREADY_REDEEMED error code.

This is the prerequisite for treating IN-4 (auth code in the redirect
query string) as mitigated.

Refs M-3."
```

---

## Task 7: Two robustness fixes in the export path

Spec §8, Tranche 0, opportunistic items from the companion review. Both live in files the earlier tasks already touch.

**Files:**
- Modify: `direct-file/state-api/src/main/java/gov/irs/directfile/stateapi/controller/StateApiController.java` (the `getStateCode` method at the bottom of the class)
- Modify: `direct-file/state-api/src/main/java/gov/irs/directfile/stateapi/encryption/Encryptor.java:59-61`
- Test: `direct-file/state-api/src/test/java/gov/irs/directfile/stateapi/controller/StateApiControllerTest.java`
- Test: `direct-file/state-api/src/test/java/gov/irs/directfile/stateapi/encryption/CryptorTest.java`

**Interfaces:**
- Consumes: nothing from earlier tasks.
- Produces: no signature changes. `getStateCode` returns `""` instead of throwing on a short header; `Encryptor.aesGcmEncrypt` throws `IllegalArgumentException` instead of relying on `assert`.

**Why L-4 matters.** `assert` is stripped unless the JVM runs with `-ea`. In production these two cryptographic length checks do not execute at all, so a wrong-length key or IV reaches BouncyCastle as an opaque failure rather than a clear one.

- [ ] **Step 1: Write the failing tests**

Add to `StateApiControllerTest.java`:

```java
    @Test
    public void getStateCode_returnsEmptyForSingleCharacterHeader() {
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.addHeader("x-header", "I");

        assertEquals("", ReflectionTestUtils.invokeMethod(controller, "getStateCode", request));
    }

    @Test
    public void getStateCode_returnsFirstTwoCharacters() {
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.addHeader("x-header", "IN-something");

        assertEquals("IN", ReflectionTestUtils.invokeMethod(controller, "getStateCode", request));
    }
```

Match the class's existing way of obtaining a `controller` instance and its request-mocking style; if it does not already use `MockHttpServletRequest`, add `import org.springframework.mock.web.MockHttpServletRequest;`.

Add to `CryptorTest.java`:

```java
    @Test
    public void aesGcmEncrypt_rejectsWrongKeyLength() {
        byte[] shortKey = new byte[16];
        byte[] iv = new byte[12];

        assertThrows(IllegalArgumentException.class, () -> Encryptor.aesGcmEncrypt("payload", shortKey, iv));
    }

    @Test
    public void aesGcmEncrypt_rejectsWrongIvLength() throws Exception {
        byte[] key = Encryptor.generatePassword();
        byte[] shortIv = new byte[8];

        assertThrows(IllegalArgumentException.class, () -> Encryptor.aesGcmEncrypt("payload", key, shortIv));
    }
```

- [ ] **Step 2: Run the tests to verify they fail**

```bash
./mvnw test -Dtest=StateApiControllerTest+CryptorTest
```

Expected: FAIL. The single-character header raises `StringIndexOutOfBoundsException`; the length tests raise `InvalidCipherTextException` or `IllegalArgumentException` from BouncyCastle rather than from our own guard (and with assertions disabled, may not throw at the expected point at all).

- [ ] **Step 3: Fix `getStateCode`**

In `StateApiController.java`, replace the `getStateCode` method:

```java
    private String getStateCode(HttpServletRequest request) {

        String stateInfo = request.getHeader(X_HEADER);
        if (StringUtils.isBlank(stateInfo) || stateInfo.length() < 2) {
            log.info(X_HEADER + " does not exist, is empty, or is too short to contain a state code");
            return "";
        }
        return stateInfo.substring(0, 2);
    }
```

- [ ] **Step 4: Fix `Encryptor`**

In `Encryptor.java`, replace lines 59-61:

```java
        if (aesKey.length != AES256_GCM_SECRET_LENGTH) {
            throw new IllegalArgumentException("AES 256 secret is not " + AES256_GCM_SECRET_LENGTH + " bytes");
        }
        if (aesIV.length != AES256_GCM_IV_LENGTH) {
            throw new IllegalArgumentException("AES 256 IV is not " + AES256_GCM_IV_LENGTH + " bytes");
        }
```

- [ ] **Step 5: Run the tests to verify they pass**

```bash
./mvnw test -Dtest=StateApiControllerTest+CryptorTest
```

Expected: PASS.

- [ ] **Step 6: Run the whole suite, format, and commit**

```bash
./mvnw test
./mvnw spotless:apply
git add direct-file/state-api/src/
git commit -m "fix(state-api): bound x-header parsing, replace crypto asserts with throws

getStateCode threw on a one-character header. Encryptor validated key and
IV lengths with assert, which is disabled without -ea, so the checks never
ran in production.

Refs L-3, L-4."
```

---

## Task 8: Make state onboarding a reviewed, versioned artifact

Spec finding IN-1, code and document half. Onboarding a state is currently a database data change: no Liquibase changeset in the tree seeds a `state_profile` row, so the values that decide a state's trust anchor never pass through review or CI.

**Files:**
- Create: `direct-file/state-api/src/main/resources/db/migrations/TEMPLATE-onboard-state.yaml.example`
- Create: `docs/security/state-onboarding-checklist.md`
- Modify: `direct-file/state-api/README.md`

**Interfaces:**
- Consumes: the validation from Task 2 (non-https URLs are rejected at read time) and the schema column from Task 6 (`redeemed_at`), so the template must not conflict with either.
- Produces: no code interface. The template is a `.example` file so `includeAll` in `db/changelog.yaml` does not attempt to run it.

**Scope boundary.** This task delivers the artifact and the checklist. Deciding that onboarding *must* go through them, and who approves, is an organizational call for the milestone owner. Step 4 writes that down rather than leaving it implied.

- [ ] **Step 1: Create the onboarding changeset template**

Create `direct-file/state-api/src/main/resources/db/migrations/TEMPLATE-onboard-state.yaml.example`:

```yaml
# Template for onboarding a state partner.
#
# Copy to <YYYYMMDDHHMM>-onboard-<state-code>.yaml, fill in every value, and open a PR.
# Onboarding a state is a security change: these values decide which certificate
# authenticates the state's export requests, whether returns not yet accepted by the
# IRS are exportable, and where the authenticated client navigates taxpayers.
#
# Before merging, complete docs/security/state-onboarding-checklist.md.
#
# The .example extension keeps this file out of db/changelog.yaml's includeAll.
databaseChangeLog:
  - changeSet:
      id: onboard-state-XX
      author: CHANGE-ME
      changes:
        - insert:
            tableName: state_profile
            columns:
              # Selects which certificate verifies this state's JWTs. Must be unique.
              - column: {name: account_id, value: "CHANGE-ME"}
              - column: {name: state_code, value: "XX"}
              - column: {name: tax_system_name, value: "CHANGE-ME"}
              # Every URL below MUST be https. StateApiServiceImpl.lookupStateProfile
              # refuses to serve a profile whose landing_url or default_redirect_url
              # is not, and drops non-https entries from the redirect allowlist.
              - column: {name: landing_url, value: "https://CHANGE-ME"}
              - column: {name: default_redirect_url, value: "https://CHANGE-ME"}
              - column: {name: department_of_revenue_url, value: "https://CHANGE-ME"}
              - column: {name: filing_requirements_url, value: "https://CHANGE-ME"}
              - column: {name: transfer_cancel_url, value: "https://CHANGE-ME"}
              - column: {name: waiting_for_acceptance_cancel_url, value: "https://CHANGE-ME"}
              # false lets returns still PENDING with the IRS be exported. This is a
              # disclosure decision, not a convenience flag. Record the rationale in
              # the PR description.
              - column: {name: accepted_only, valueBoolean: true}
              # S3 object key of the state's X.509 certificate in the cert bucket.
              - column: {name: cert_location, value: "CHANGE-ME.cer"}
              # IRS-enforced expiry. Set SHORTER than the certificate's own notAfter so
              # the IRS can expire it administratively without the state reissuing.
              - column: {name: cert_expiration_date, valueDate: "CHANGE-ME"}
              - column: {name: archived, valueBoolean: false}
        - insert:
            tableName: state_redirect
            columns:
              - column: {name: state_profile_id, valueComputed: "(SELECT id FROM state_profile WHERE state_code = 'XX')"}
              # Exact-match allowlist. determineRedirectUrl compares with string
              # equality, so list every URL the state will redirect to, verbatim.
              - column: {name: redirect_url, value: "https://CHANGE-ME"}
        - insert:
            tableName: state_language
            columns:
              - column: {name: state_profile_id, valueComputed: "(SELECT id FROM state_profile WHERE state_code = 'XX')"}
              - column: {name: df_language_code, value: "en"}
              - column: {name: state_language_code, value: "en"}
      rollback:
        - delete:
            tableName: state_language
            where: "state_profile_id = (SELECT id FROM state_profile WHERE state_code = 'XX')"
        - delete:
            tableName: state_redirect
            where: "state_profile_id = (SELECT id FROM state_profile WHERE state_code = 'XX')"
        - delete:
            tableName: state_profile
            where: "state_code = 'XX'"
```

Verify the column names against the actual schema before committing — read `202310251943-initial_schema.yaml` plus every later migration, since `transfer_cancel_url`, `waiting_for_acceptance_cancel_url`, `department_of_revenue_url`, `filing_requirements_url`, `custom_filing_deadline`, and `archived` were each added by a separate changeset and the exact names matter.

- [ ] **Step 2: Write the onboarding checklist**

Create `docs/security/state-onboarding-checklist.md` by lifting §6 of `docs/security/2026-08-23_indiana-milestone-security-spec.md` verbatim, with a short preamble:

```markdown
# State Onboarding Security Checklist

Complete before merging a state onboarding changeset
(`db/migrations/<date>-onboard-<state-code>.yaml`). Derived from
`docs/security/2026-08-23_indiana-milestone-security-spec.md` §6.

Attach the completed checklist to the onboarding PR.
```

Then copy the checklist body across unchanged, so the two documents cannot drift into disagreement about what is required.

- [ ] **Step 3: Document the process in the state-api README**

Add a section to `direct-file/state-api/README.md`:

```markdown
## Onboarding a state partner

State profiles are **not** ad-hoc database inserts. Onboarding a state changes which
certificate authenticates that state's export requests, whether returns not yet
accepted by the IRS are exportable, and where the authenticated client navigates
taxpayers — so it goes through review like any code change.

1. Copy `src/main/resources/db/migrations/TEMPLATE-onboard-state.yaml.example` to
   `src/main/resources/db/migrations/<YYYYMMDDHHMM>-onboard-<state-code>.yaml`.
2. Fill in every `CHANGE-ME`. All URLs must be `https`.
3. Upload the state's X.509 certificate to the cert bucket at the `cert_location` key.
4. Complete `docs/security/state-onboarding-checklist.md` and attach it to the PR.
5. Get review from someone other than the author.

To take a state offline, set `archived = true` — both profile lookup paths fail closed
with `E_ACCOUNT_ARCHIVED`.
```

- [ ] **Step 4: Record the open organizational decision**

Append to `docs/security/state-onboarding-checklist.md`:

```markdown
## Open decision for the milestone owner

This checklist and the changeset template make a reviewed onboarding path *available*.
They do not make it *mandatory* — nothing prevents a direct database insert that skips
both.

Two questions need an owner:

1. Who approves a state onboarding PR, and does it need security review specifically?
2. What prevents or detects an onboarding that bypasses this path — a database
   permission boundary, an audit alert on `state_profile` writes, or a periodic
   reconciliation of live rows against merged changesets?

Until (2) is answered, the control is a convention rather than an enforcement.
```

- [ ] **Step 5: Verify the template does not run**

```bash
cd /Users/thomaswarn/repo/direct-file/direct-file/state-api
./mvnw test
```

Expected: PASS. `db/changelog.yaml` uses `includeAll` over `migrations/`, which by default only picks up files Liquibase recognizes — the `.example` extension keeps the template out. If the suite fails with a Liquibase parse error naming the template, move it to `direct-file/state-api/docs/` instead and update the README path in Step 3.

- [ ] **Step 6: Commit**

```bash
git add direct-file/state-api/ docs/security/state-onboarding-checklist.md
git commit -m "docs(state-api): make state onboarding a reviewed, versioned artifact

Adds a Liquibase changeset template, a security checklist, and README
process docs, so onboarding a state goes through review instead of being
an ad-hoc database insert.

Whether the path is mandatory is an open organizational decision, recorded
in the checklist.

Refs IN-1."
```

---

## Verification

After all tasks, confirm the whole thing holds together.

- [ ] **Full state-api suite**

```bash
cd /Users/thomaswarn/repo/direct-file/direct-file/state-api
./mvnw clean test
```

Expected: PASS, zero failures.

- [ ] **Full client suite for touched areas**

```bash
cd /Users/thomaswarn/repo/direct-file/direct-file/df-client/df-client-app
npx vitest --run src/utils src/screens/AuthorizeStateScreen src/components/StateInfoCard src/components/StateTaxesButton
npm run lint:ts
```

Expected: PASS.

- [ ] **Integration tests**, if Docker is available

```bash
cd /Users/thomaswarn/repo/direct-file/direct-file/state-api
./integrationtest.sh
```

Expected: PASS. These exercise the real export path end to end and are the strongest check that Task 5 and Task 6 did not break the protocol. If a test replays an authorization code, that test needs its own code now — fix the test, not the control.

- [ ] **Confirm the spec's Tranche 0 and Tranche 1 items are all closed**

Re-read §8 of `docs/security/2026-08-23_indiana-milestone-security-spec.md` and confirm: IN-5 (Tasks 1–2), M-5 (Task 3), L-3 and L-4 (Task 7), IN-1 (Task 8), M-3 (Task 6), IN-2 (Tasks 4–5). H-1 remains open by design — it is Tranche 3 and needs its own plan.

- [ ] **Hand back the operational items this plan cannot perform**

State explicitly to the milestone owner:
1. The production signing key must be rotated to a value never committed (Task 3 asserts, it does not rotate).
2. `STATE_API_AUTHORIZATION_TOKEN_SIGNING_KEY` must be set in every deployed environment or state-api will not start.
3. The production profile name should be confirmed against Task 4's inverted check.
4. A revocation SLA with Indiana still needs agreeing — Task 5 makes revocation prompt, it does not define how fast the IRS must act.
