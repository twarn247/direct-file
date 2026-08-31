# Client Hardening and CI Coverage Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Give the authenticated taxpayer application a Content-Security-Policy, make it impossible to ship the test-data hooks in a production bundle, and put the client under CI so both guards actually run.

**Architecture:** Three changes in `df-client`, layered. A CSP `<meta>` tag in `df-client-app/index.html` — placed before the inline analytics bootstrap it must govern — modelled on the policy `df-static-site` already ships. A build-time assertion that `VITE_ALLOW_LOADING_TEST_DATA` is unset for production builds, so the hooks that read query parameters into browser storage cannot reach a real bundle. Then a `client` job in the existing CI workflow running lint and the three vitest suites, which is what keeps the first two from silently regressing.

**Tech Stack:** Vite, React, TypeScript, Vitest, ESLint, Stylelint, Node 18.20.4 (`df-client/.nvmrc`), GitHub Actions.

**Spec:** `docs/security/2026-08-22_codebase-security-review.md` findings L-6 and L-8, plus the client-coverage follow-up named in `docs/superpowers/plans/2026-08-29-ci-pipeline-and-dependency-scanning.md`.

## Global Constraints

- **Node 18.20.4**, pinned in `direct-file/df-client/.nvmrc`. CI must use it.
- **Backtick string literals in TypeScript.** ESLint enforces it repo-wide (`const x = \`value\`;`).
- **`npm run lint` must pass with `--max-warnings=0`** — that is how both lint scripts are already configured.
- **Do not change what Google Tag Manager does.** This plan constrains where scripts may load from; it does not alter analytics behavior. If the policy breaks GTM, the policy changes, not the analytics.
- **`generate-fact-dictionary` is a prerequisite for the test scripts** and is already wired as a `pre` script. It is plain `vite-node` over TypeScript with no backend or Scala dependency, so CI needs no JVM.

## The constraint that shapes Task 1

A CSP delivered by `<meta http-equiv>` is **not** equivalent to one delivered by a response header. Three limits apply, and all three matter here:

1. **No report-only mode.** `Content-Security-Policy-Report-Only` is header-only. There is no way to stage a meta-delivered policy, observe violations, and then enforce — it is enforcing from the moment it merges.
2. **`report-uri` / `report-to` are ignored.** No violation telemetry. If the policy blocks something in production, the signal is a user-visible breakage, not a report.
3. **`frame-ancestors` is ignored.** Clickjacking protection is not achievable this way and still needs an edge header.

Together these mean the only safety net is verification before merge. That is why Task 1 Step 6 is a blocking manual pass rather than a suggestion, and why the handback asks for this to move to an edge header where it can be staged properly.

A second, easily-missed mechanical point: **a meta CSP only governs content the parser encounters after it.** `df-client-app/index.html` currently opens `<head>` with the inline GTM bootstrap. If the meta tag is added below it, the policy will not apply to that script at all — the page will look protected and the one inline script on it will be exempt. The meta tag must be the first element in `<head>`.

## Scope note

**Not in this plan:** the fact-graph's own test suite and Scala.js cross-build (the other follow-up from the CI plan), and `utils/csp-simulator`. Findings L-1 (`MockDataImportController` profile gating), L-2, and L-5 (charset) are backend lows unrelated to the client and are better batched separately.

---

## Task 1: Add a Content-Security-Policy to the client application

**Files:**
- Modify: `direct-file/df-client/df-client-app/index.html`
- Test: `direct-file/df-client/df-client-app/src/test/contentSecurityPolicy.test.ts`

**Interfaces:**
- Consumes: nothing from other tasks.
- Produces: a `<meta http-equiv="Content-Security-Policy">` as the first element of `<head>`, and a test that recomputes the inline script's SHA-256 from the file and asserts the policy still contains it.

**Design note — hash the inline bootstrap rather than allowing `'unsafe-inline'`.** `df-static-site` uses `script-src 'self' 'unsafe-inline' ...`. Copying that here would be consistent but would give up most of what a CSP buys: `'unsafe-inline'` permits any injected inline script, which is the exact class of attack CSP exists to stop, on the app that renders taxpayer data. The inline GTM bootstrap is fixed content, so it can be hashed instead.

The risk is that Google Tag Manager containers frequently inject further inline scripts at runtime (custom HTML tags), which a bootstrap-only hash will not cover. **Step 6 exists to find that out before merge.** If GTM breaks under the hashed policy, fall back to adding `'unsafe-inline'` to `script-src` and record it as a known limitation in the handback — a weaker CSP that ships beats a stronger one that gets reverted.

- [ ] **Step 1: Compute the inline script's hash**

From `direct-file/df-client/df-client-app/`:

```bash
node -e "
const fs = require('fs');
const crypto = require('crypto');
const html = fs.readFileSync('index.html', 'utf8');
const m = html.match(/<script>([\s\S]*?)<\/script>/);
if (!m) { console.error('no inline script found'); process.exit(1); }
const hash = crypto.createHash('sha256').update(m[1], 'utf8').digest('base64');
console.log('sha256-' + hash);
"
```

The hash covers the **exact bytes between the tags**, including leading and trailing whitespace and newlines. Any reformatting — including Prettier touching `index.html` — changes it. That is precisely why Step 5 turns this same computation into a test rather than leaving the value to drift.

Record the output; it goes into the policy in Step 2 as `'sha256-…'` (keep the single quotes).

- [ ] **Step 2: Add the policy as the first element of `<head>`**

In `direct-file/df-client/df-client-app/index.html`, insert immediately after `<head>` and **before** the Google Tag Manager comment and script:

```html
    <!--
      Content-Security-Policy. This must be the FIRST element in <head>: a meta-delivered
      policy only governs content the parser reaches after it, so anything above it -- the
      GTM bootstrap included -- would be exempt.

      Meta delivery cannot express frame-ancestors, report-uri, or report-only; those need
      a response header from the edge. See the handback in
      docs/superpowers/plans/2026-08-31-client-hardening-and-ci.md.

      The inline GTM bootstrap below is allowed by SHA-256 hash rather than by
      'unsafe-inline', so an injected inline script is still blocked. Editing that script
      changes its hash -- src/test/contentSecurityPolicy.test.ts fails until this is
      updated to match.
    -->
    <meta
      http-equiv="Content-Security-Policy"
      content="default-src 'self';
      base-uri 'self';
      object-src 'none';
      form-action 'self';
      script-src 'self' 'sha256-REPLACE_WITH_STEP_1_OUTPUT' https://*.googletagmanager.com https://stage.connect.irs.gov https://connect.irs.gov;
      style-src 'self' 'unsafe-inline' https://stage.connect.irs.gov https://connect.irs.gov;
      style-src-elem 'self' 'unsafe-inline' https://stage.connect.irs.gov https://connect.irs.gov;
      img-src 'self' data: https://*.google-analytics.com https://*.googletagmanager.com;
      font-src 'self' data:;
      connect-src 'self' https://*.google-analytics.com https://*.googletagmanager.com https://stage.connect.irs.gov https://connect.irs.gov;
      frame-src https://*.googletagmanager.com https://stage.connect.irs.gov https://connect.irs.gov;"
    />
```

Replace `REPLACE_WITH_STEP_1_OUTPUT` with the hash from Step 1, keeping the `sha256-` prefix.

Where each directive comes from, so a reviewer can check rather than trust:

| Directive | Why |
|---|---|
| `default-src 'self'` | Matches `df-static-site`. Everything not named below falls back to same-origin. |
| `form-action 'self'` | **Differs from the static site's `'none'` on purpose** — this app submits forms. `'none'` would break it. |
| `script-src` | `'self'` for the Vite bundle, the hash for the GTM bootstrap, `*.googletagmanager.com` for `gtm.js`, eGain domains from `.env.development`. No `'unsafe-inline'` — see the design note. |
| `style-src` / `style-src-elem` | `'unsafe-inline'` is required: USWDS and React inline styles. Same as the static site. |
| `img-src` | `data:` for inlined assets, GA/GTM for tracking pixels. |
| `connect-src` | `'self'` for the backend API (same origin), plus GA/GTM beacons and eGain. |
| `frame-src` | The GTM `<noscript>` iframe in `<body>`, plus eGain chat. |

- [ ] **Step 3: Verify the app builds and starts**

```bash
npm run build
npm run preview
```

Open `http://localhost:3000`. **Expected: the app renders.** If you get a blank page, open the console — a CSP violation names the blocked directive and URL, which tells you exactly what to add.

- [ ] **Step 4: Write the guard test**

Create `direct-file/df-client/df-client-app/src/test/contentSecurityPolicy.test.ts`:

```ts
import { createHash } from 'crypto';
import { readFileSync } from 'fs';
import { resolve } from 'path';

const indexHtml = readFileSync(resolve(__dirname, `../../index.html`), `utf8`);

const cspMatch = indexHtml.match(/http-equiv="Content-Security-Policy"\s*\n?\s*content="([\s\S]*?)"/);

describe(`Content-Security-Policy`, () => {
  it(`is present in index.html`, () => {
    expect(cspMatch).not.toBeNull();
  });

  it(`appears before the first script, so the policy actually governs it`, () => {
    // A meta-delivered CSP only applies to content the parser reaches after it. If the
    // inline GTM bootstrap moves above the meta tag, the policy silently stops covering
    // it and the hash below becomes decorative.
    const cspIndex = indexHtml.indexOf(`Content-Security-Policy`);
    const scriptIndex = indexHtml.indexOf(`<script>`);

    expect(cspIndex).toBeGreaterThan(-1);
    expect(scriptIndex).toBeGreaterThan(-1);
    expect(cspIndex).toBeLessThan(scriptIndex);
  });

  it(`allows the inline bootstrap by its current hash`, () => {
    // Recomputed from the file rather than hardcoded, so editing the inline script
    // without updating the policy fails here instead of in a browser.
    const scriptMatch = indexHtml.match(/<script>([\s\S]*?)<\/script>/);
    expect(scriptMatch).not.toBeNull();

    const hash = createHash(`sha256`)
      .update(scriptMatch![1], `utf8`)
      .digest(`base64`);

    expect(cspMatch![1]).toContain(`sha256-${hash}`);
  });

  it(`does not permit arbitrary inline script`, () => {
    // 'unsafe-inline' in script-src would defeat the main reason this policy exists.
    // If GTM forced it, this test is the place to record that deliberately.
    const scriptSrc = cspMatch![1].match(/script-src([^;]*)/);
    expect(scriptSrc).not.toBeNull();
    expect(scriptSrc![1]).not.toContain(`'unsafe-inline'`);
  });

  it(`keeps object-src and base-uri locked down`, () => {
    expect(cspMatch![1]).toContain(`object-src 'none'`);
    expect(cspMatch![1]).toContain(`base-uri 'self'`);
  });
});
```

- [ ] **Step 5: Run the guard test**

```bash
npx vitest --run src/test/contentSecurityPolicy.test.ts
```

**Expected: PASS.** If the hash assertion fails, the value pasted in Step 2 does not match the file — recompute rather than editing the test.

- [ ] **Step 6: Walk the application against the enforcing policy — blocking**

**Do not skip or shorten this.** There is no report-only mode and no violation telemetry for a meta-delivered policy, so this pass is the only thing standing between a mistake here and a broken production app.

With `npm run preview` running and the browser console open, exercise at minimum:

- [ ] Load the landing page; confirm zero CSP violations in the console
- [ ] Sign in and reach the checklist
- [ ] Walk a section of the interview that renders form inputs
- [ ] Open a modal (`TransferInfoModal` or `StatusInfoModal`)
- [ ] Reach the state-transfer screen (`AuthorizeStateScreen`) and confirm the outbound link renders
- [ ] Trigger the eGain chat widget if it is reachable in this build
- [ ] **Confirm Google Tag Manager still loads** — check the Network tab for `gtm.js` returning 200, and `dataLayer` being defined in the console

Record the result in the PR. If GTM is blocked, add `'unsafe-inline'` to `script-src`, invert the fourth test in Step 4 into an assertion that documents *why* it is present, and say so explicitly in the PR — a documented weaker policy is fine; an undocumented one is not.

Any other violation: add the specific origin to the specific directive. Never widen to `*` or add `'unsafe-inline'` to fix a non-script directive.

- [ ] **Step 7: Lint and commit**

```bash
npm run lint
git add direct-file/df-client/df-client-app/index.html direct-file/df-client/df-client-app/src/test/contentSecurityPolicy.test.ts
git commit -m "feat(client): add a Content-Security-Policy to the taxpayer application

df-static-site shipped a detailed policy; df-client-app -- the app that
renders taxpayer data -- shipped none. Placed first in <head> because a
meta-delivered policy only governs what the parser reaches after it.

The inline GTM bootstrap is allowed by SHA-256 hash rather than
'unsafe-inline', so injected inline script is still blocked. A test
recomputes the hash from the file so an edit cannot silently desync it.

Meta delivery cannot express frame-ancestors, report-uri, or report-only;
moving this to an edge header is a handback item.

Refs L-6."
```

---

## Task 2: Make the test-data hooks impossible to ship

**Files:**
- Modify: `direct-file/df-client/df-client-app/vite.config.ts`
- Test: `direct-file/df-client/df-client-app/src/test/testDataHooks.test.ts`

**Interfaces:**
- Consumes: nothing from other tasks.
- Produces: a Vite build that fails when `VITE_ALLOW_LOADING_TEST_DATA` is truthy in a production build.

**Why this is currently only safe by accident.** `App.tsx:57` reads `?testEmail=` into `sessionStorage.email` and `?generateUUID` into `localStorage.preauthUuid` when `VITE_ALLOW_LOADING_TEST_DATA` is set. The flag appears only in `.env.development`, and there is no `.env.production`, so a `vite build` does not pick it up — but that is a property of which files happen to exist, not a rule. Vite reads `VITE_*` from the process environment too, so a CI variable, a Docker `ENV`, or a shell export would switch these hooks on in a production bundle with nothing to stop it.

- [ ] **Step 1: Confirm the current state**

```bash
cd direct-file/df-client/df-client-app
ls -a | grep "^\.env"
grep -rn "VITE_ALLOW_LOADING_TEST_DATA" . --include="*.env*" --include="*.ts" --include="*.tsx" --include="Dockerfile*" 2>/dev/null | grep -v node_modules
```

**Expected: only `.env.development` and `App.tsx:57`.** If a Dockerfile or CI file also sets it, that is a live exposure rather than a hypothetical, and the PR should say so.

- [ ] **Step 2: Write the failing test**

Create `direct-file/df-client/df-client-app/src/test/testDataHooks.test.ts`:

```ts
import { existsSync, readFileSync } from 'fs';
import { resolve } from 'path';

const appRoot = resolve(__dirname, `../..`);

describe(`test-data loading hooks`, () => {
  it(`is not enabled by any committed production env file`, () => {
    // Vite loads .env.production and .env.production.local for production builds.
    // Neither should exist with this flag set.
    for (const name of [`.env.production`, `.env.production.local`, `.env`]) {
      const path = resolve(appRoot, name);
      if (existsSync(path)) {
        expect(readFileSync(path, `utf8`)).not.toMatch(/^VITE_ALLOW_LOADING_TEST_DATA=(?!false)/m);
      }
    }
  });

  it(`is guarded by a build-time assertion in vite.config.ts`, () => {
    // The hooks read query parameters into browser storage. The only thing keeping them
    // out of a production bundle today is that no .env.production exists -- Vite also
    // reads VITE_* from the process environment, so that is not a guarantee.
    const viteConfig = readFileSync(resolve(appRoot, `vite.config.ts`), `utf8`);

    expect(viteConfig).toContain(`VITE_ALLOW_LOADING_TEST_DATA`);
  });
});
```

- [ ] **Step 3: Run it to verify it fails**

```bash
npx vitest --run src/test/testDataHooks.test.ts
```

Expected: the second test FAILS — `vite.config.ts` does not mention the flag.

- [ ] **Step 4: Add the build-time assertion**

`vite.config.ts` currently ends with `export default defineConfig(configOptions);` — a **static object**, not a factory, and it imports `defineConfig` from `vitest/config` rather than `vite`. `mode` is only available inside a factory, so the default export has to become one. `configOptions` stays exported as-is, because `vite.config.allscreens.ts` imports it.

Change the import line 1 to add `loadEnv` from `vite` (not from `vitest/config`, which does not re-export it):

```ts
import { UserConfig, defineConfig } from 'vitest/config';
import { loadEnv } from 'vite';
```

Then replace the final line, `export default defineConfig(configOptions);`, with:

```ts
export default defineConfig(({ mode }) => {
  // App.tsx reads ?testEmail= and ?generateUUID into sessionStorage/localStorage when
  // this flag is set. Vite resolves VITE_* from .env files AND the process environment,
  // so the absence of a .env.production is not a guarantee -- a CI variable or a Docker
  // ENV would switch these hooks on in a shipped bundle. Fail the build instead.
  const env = loadEnv(mode, process.cwd(), 'VITE_');
  const testDataEnabled = env.VITE_ALLOW_LOADING_TEST_DATA;
  const isTruthy = testDataEnabled !== undefined && testDataEnabled !== '' && testDataEnabled !== 'false';

  if (mode === 'production' && isTruthy) {
    throw new Error(
      `VITE_ALLOW_LOADING_TEST_DATA is set to "${testDataEnabled}" for a production build. ` +
        `These hooks read query parameters into browser storage and must never ship. ` +
        `Unset it, or build with --mode=development.`
    );
  }

  return configOptions;
});
```

Note this file uses single-quoted strings, unlike `src/` — match the file, not the repo-wide `src` convention, or Prettier will rewrite it.

- [ ] **Step 5: Run the test to verify it passes**

```bash
npx vitest --run src/test/testDataHooks.test.ts
```

Expected: PASS.

- [ ] **Step 6: Prove the guard actually fires**

A guard that has never triggered has not been tested:

```bash
VITE_ALLOW_LOADING_TEST_DATA=true npm run build
```

**Expected: the build FAILS with the message above.** Then confirm the normal path still works:

```bash
npm run build          # expected: succeeds
npm run build:development   # expected: succeeds -- development mode is exempt
```

- [ ] **Step 7: Commit**

```bash
npm run lint
git add direct-file/df-client/df-client-app/vite.config.ts direct-file/df-client/df-client-app/src/test/testDataHooks.test.ts
git commit -m "fix(client): fail production builds that enable the test-data hooks

App.tsx reads ?testEmail= and ?generateUUID into browser storage behind
VITE_ALLOW_LOADING_TEST_DATA. That flag lives only in .env.development, but
Vite also resolves VITE_* from the process environment, so a CI variable or
Docker ENV could switch the hooks on in a shipped bundle with nothing to
stop it.

Refs L-8."
```

---

## Task 3: Put the client under CI

Both guards above run only when someone remembers, until this lands.

**Files:**
- Modify: `.github/workflows/ci.yml`

**Interfaces:**
- Consumes: the guard tests from Tasks 1 and 2.
- Produces: a `client` job, independent of `build-and-test` (the client needs no JVM, fact-graph, or Maven).

**Design note.** The `client` job deliberately does not `needs:` the Java job. `generate-fact-dictionary` is plain `vite-node` over TypeScript, so the client has no dependency on the fact-graph artifact or the Maven build — chaining them would serialise two independent pipelines and roughly double wall-clock for no benefit.

Read `.github/workflows/ci.yml` before editing. It was hardened after the original plan — actions are pinned to commit SHAs, permissions are scoped, and fork-PR handling was fixed. **Match those conventions:** pin any new action to a SHA with a trailing `# vX.Y.Z` comment, exactly as the existing steps do.

- [ ] **Step 0: Resolve a SHA for `actions/setup-node`**

The workflow pins every action to a commit SHA. `setup-node` is not used yet, so get one:

```bash
gh api repos/actions/setup-node/git/ref/tags/v4 --jq '.object.sha'
```

If that returns an annotated-tag object rather than a commit, dereference it:

```bash
gh api repos/actions/setup-node/git/tags/<sha-from-above> --jq '.object.sha'
```

Use the resulting commit SHA in place of `SET_ME`, with a trailing `# v4.x.y` comment naming the version — matching the style of `ci.yml:26` and `:29`.

- [ ] **Step 1: Add the client job**

Append to `.github/workflows/ci.yml`:

```yaml
  client:
    name: Lint and test the client
    runs-on: ubuntu-latest
    timeout-minutes: 30
    defaults:
      run:
        working-directory: direct-file/df-client/df-client-app

    steps:
      - uses: actions/checkout@11d5960a326750d5838078e36cf38b85af677262 # v4.4.0

      - name: Set up Node
        uses: actions/setup-node@SET_ME # see Step 0
        with:
          node-version-file: direct-file/df-client/.nvmrc
          cache: npm
          cache-dependency-path: direct-file/df-client/df-client-app/package-lock.json

      - name: Install dependencies
        run: npm ci

      # Both lint scripts run with --max-warnings=0. prelint:ts runs tsc --build, so this
      # also type-checks.
      - name: Lint
        run: npm run lint

      # Three suites because the repository splits them that way: test:ci excludes the
      # completeness, functional-flow, and all-screens directories, which :2 and :3 cover.
      # Running only test:ci would silently skip them.
      - name: Test
        run: npm run test:ci

      - name: Test (completeness and functional flows)
        run: npm run test:ci:2

      - name: Test (all screens)
        run: npm run test:ci:3
```

The `checkout` SHA above is the one already used by the other two jobs (`ci.yml:26`, `:114`), so it is correct as written. `setup-node` is not yet used anywhere in the workflow — resolve and pin it in Step 0 below. Do not introduce an unpinned `@v4` reference into a workflow that was deliberately hardened.

- [ ] **Step 2: Push and watch**

```bash
git add .github/workflows/ci.yml
git commit -m "ci: lint and test the client"
git push
gh run watch
```

**Expect the first run to need iteration.** Likely causes:

- `npm ci` fails on a lockfile/Node mismatch — confirm `.nvmrc` (18.20.4) matches what the lockfile was generated with.
- A suite times out. `test:ci` sets `VITEST_MAX_THREADS=4`; GitHub runners have fewer cores than a laptop, so raise `timeout-minutes` before reducing thread counts.
- `lint` fails on pre-existing warnings. As with the Java side: fix them, do not raise `--max-warnings`.

- [ ] **Step 3: Confirm the new guards ran**

```bash
gh run view --log | grep -E "contentSecurityPolicy|testDataHooks"
```

**Expected: both present and passing.** If absent, they fall outside the `test:ci` include pattern — check the `--exclude` glob in the `test:ci` script and move the files if needed.

- [ ] **Step 4: Prove the client job goes red**

Same discipline as the Java pipeline. Temporarily break the CSP guard:

```bash
# In index.html, add 'unsafe-inline' to script-src.
git commit -am "TEMP: prove CI catches a CSP regression"
git push
gh run watch
```

**Expected: `contentSecurityPolicy.test.ts` fails and the run goes red.** Then revert and record the run link in the PR.

- [ ] **Step 5: Update the CI documentation**

In `direct-file/README.md`, extend the CI section added by the previous plan:

```markdown
**`client`** runs `npm run lint` (ESLint and Stylelint, both at `--max-warnings=0`, with
`tsc --build` via `prelint:ts`) and all three vitest suites for `df-client-app`. It does
not depend on the Java jobs — the client's `generate-fact-dictionary` step is plain
`vite-node` and needs no JVM.

The fact-graph's own test suite and Scala.js cross-build are still not covered.
```

- [ ] **Step 6: Commit and merge**

---

## Verification

- [ ] **All three CI jobs pass on a pull request**

```bash
gh pr checks
```

Expected: `build-and-test`, `dependency-scan`, and `client` all green.

- [ ] **The new guards ran in CI**

```bash
gh run view --log | grep -E "contentSecurityPolicy|testDataHooks"
```

- [ ] **The client job has been proven to go red** (Task 3 Step 4), with the run link in the PR.

- [ ] **The CSP walkthrough was completed and recorded** (Task 1 Step 6), including whether GTM survived the hashed policy.

- [ ] **The production-build guard fires** (Task 2 Step 6):

```bash
cd direct-file/df-client/df-client-app
VITE_ALLOW_LOADING_TEST_DATA=true npm run build   # expected: fails
npm run build                                     # expected: succeeds
```

- [ ] **Change surface**

```bash
git diff --stat origin/main
```

Expected: `.github/workflows/ci.yml`, `direct-file/df-client/df-client-app/{index.html,vite.config.ts}`, two new test files, and `direct-file/README.md`. No backend or `libs` changes.

## Handback to the milestone owner

1. **Move the CSP to an edge response header.** The meta tag is a floor, not a ceiling: it cannot express `frame-ancestors` (so clickjacking protection is still absent), cannot report violations, and cannot be staged in report-only mode. A header at the CDN gets all three, and lets the policy tighten with evidence rather than guesswork.
2. **Confirm whether the edge already sets a CSP.** If it does, this meta tag now composes with it — and CSP composition is intersection, so two policies are strictly more restrictive than either alone. That combination needs checking against the same walkthrough in Task 1 Step 6.
3. **If GTM forced `'unsafe-inline'`** (Task 1 Step 6), the policy is meaningfully weaker than intended. Consider a nonce-based policy via the edge, or moving the GTM bootstrap into a bundled module.
4. **Decide whether the test-data hooks should exist at all.** Task 2 makes them unshippable, which is the safe fix. Deleting `App.tsx:57-68` outright and moving the behavior into test setup would be better, but it touches how developers work locally and is your call, not the implementer's.
5. **Still uncovered by CI:** the fact-graph's test suite and Scala.js cross-build, and `utils/csp-simulator`. A green pipeline does not yet mean the whole repository is tested.
