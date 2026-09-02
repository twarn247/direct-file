# Clear the Test Quarantine Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Resolve the last two quarantined client test files, dismantle the now-empty quarantine machinery, and add a guard against the tax-year drift that caused the previous quarantine removal.

**Architecture:** Two unrelated defects, each with a different correct resolution. `apiHelpers.test.ts` asserts a `localStorage`-driven auth-header override whose implementation was stripped for the public release; restoring the behavior would re-introduce the exact hazard L-8 closed, so the test and its orphaned constant are deleted. `flowSnapshots.test.ts` aborts during collection on a dangling symlink, taking 163 present scenarios down with one absent directory; it learns to skip the missing folder. With both passing, the quarantine is empty and its machinery — the exclude glob, the watch script, the guard test, and the CI step — comes out, which is the exit condition it was built with. A fourth, independent task adds the tax-year agreement test that handback #2 of the previous plan asked for.

**Tech Stack:** Vitest 1.6.1, TypeScript, GitHub Actions.

**Spec:** No security-review finding. This closes handbacks #1 and #2 of `docs/superpowers/plans/2026-09-02-hsa-mfj-test-clock-drift.md`, and completes the quarantine introduced in `docs/superpowers/plans/2026-09-01-backend-lows-and-ci-gating.md` Task 4.

## Global Constraints

- **Backtick string literals in TypeScript.** ESLint enforces it repo-wide (`const x = \`value\`;`).
- **`npm run lint` must pass with `--max-warnings=0`.**
- **Run client commands from `direct-file/df-client/df-client-app`.** Dependencies install from the workspace root (`direct-file/df-client`).
- **Tasks 1, 2, and 4 must land in the same pull request.** The `Quarantined tests still fail` CI step (`.github/workflows/ci.yml:341`) inverts its exit code — it fails when a quarantined file *passes*. Tasks 1 and 2 each make one pass, so CI stays red until Task 4 removes them. Task 3 is independent and could ship separately.

---

## Task 1: Delete the test for stripped preauth behavior

**Files:**
- Modify: `direct-file/df-client/df-client-app/src/misc/apiHelpers.test.ts:2,53-64`
- Modify: `direct-file/df-client/df-client-app/src/misc/apiHelpers.ts:40`

**Interfaces:**
- Consumes: nothing from other tasks.
- Produces: a passing `apiHelpers.test.ts`. Task 4 depends on that.

**Why deletion rather than a fix.** The failing test asserts:

```ts
it(`Overrides the ${SM_UNIVERSALID} from localstorage when preauthUuid is set`, () => {
  const preauthUuid = uuidv4();
  localStorage.setItem(`preauthUuid`, preauthUuid);
  const headers = formatAndAppendHeaders({});
  expect(headers).toHaveProperty(SM_UNIVERSALID, preauthUuid);
});
```

`formatAndAppendHeaders` (`apiHelpers.ts:42-62`) never reads `localStorage`. It sets `requestHeaders[SM_UNIVERSALID] = viteSadiAuthId` from the environment and nothing else. `PREAUTH_UUID` is declared at line 40 and referenced by no source file — `grep -rn "PREAUTH_UUID" src/` matches only its own declaration. The implementation was removed for the public release, the same pattern as the nulled HMAC key (L-2), the hardcoded properties, and the dead `address` parameter chain in `TaxReturnService`.

There are two ways to make this test pass, and only one is right. Reinstating the override would make a value in browser `localStorage` set the `SM_UNIVERSALID` authentication header — a client-controlled auth-identity override, which is the same hazard class as the `?generateUUID` → `localStorage.preauthUuid` hook that L-8 and PR #6 closed off with a build-time assertion. **Do not reimplement it.** The test documents behavior that was deliberately removed, so it goes too.

- [ ] **Step 1: Confirm the current state**

```bash
cd direct-file/df-client/df-client-app
npx vitest --run src/misc/apiHelpers.test.ts
grep -rn "PREAUTH_UUID" src/ --include="*.ts" --include="*.tsx"
```

Expected: `Tests 1 failed | 3 passed (4)`, and the grep matching only `src/misc/apiHelpers.ts:40`.

**If the grep matches a source file other than that declaration, stop.** It would mean the override exists somewhere after all, and this task's premise is wrong.

- [ ] **Step 2: Delete the test**

Remove the whole `it(...)` block at `src/misc/apiHelpers.test.ts:53-64`, including the blank line after it.

- [ ] **Step 3: Remove the now-unused import**

`uuidv4` was used only by the deleted test (`grep -n "uuidv4" src/misc/apiHelpers.test.ts` matched lines 2 and 55). Delete line 2:

```ts
import { v4 as uuidv4 } from 'uuid';
```

Leave `localStorage.clear()` in the `beforeEach` at line 41. Nothing sets `localStorage` in this file any more, so it is strictly redundant, but clearing browser state between tests is ordinary hygiene and removing it is churn that would have to be re-added by the next test that touches storage.

- [ ] **Step 4: Remove the orphaned constant**

In `src/misc/apiHelpers.ts`, delete line 40:

```ts
export const PREAUTH_UUID = `preauthUuid`;
```

It is exported, so confirm nothing outside `src/` imports it:

```bash
grep -rn "PREAUTH_UUID" . --include="*.ts" --include="*.tsx" --exclude-dir=node_modules
```

Expected: no matches at all after the deletion.

- [ ] **Step 5: Run the file**

```bash
npx vitest --run src/misc/apiHelpers.test.ts
```

Expected: `Tests 3 passed (3)`.

- [ ] **Step 6: Lint and commit**

```bash
npm run lint
cd ../../..
git add direct-file/df-client/df-client-app/src/misc/apiHelpers.test.ts \
        direct-file/df-client/df-client-app/src/misc/apiHelpers.ts
git commit -m "fix(client): drop the test for preauthUuid header override

The test asserted that a preauthUuid in localStorage overrides the
SM_UNIVERSALID authentication header. formatAndAppendHeaders never reads
localStorage, and PREAUTH_UUID was declared but referenced nowhere -- the
implementation was stripped for the public release.

Deleted rather than reimplemented on purpose. Restoring it would let a
value in browser storage set the auth identity header, the same hazard
as the ?generateUUID -> localStorage.preauthUuid hook that L-8 closed
with a build-time assertion. The orphaned constant goes with it."
```

---

## Task 2: Stop one dangling symlink from taking down 163 scenarios

**Files:**
- Modify: `direct-file/df-client/df-client-app/src/test/scenarioTests/flowSnapshots.test.ts:51-62`

**Interfaces:**
- Consumes: nothing from other tasks.
- Produces: a passing `flowSnapshots.test.ts`. Task 4 depends on that.

**This is not a missing fixture, it is a dangling symlink.** Both scenario folders are git-tracked symlinks into the backend:

```
backend-scenarios     -> ../../../../../backend/src/test/resources/scenarios       163 entries
backend-scenarios-ero -> ../../../../../backend/src/test/resources/scenarios-ero   MISSING
```

`scenarios-ero` (Electronic Return Originator scenarios) is not in this public checkout; the symlink is tracked and points at nothing. `fs.readdirSync(ERO_SCENARIO_FOLDER)` on line 55 throws `ENOENT` **during collection**, before any test is registered, so the entire suite fails to load — including the 163 scenarios that are present and would otherwise run. One absent directory is currently costing the whole file.

The `ero-*.csv` expected-output snapshots in `flow-snapshots/` did ship. Only the inputs were stripped. So a tolerant check means the ERO scenarios resume automatically if the fixtures ever land, with no further change.

`fs.existsSync` follows symlinks, so it returns `false` for a dangling link — exactly the test needed.

- [ ] **Step 1: Confirm the diagnosis**

```bash
cd direct-file/df-client/df-client-app
ls -la src/test/factDictionaryTests/ | grep backend-scenarios
ls ../../backend/src/test/resources/ | grep scenarios
npx vitest --run src/test/scenarioTests/flowSnapshots.test.ts 2>&1 | tail -20
```

Expected: two symlinks; only `scenarios` present in the backend resources; the suite failing with `ENOENT ... scandir './src/test/factDictionaryTests/backend-scenarios-ero'`.

- [ ] **Step 2: Guard the ERO read**

Replace lines 51-62 of `src/test/scenarioTests/flowSnapshots.test.ts`:

```ts
  const SCENARIO_FOLDER = `./src/test/factDictionaryTests/backend-scenarios`;
  const ERO_SCENARIO_FOLDER = `./src/test/factDictionaryTests/backend-scenarios-ero`;
  const FLOW_SNAPSHOTS_FOLDER = `./src/test/scenarioTests/flow-snapshots`;
  const files = fs.readdirSync(SCENARIO_FOLDER);
  const eroFiles = fs.readdirSync(ERO_SCENARIO_FOLDER);
  const jsons = files.filter((f) => f.endsWith(`.json`) && !f.endsWith(`.expected.json`));
  const eroJsons = eroFiles.filter((f) => f.endsWith(`.json`) && !f.endsWith(`.expected.json`));
```

with:

```ts
  const SCENARIO_FOLDER = `./src/test/factDictionaryTests/backend-scenarios`;
  const ERO_SCENARIO_FOLDER = `./src/test/factDictionaryTests/backend-scenarios-ero`;
  const FLOW_SNAPSHOTS_FOLDER = `./src/test/scenarioTests/flow-snapshots`;
  const isScenarioJson = (f: string) => f.endsWith(`.json`) && !f.endsWith(`.expected.json`);

  const jsons = fs.readdirSync(SCENARIO_FOLDER).filter(isScenarioJson);

  // backend-scenarios-ero is a git-tracked symlink to backend/src/test/resources/scenarios-ero,
  // which is not present in this public checkout, so the link dangles. existsSync follows
  // symlinks, so this is false exactly when the target is missing. Reading it unguarded threw
  // ENOENT during collection and took the whole suite down with it -- including the 163 non-ERO
  // scenarios that ARE present. The ero-*.csv expected outputs did ship, so if the fixtures
  // ever land these scenarios start running again with no change here.
  const eroScenariosAvailable = fs.existsSync(ERO_SCENARIO_FOLDER);
  const eroJsons = eroScenariosAvailable ? fs.readdirSync(ERO_SCENARIO_FOLDER).filter(isScenarioJson) : [];
  if (!eroScenariosAvailable) {
    // eslint-disable-next-line no-console
    console.warn(
      `Skipping ERO flow snapshots: ${ERO_SCENARIO_FOLDER} is a dangling symlink (target not in this checkout).`
    );
  }
```

The `scenarioFolders` array below is unchanged — with `eroJsons` empty its `forEach` registers no tests for that folder.

- [ ] **Step 3: Add a guard against silently running nothing**

Skipping a missing folder introduces a new failure mode: if `backend-scenarios` ever dangles too, the suite would pass having run zero scenarios. Add this immediately after the `scenarioFolders.forEach(...)` block, inside the same `describe`:

```ts
  it(`found scenarios to snapshot`, () => {
    // Guards the skip above: a suite that silently runs zero scenarios must not read as green.
    expect(jsons.length).toBeGreaterThan(0);
  });
```

- [ ] **Step 4: Run the file**

```bash
npx vitest --run src/test/scenarioTests/flowSnapshots.test.ts
```

Expected: the suite collects and runs. 163 scenario files are present, so expect on the order of 164 tests (the scenarios plus the new guard) and **zero failures**, with the `Skipping ERO flow snapshots` warning in the output.

**If individual scenarios fail their snapshot comparison, stop and report the list.** Note this suite rewrites the snapshot file on mismatch before asserting (lines 76-82), so a second run would pass having silently overwritten the expected output. Do not re-run to get green — a mismatch here is a real finding about flow ordering, and the rewritten `.csv` files must not be committed.

- [ ] **Step 5: Confirm nothing was rewritten**

```bash
git status --short src/test/scenarioTests/flow-snapshots/
```

Expected: no output. If any `.csv` shows as modified, Step 4 hit a genuine snapshot mismatch — `git checkout` those files and report rather than committing them.

- [ ] **Step 6: Lint and commit**

```bash
npm run lint
cd ../../..
git add direct-file/df-client/df-client-app/src/test/scenarioTests/flowSnapshots.test.ts
git commit -m "fix(client): skip ERO flow snapshots when their fixtures are absent

backend-scenarios-ero is a tracked symlink to
backend/src/test/resources/scenarios-ero, which is not in this public
checkout. readdirSync on the dangling link threw ENOENT during
collection, so the whole suite failed to load and the 163 non-ERO
scenarios never ran at all.

existsSync follows symlinks, so it is false exactly when the target is
missing. The ero-*.csv expected outputs did ship, so the ERO scenarios
resume automatically if the fixtures ever land.

Adds a guard test so a suite that runs zero scenarios cannot read as
green -- the failure mode the skip would otherwise introduce."
```

---

## Task 3: Guard the tax-year constants against drift

**Files:**
- Test: `direct-file/df-client/df-client-app/src/test/taxYearConsistency.test.ts`

**Interfaces:**
- Consumes: nothing from other tasks.
- Produces: nothing other tasks consume. Independent of Tasks 1, 2, and 4.

**Why this exists.** The tax year is written as three independent literals that must move together:

- `src/constants/taxConstants.ts:4` — `` export const CURRENT_TAX_YEAR = `2024`; ``
- `backend/src/main/resources/tax/constants.xml` — `<TaxYear>2024</TaxYear>` inside the `/taxYear` fact
- the same fact's `<Derived><Int>2024</Int></Derived>`

Nothing enforces agreement. This is the drift class that produced the HSA MFJ failure: ages were measured against the fact dictionary's tax year while fixtures were built from the wall clock, and the mismatch surfaced a year later as twenty wrong dollar amounts that read like a tax-calculation bug. A test that fails the moment these three disagree is cheap and catches the next one at the commit that causes it.

The client already reaches the backend XML — `src/fact-dictionary/generate-src/xml-src` is a symlink to `backend/src/main/resources/tax`, and `readRawFacts.ts` reads the dictionary through it at build time. This test uses the same path.

**`constants.xml` contains 18 `<TaxYear>` tags**, one per fact that declares a tax year. The match must be scoped to the `/taxYear` fact's own block or it will read some other fact's value.

- [ ] **Step 1: Write the test**

Create `direct-file/df-client/df-client-app/src/test/taxYearConsistency.test.ts`:

```ts
import { readFileSync } from 'fs';
import { resolve } from 'path';

import { CURRENT_TAX_YEAR } from '../constants/taxConstants.js';

// xml-src is a symlink to backend/src/main/resources/tax -- the same path readRawFacts.ts
// uses to build the fact dictionary.
const CONSTANTS_XML = resolve(__dirname, `../fact-dictionary/generate-src/xml-src/constants.xml`);

describe(`tax year constants`, () => {
  it(`CURRENT_TAX_YEAR agrees with the fact dictionary's /taxYear`, () => {
    // The tax year lives in three independent literals that must be incremented together.
    // Nothing else enforces that, and a mismatch does not fail loudly -- it surfaces later as
    // wrong amounts in facts derived from age or from year-relative thresholds. That is how
    // the HSA MFJ failures happened: fixtures measured against one year, facts against another.
    const xml = readFileSync(CONSTANTS_XML, `utf8`);

    // constants.xml has many <TaxYear> tags, one per fact that declares one. Scope to the
    // /taxYear fact's own block rather than matching the first tag in the file.
    const factBlock = /<Fact path="\/taxYear">([\s\S]*?)<\/Fact>/.exec(xml);
    expect(factBlock, `could not find the /taxYear fact in ${CONSTANTS_XML}`).not.toBeNull();

    const declaredTaxYear = /<TaxYear>(\d{4})<\/TaxYear>/.exec(factBlock![1]);
    const derivedValue = /<Int>(\d{4})<\/Int>/.exec(factBlock![1]);
    expect(declaredTaxYear, `/taxYear has no <TaxYear> tag`).not.toBeNull();
    expect(derivedValue, `/taxYear has no derived <Int> value`).not.toBeNull();

    expect(declaredTaxYear![1]).toBe(CURRENT_TAX_YEAR);
    expect(derivedValue![1]).toBe(CURRENT_TAX_YEAR);
  });
});
```

- [ ] **Step 2: Run it and confirm it passes today**

```bash
cd direct-file/df-client/df-client-app
npx vitest --run src/test/taxYearConsistency.test.ts
```

Expected: `Tests 1 passed (1)`. All three literals are `2024` right now, so a green result is correct here rather than suspicious.

- [ ] **Step 3: Prove the test actually fails on drift**

A guard that cannot fail is worse than none — verify it detects the thing it exists for, then revert.

```bash
sed -i.bak 's/export const CURRENT_TAX_YEAR = `2024`;/export const CURRENT_TAX_YEAR = `2025`;/' src/constants/taxConstants.ts
npx vitest --run src/test/taxYearConsistency.test.ts
```

Expected: FAILS with `expected '2024' to be '2025'`.

Then restore, and confirm the restore is clean:

```bash
mv src/constants/taxConstants.ts.bak src/constants/taxConstants.ts
git diff --exit-code src/constants/taxConstants.ts && echo "restored cleanly"
npx vitest --run src/test/taxYearConsistency.test.ts
```

Expected: `restored cleanly`, then `Tests 1 passed (1)`.

- [ ] **Step 4: Lint and commit**

```bash
npm run lint
cd ../../..
git add direct-file/df-client/df-client-app/src/test/taxYearConsistency.test.ts
git commit -m "test(client): assert the tax year agrees across its three literals

CURRENT_TAX_YEAR in taxConstants.ts, <TaxYear> in the /taxYear fact, and
that fact's derived <Int> must be incremented together, and nothing
enforced it. A mismatch does not fail loudly -- it surfaces later as
wrong amounts in anything derived from age or a year-relative threshold,
which is how the HSA MFJ catch-up failures presented.

Scoped to the /taxYear fact's own block: constants.xml has 18 <TaxYear>
tags and matching the first one would read a different fact.

Closes handback 2 of the HSA clock-drift plan."
```

---

## Task 4: Dismantle the empty quarantine

**Files:**
- Modify: `direct-file/df-client/df-client-app/package.json:71`
- Delete: `direct-file/df-client/df-client-app/src/test/quarantineList.test.ts`
- Modify: `direct-file/df-client/df-client-app/package.json:72` (delete the `test:ci:quarantine-watch` script)
- Modify: `.github/workflows/ci.yml:336-343`
- Modify: `direct-file/README.md` (the CI quarantine section)

**Interfaces:**
- Consumes: passing `apiHelpers.test.ts` (Task 1) and `flowSnapshots.test.ts` (Task 2).
- Produces: a client CI job with no quarantine.

**The quarantine had an exit condition and this is it.** With both files passing, the list is empty, and every remaining piece of the mechanism is either inert or actively wrong:

- `test:ci:quarantine-watch` with no arguments would invoke `vitest run` over the whole suite and invert its exit code — it would fail CI precisely when everything passes.
- `quarantineList.test.ts` would assert an empty list against an exclude glob with no single-file entries.
- The CI step's name, `Quarantined tests still fail (remove from quarantine if this goes red)`, would describe nothing.

Removing it is the right end state rather than leaving an empty frame. If a file ever needs quarantining again, `docs/superpowers/plans/2026-09-01-backend-lows-and-ci-gating.md` Task 4 and this task together are a complete record of how to rebuild it, and rebuilding deliberately is better than inheriting standing permission to quarantine.

- [ ] **Step 1: Remove the single-file exclusions from `test:ci`**

`package.json:71` currently reads:

```json
    "test:ci": "VITEST_MAX_THREADS=4 VITEST_MIN_THREADS=4 vitest --exclude 'src/{test/completenessTests/*,test/functionalFlowTests/*,all-screens/*,misc/apiHelpers.test.ts,test/scenarioTests/flowSnapshots.test.ts}' --run --silent",
```

Drop the two file entries, keeping the three directory globs that separate `test:ci` from `test:ci:2` and `test:ci:3`:

```json
    "test:ci": "VITEST_MAX_THREADS=4 VITEST_MIN_THREADS=4 vitest --exclude 'src/{test/completenessTests/*,test/functionalFlowTests/*,all-screens/*}' --run --silent",
```

- [ ] **Step 2: Delete the watch script**

Delete line 72 of `package.json` entirely:

```json
    "test:ci:quarantine-watch": "vitest run --silent src/misc/apiHelpers.test.ts src/test/scenarioTests/flowSnapshots.test.ts; test $? -ne 0",
```

Check the surrounding JSON still parses — removing a middle entry must not leave a trailing comma:

```bash
cd direct-file/df-client/df-client-app
node -e "JSON.parse(require('fs').readFileSync('package.json','utf8')); console.log('package.json parses')"
```

- [ ] **Step 3: Delete the guard test**

```bash
git rm src/test/quarantineList.test.ts
```

- [ ] **Step 4: Remove the CI step**

In `.github/workflows/ci.yml`, delete the `Quarantined tests still fail (remove from quarantine if this goes red)` step at lines 336-343, including the comment block above it that explains the inverted exit code. Leave the `Test`, `Test (completeness and functional flows)`, and `Test (all screens)` steps and their `if: always()` conditions untouched.

Verify the workflow still parses:

```bash
cd ../../..
python3 -c "import yaml,sys; yaml.safe_load(open('.github/workflows/ci.yml')); print('ci.yml parses')"
```

- [ ] **Step 5: Run the full client suite as CI will**

```bash
cd direct-file/df-client/df-client-app
npm run lint && npm run test:ci && npm run test:ci:2 && npm run test:ci:3
```

Expected: all four green. `test:ci`'s file count should be **two higher** than before this task (both previously-excluded files now run) **minus one** (`quarantineList.test.ts` deleted), plus one if Task 3 landed first (`taxYearConsistency.test.ts`). Confirm `apiHelpers.test.ts` and `flowSnapshots.test.ts` appear in the output rather than reasoning from the count alone.

- [ ] **Step 6: Update the README**

In `direct-file/README.md`, remove the quarantine table and the paragraphs describing the exclusions and the watch step. Replace them with a short record of the outcome:

```markdown
The `Test` step runs the full `df-client-app` suite with no exclusions beyond the three
directory globs that split it from `test:ci:2` and `test:ci:3`.

Three files were quarantined here between 2026-08-31 and 2026-09-02 while their failures were
diagnosed; all three are resolved and the quarantine machinery has been removed.
`hsa.test.ts` was a test fixture deriving ages from the wall clock rather than the tax year.
`apiHelpers.test.ts` asserted a `localStorage` auth-header override whose implementation was
stripped for the public release, and was deleted rather than reinstated. `flowSnapshots.test.ts`
aborted on a dangling `backend-scenarios-ero` symlink and now skips that folder when its target
is absent, which recovered 163 scenarios that were not running at all.
```

Keep the "Reproducing a CI failure locally" block, and drop `test:ci:quarantine-watch` from it if it appears there.

- [ ] **Step 7: Commit**

```bash
cd ../../..
git add direct-file/df-client/df-client-app/package.json \
        .github/workflows/ci.yml \
        direct-file/README.md
git add -u direct-file/df-client/df-client-app/src/test/
git commit -m "ci: remove the test quarantine, now that it is empty

Both remaining files pass, so every part of the mechanism is inert or
wrong: an argument-less quarantine-watch would invert the exit code over
the whole suite and fail CI when everything passes, and the guard test
would assert an empty list against a glob with no file entries.

The quarantine was built with an exit condition. This is it. The
backend-lows plan's Task 4 and this task are a complete record of how to
rebuild one if that is ever needed again.

The client suite now runs with no exclusions beyond the three directory
globs separating test:ci from test:ci:2 and test:ci:3."
```

---

## Handbacks

1. **The ERO scenarios are skipped, not verified.** `backend/src/test/resources/scenarios-ero` is absent from this checkout, so the `ero-*.csv` snapshots in `flow-snapshots/` are unchecked expected-outputs with no inputs. They will start being verified automatically if the fixtures ever land. Until then, nothing confirms the ERO flow ordering is still correct, and no warning about that appears anywhere except this file and the console line the suite prints.

2. **`flowSnapshots.test.ts` rewrites its own expected output on mismatch** (lines 76-82) before asserting, so a failing run leaves modified `.csv` files and a second run passes. That makes an accidental `git add -A` silently bless a flow-ordering regression. It should write to a temp path and diff, or be gated behind an explicit update flag.

3. **Branch protection on `main` is still not applied.** `gh api repos/twarn247/direct-file/branches/main/protection` returns `404 Branch not protected`. It has now been written into two plans and handed over directly once. Handback #4 of `docs/superpowers/plans/2026-09-02-hsa-mfj-test-clock-drift.md` states it *was* applied — **that is wrong** and should be corrected in that document.

4. **The tax-year guard covers three literals, not every year-dependent value.** `constants.xml` has 18 `<TaxYear>` tags and the flow contains other year-relative thresholds. Task 3 asserts only that `/taxYear` agrees with `CURRENT_TAX_YEAR`; a fact declaring a stale `<TaxYear>` of its own would still pass.

5. **The security review is still not on `main`.** It exists only on `origin/claude/report-security-review-lb7lsz` (commit `a6777fe`). Six plans now cite that path as their spec and it resolves for none of them.

6. **The original review's register is fully closed** — H-1, M-1 through M-5, and L-1 through L-8. With the quarantine empty and the client suite fully gating, a fresh review against the current tree rather than the 2025-06-05 snapshot is the natural next substantial piece of work.
