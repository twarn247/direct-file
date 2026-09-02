# HSA MFJ Clock-Drift Fix and Quarantine Removal Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Fix the wall-clock dependency that makes `hsa.test.ts`'s MFJ block fail, remove the file from the CI quarantine, and correct the record that called this a tax-calculation defect.

**Architecture:** One root cause, three consequences. The MFJ test block derives dates of birth from `new Date()` while the fact graph evaluates age at the end of a fixed tax year, so every age in the table drifts down by one per calendar year. Replacing the wall-clock arithmetic with a helper anchored to `CURRENT_TAX_YEAR` fixes all 20 assertions. That makes the file pass, which trips the quarantine-watch step (it fails CI when a quarantined file starts passing), so removal from all four quarantine locations happens in the same change. Finally the README and PR #6 comment describe this as wrong tax math, which it is not, and that has to be corrected where people will read it.

**Tech Stack:** Vitest 1.6.1, TypeScript, the Direct File fact graph (Scala.js), GitHub Actions.

**Spec:** No security-review finding. This originates from the CI quarantine decision in `docs/superpowers/plans/2026-09-01-backend-lows-and-ci-gating.md` Task 4 and its first handback, and from the diagnosis recorded below.

## Global Constraints

- **Backtick string literals in TypeScript.** ESLint enforces it repo-wide (`const x = \`value\`;`).
- **`npm run lint` must pass with `--max-warnings=0`.**
- **`/taxYear` is fixed at 2024** (`direct-file/backend/src/main/resources/tax/constants.xml:39`) and `CURRENT_TAX_YEAR` is `` `2024` `` (`src/constants/taxConstants.ts:4`). Both must move together when the tax year is incremented; this plan makes the test depend on the client-side constant.
- **Run client commands from `direct-file/df-client/df-client-app`.** Dependencies install from the workspace root (`direct-file/df-client`), not from the app subdirectory.

---

## The diagnosis, in full

This is recorded here because the existing written record is wrong and an executor will otherwise re-derive it.

`/filers/*/additionToHsaContributionLimit` (Form 8889 line 7, `backend/src/main/resources/tax/hsa.xml:1848`) grants the $1,000 catch-up only when all four of these hold:

```
../wasEligibleToMakeHsaContributionsAllYear
../age55OrOlder            (module: filers)
../isCoveredByFamilyHdhp
/isMarried                 (module: filers)
```

Instrumenting the graph for the MFJ "Filer over 55, spouse under 55" case showed three of the four true and **`age55OrOlder` false for the 56-year-old filer**:

```
PRIMARY(56) age55OrOlder                  :: complete=true value=false
PRIMARY(56) wasEligibleAllYear            :: complete=true value=true
PRIMARY(56) isCoveredByFamilyHdhp         :: complete=true value=true
PRIMARY(56) hasMadeContributionsToHsa     :: complete=true value=true
PRIMARY(56) additionToHsaContributionLimit:: complete=true value=0.00
GLOBAL      isMarried                     :: complete=true value=true
```

`/filers/*/age55OrOlder` (`backend/src/main/resources/tax/filers.xml:674`) is `age >= 55`, and its description is explicit: *"Whether the filer is 55 or older **at the end of their tax year**."* The tax year is 2024.

The MFJ block (`src/test/factDictionaryTests/hsa.test.ts:623-627`) builds each date of birth from the wall clock:

```ts
const primaryFilerDob = new Date();
primaryFilerDob.setFullYear(primaryFilerDob.getFullYear() - testCase.filerAge);
```

Run on 2026-09-02 with `filerAge: 56` that yields a DOB of `1970-09-02`, whose age at 2024-12-31 is **54**. Every age in the table is effectively reduced by `currentYear − 2024`. When these tests were written in 2025 the drift was 1, so `56` still landed on exactly 55 and they passed; in 2026 the drift is 2, every "over 55" party falls under the threshold, all catch-ups become `0.00`, and the line 6 allocation, line 8 totals, and line 12 amounts cascade from there. That single cause accounts for all 20 assertions.

Changing only the DOB to a fixed `1957-06-06` — nothing else — flips `age55OrOlder` to `true` and `additionToHsaContributionLimit` to `1000.00`, exactly what the test expects.

**The fact dictionary is correct. The test rotted against the wall clock.** The single- and MFS-filer blocks pass because their fixtures hardcode `` createDayWrapper(`1957-06-06`) `` (`hsa.test.ts:47,59`), which is why only MFJ broke.

**Confirmed not a second defect:** the dictionary grants the catch-up on line 7 only for married filers, and folds it into line 3 otherwise — `hsa.test.ts:250-258` asserts a single 55+ filer with family coverage gets line 3 `9300.00` and line 7 `0.00`, and it passes. That mirrors Form 8889's own structure: the family limit is divided between spouses on line 6, so the per-person catch-up has to be added back on line 7 where it cannot be divided. Do not "fix" this.

**Scope of the pattern:** `grep -rn "setFullYear(.*getFullYear() -" src/` matches only `hsa.test.ts:625,627`. The two other `new Date()` uses in tests (`functionalFlowTests/aboutYou.test.ts:43`, `FlowRender.test.tsx:27`) are `createdAt` timestamps that cross no threshold. No other file has this defect today; Task 1 adds the helper that keeps it that way.

---

## Task 1: Anchor the MFJ ages to the tax year

**Files:**
- Modify: `direct-file/df-client/df-client-app/src/test/testData.ts`
- Modify: `direct-file/df-client/df-client-app/src/test/factDictionaryTests/hsa.test.ts:622-627`

**Interfaces:**
- Consumes: nothing from other tasks.
- Produces: `dateOfBirthForAgeAtEndOfTaxYear(age: number): string` exported from `src/test/testData.ts`, returning a `YYYY-MM-DD` string. Task 2 depends on this task having made `hsa.test.ts` pass.

**Why a shared helper rather than inlining the arithmetic.** Inlining fixes today's failure and leaves the next author to rediscover that "age" in this codebase means age at the end of the tax year, not age now. The helper puts the rule in one named place, and `grep` for it is how a reviewer checks that a new age-dependent fixture got it right.

- [ ] **Step 1: Confirm the current failure**

```bash
cd direct-file/df-client/df-client-app
npx vitest --run src/test/factDictionaryTests/hsa.test.ts
```

Expected: `Tests 20 failed | 103 passed (123)`, every failure under `HSA Contributions and Coverage > For MFJ TPs`.

If the counts differ, stop and report. In particular, **if this now passes, the calendar has moved and the drift has changed** — re-derive the diagnosis above before continuing, because the numbers in it are dated 2026-09-02.

- [ ] **Step 2: Add the helper**

`direct-file/df-client/df-client-app/src/test/testData.ts` **already imports the constant** at line 18:

```ts
import { CURRENT_TAX_YEAR } from '../constants/taxConstants.js';
```

so no new import is needed. Add the helper as a new export:

```ts
/**
 * A date of birth for a filer who is exactly `age` at the END OF THE TAX YEAR, which is what
 * /filers/*\/age and every threshold built on it (age55OrOlder, age65OrOlder) actually measure.
 *
 * Do not build ages from `new Date()`. The tax year is fixed while the wall clock is not, so
 * wall-clock arithmetic silently reduces every age by one per calendar year and fixtures drift
 * across thresholds long after they were written. That is exactly how the MFJ block of
 * hsa.test.ts came to fail: ages written as 56 evaluated as 54 two years later.
 *
 * June 6 is arbitrary but safely before December 31, so the birthday has always occurred by the
 * end of the tax year.
 */
export const dateOfBirthForAgeAtEndOfTaxYear = (age: number): string =>
  `${parseInt(CURRENT_TAX_YEAR) - age}-06-06`;
```

`CURRENT_TAX_YEAR` is a template-literal string (`` `2024` ``), hence the `parseInt`.

- [ ] **Step 3: Use it in the MFJ block**

In `src/test/factDictionaryTests/hsa.test.ts`, add `dateOfBirthForAgeAtEndOfTaxYear` to the existing import block from `'../testData.js'` (the one at lines 12-31).

Then replace lines 623-627:

```ts
          // setup the test data
          const primaryFilerDob = new Date();
          primaryFilerDob.setFullYear(primaryFilerDob.getFullYear() - testCase.filerAge);
          const spouseDob = new Date();
          spouseDob.setFullYear(spouseDob.getFullYear() - testCase.spouseAge);
```

with:

```ts
          // setup the test data. Ages are measured at the end of the tax year, not today --
          // see dateOfBirthForAgeAtEndOfTaxYear.
          const primaryFilerDob = dateOfBirthForAgeAtEndOfTaxYear(testCase.filerAge);
          const spouseDob = dateOfBirthForAgeAtEndOfTaxYear(testCase.spouseAge);
```

The two call sites that consumed these values (lines 632-633) currently read:

```ts
            [`/filers/#${primaryFilerId}/dateOfBirth`]: createDayWrapper(primaryFilerDob.toISOString().split(`T`)[0]),
            [`/filers/#${spouseId}/dateOfBirth`]: createDayWrapper(spouseDob.toISOString().split(`T`)[0]),
```

The helper already returns a `YYYY-MM-DD` string, so drop the `.toISOString().split(...)`:

```ts
            [`/filers/#${primaryFilerId}/dateOfBirth`]: createDayWrapper(primaryFilerDob),
            [`/filers/#${spouseId}/dateOfBirth`]: createDayWrapper(spouseDob),
```

- [ ] **Step 4: Run the file and verify it is fully green**

```bash
npx vitest --run src/test/factDictionaryTests/hsa.test.ts
```

Expected: `Tests 123 passed (123)`, zero failures.

**Do not adjust any `expected*` value in the `testCases` table to make this pass.** Those encode the correct Form 8889 arithmetic and the fact dictionary already agrees with them once the ages are right. If an assertion still fails after this change, that is a genuine second defect — stop and report it rather than editing the expectation.

- [ ] **Step 5: Confirm no other test regressed**

The helper is new, so nothing else can have changed behavior — but `testData.ts` is imported very widely, so a bad import breaks many files at once.

```bash
npm run test:ci
```

Expected: same pass count as before this task, no new failures. `hsa.test.ts` is still excluded at this point, so it will not appear.

- [ ] **Step 6: Lint and commit**

```bash
npm run lint
cd ../../..
git add direct-file/df-client/df-client-app/src/test/testData.ts \
        direct-file/df-client/df-client-app/src/test/factDictionaryTests/hsa.test.ts
git commit -m "fix(client): anchor HSA MFJ test ages to the tax year, not the wall clock

The MFJ block built dates of birth from new Date() minus the case's age,
but /filers/*/age55OrOlder measures age at the END OF THE TAX YEAR, which
is fixed at 2024. Every age was therefore reduced by one per calendar
year: written in 2025 the drift was 1 and 56 still landed on 55, so the
tests passed; by 2026 the drift was 2, every over-55 party evaluated as
under 55, all form 8889 line 7 catch-ups became 0.00, and the line 6, 8,
and 12 values cascaded -- 20 assertions from one cause.

The fact dictionary was correct throughout. Verified by instrumenting the
graph: three of line 7's four conditions held and age55OrOlder was false;
substituting a fixed 1957 date of birth and changing nothing else
produced exactly the 1000.00 the test expects.

Adds dateOfBirthForAgeAtEndOfTaxYear to testData.ts so the rule lives in
one named place. The single and MFS fixtures were never affected because
they hardcode 1957-06-06."
```

---

## Task 2: Remove `hsa.test.ts` from the quarantine

**Files:**
- Modify: `direct-file/df-client/df-client-app/package.json:71,72`
- Modify: `direct-file/df-client/df-client-app/src/test/quarantineList.test.ts`
- Modify: `direct-file/README.md` (the CI quarantine table)

**Interfaces:**
- Consumes: a green `hsa.test.ts` from Task 1.
- Produces: a quarantine list of two files.

**This task is not optional cleanup — Task 1 breaks CI without it.** The `Quarantined tests still fail` step (`.github/workflows/ci.yml:341`) runs `test:ci:quarantine-watch`, which runs the quarantined files and **inverts the exit code**: it fails when they pass. That is the exit condition working as designed. Task 1 makes `hsa.test.ts` pass, so the watch step goes red until the file is removed from the list. Both tasks must land in the same pull request.

All four locations must agree, and `quarantineList.test.ts` enforces three of them against each other.

- [ ] **Step 1: Update `test:ci` to stop excluding the file**

In `direct-file/df-client/df-client-app/package.json`, line 71 currently reads:

```json
    "test:ci": "VITEST_MAX_THREADS=4 VITEST_MIN_THREADS=4 vitest --exclude 'src/{test/completenessTests/*,test/functionalFlowTests/*,all-screens/*,misc/apiHelpers.test.ts,test/factDictionaryTests/hsa.test.ts,test/scenarioTests/flowSnapshots.test.ts}' --run --silent",
```

Remove `test/factDictionaryTests/hsa.test.ts,` from the brace expansion:

```json
    "test:ci": "VITEST_MAX_THREADS=4 VITEST_MIN_THREADS=4 vitest --exclude 'src/{test/completenessTests/*,test/functionalFlowTests/*,all-screens/*,misc/apiHelpers.test.ts,test/scenarioTests/flowSnapshots.test.ts}' --run --silent",
```

Keep it a single brace-expanded glob. Repeated `--exclude` flags are not supported by this Vitest version — it throws `Expected a single value for option`, and `quarantineList.test.ts` asserts the single-glob shape.

- [ ] **Step 2: Update `test:ci:quarantine-watch`**

Line 72 currently reads:

```json
    "test:ci:quarantine-watch": "vitest run --silent src/misc/apiHelpers.test.ts src/test/factDictionaryTests/hsa.test.ts src/test/scenarioTests/flowSnapshots.test.ts; test $? -ne 0",
```

Drop the middle path:

```json
    "test:ci:quarantine-watch": "vitest run --silent src/misc/apiHelpers.test.ts src/test/scenarioTests/flowSnapshots.test.ts; test $? -ne 0",
```

- [ ] **Step 3: Update the guard test's expected list**

In `src/test/quarantineList.test.ts`, remove the entry from `QUARANTINED`:

```ts
const QUARANTINED = [
  `src/misc/apiHelpers.test.ts`,
  `src/test/scenarioTests/flowSnapshots.test.ts`,
].sort();
```

- [ ] **Step 4: Run the guard test**

```bash
cd direct-file/df-client/df-client-app
npx vitest --run src/test/quarantineList.test.ts
```

Expected: both assertions PASS. A failure here means Steps 1-3 disagree with each other — the exact drift the guard exists to catch.

- [ ] **Step 5: Verify the watch step still behaves correctly**

```bash
npm run test:ci:quarantine-watch; echo "exit=$?"
```

Expected: `exit=0`. The two remaining files still fail, and the inverted exit code turns that into success. If this prints `exit=1`, one of the remaining two has started passing and should be removed too — that is the mechanism doing its job, not a problem with this change.

- [ ] **Step 6: Verify `hsa.test.ts` now runs inside `test:ci`**

```bash
npm run test:ci
```

Expected: zero failures, and the file count **one higher** than the run in Task 1 Step 5, because `hsa.test.ts` is now included. Confirm `hsa.test.ts` appears in the output rather than trusting the count alone.

- [ ] **Step 7: Update the README table**

In `direct-file/README.md`, the CI section's quarantine table lists three files. Remove the `hsa.test.ts` row, leaving:

```markdown
| File | Failure |
| --- | --- |
| `src/misc/apiHelpers.test.ts` | `SM_UNIVERSALID` not overridden from `localStorage` when `preauthUuid` is set |
| `src/test/scenarioTests/flowSnapshots.test.ts` | suite fails to load: `ENOENT` on `src/test/factDictionaryTests/backend-scenarios-ero` |
```

Also update the surrounding prose: the count of excluded files changes from three to two, and the approximate count of gating test files rises accordingly.

- [ ] **Step 8: Lint and commit**

```bash
npm run lint
cd ../../..
git add direct-file/df-client/df-client-app/package.json \
        direct-file/df-client/df-client-app/src/test/quarantineList.test.ts \
        direct-file/README.md
git commit -m "ci: remove hsa.test.ts from the quarantine now that it passes

The quarantine-watch step fails when a quarantined file starts passing,
which is what the previous commit causes -- so the removal has to land
with it. hsa.test.ts's 123 assertions now gate merges again.

Two files remain quarantined: apiHelpers.test.ts and flowSnapshots.test.ts."
```

---

## Task 3: Correct the written record

**Files:**
- Modify: `direct-file/README.md` (the paragraph below the quarantine table)

**Interfaces:**
- Consumes: the diagnosis above.
- Produces: nothing other tasks consume.

Three places assert that the HSA failures are a tax-calculation defect. They are wrong, and the claim is the kind that gets repeated once it is written down — it has already propagated through two plans and a pull request comment.

1. `direct-file/README.md` — "**The `hsa.test.ts` failures are not cosmetic.** Wrong dollar amounts in contribution-limit logic mean either the fact dictionary or the test expectations are wrong, and one of those is a tax-calculation defect."
2. `docs/superpowers/plans/2026-09-01-backend-lows-and-ci-gating.md` — Task 4's warning block and handback 1.
3. https://github.com/twarn247/direct-file/pull/6#issuecomment-5494900442 — "Separately, and more important than the CI question".

The README is the live document and the only one that must change; **the two plans are historical records of what was believed at the time and should not be rewritten.** The PR comment cannot be edited by this process, so Step 2 posts a follow-up rather than pretending it can.

- [ ] **Step 1: Replace the README's characterization**

Replace the "**The `hsa.test.ts` failures are not cosmetic.**" paragraph with:

```markdown
**Previously quarantined:** `src/test/factDictionaryTests/hsa.test.ts` was excluded here and
described as a tax-calculation defect. It was not. The MFJ test block derived dates of birth
from `new Date()`, while `/filers/*/age55OrOlder` measures age at the end of the tax year —
fixed at 2024 — so every age drifted down by one per calendar year until the "over 55" cases
evaluated as under 55 and the form 8889 catch-up amounts went to zero. The fact dictionary was
correct throughout. Fixed by anchoring the fixtures to `CURRENT_TAX_YEAR` via
`dateOfBirthForAgeAtEndOfTaxYear` in `src/test/testData.ts`; use that helper for any fixture
whose age matters, and never build one from the wall clock.
```

- [ ] **Step 2: Post a correction to the PR #6 comment thread**

The original comment says the HSA failures are "wrong dollar amounts in contribution-limit logic" needing "review by someone with tax-domain knowledge." Anyone who finds that comment should find the correction with it.

```bash
gh pr comment 6 --repo twarn247/direct-file --body "Correction to the section above on the HSA failures.

These were not a tax-calculation defect. \`/filers/*/age55OrOlder\` measures age at the end of the tax year, which is fixed at 2024, but the MFJ block of \`hsa.test.ts\` derived dates of birth from \`new Date()\`. Every age in that table was therefore reduced by one per calendar year — written in 2025 the drift was 1 and \`56\` still landed on exactly 55, so the tests passed; by 2026 the drift was 2, every over-55 party evaluated as under 55, all form 8889 line 7 catch-ups became \`0.00\`, and the line 6, 8, and 12 values cascaded from there. One cause, all 20 assertions.

Verified by instrumenting the fact graph: three of line 7's four conditions held and \`age55OrOlder\` was false for a filer the test believed was 56. Substituting a fixed date of birth and changing nothing else produced exactly the \`1000.00\` the test expected.

The fact dictionary was correct throughout, and no tax-domain review is needed. The single and MFS blocks never failed because their fixtures hardcode \`1957-06-06\`. Fixed, and the file is out of the CI quarantine."
```

Confirm it posted; if `gh` reports an error, report that rather than moving on silently.

- [ ] **Step 3: Commit**

```bash
git add direct-file/README.md
git commit -m "docs: correct the record on the HSA test failures

They were described here, in two plans, and on PR #6 as a
tax-calculation defect needing tax-domain review. They were a
wall-clock-dependent test fixture. The fact dictionary was correct.

The two plans are left as-is -- they record what was believed at the
time. A correction is posted on the PR #6 thread."
```

---

## Handbacks

1. **Two files remain quarantined.** `apiHelpers.test.ts` expects `SM_UNIVERSALID` to be overridden from `localStorage.preauthUuid` and receives the nil UUID. `flowSnapshots.test.ts` fails to load at all — `ENOENT` on `src/test/factDictionaryTests/backend-scenarios-ero`, a fixture directory the public release appears to have stripped, which may make it unfixable in this checkout. Neither has been diagnosed to the depth this one now has, and neither should be assumed to be the same kind of problem.

2. **The tax year will move.** `CURRENT_TAX_YEAR` (`src/constants/taxConstants.ts:4`) and `/taxYear` (`backend/src/main/resources/tax/constants.xml:39`) are two independent literals that must be incremented together. Nothing enforces that today. A test asserting they agree would be cheap and would catch a whole class of drift, including the one this plan fixes.

3. **Only the age-from-wall-clock pattern was swept.** `grep -rn "setFullYear(.*getFullYear() -" src/` found this file alone, and the other `new Date()` uses in tests are `createdAt` timestamps crossing no threshold. But fixtures can drift on other axes — a hardcoded date near a filing deadline, an expiry window — and no general guard exists.

4. **`enforce_admins` is off on `main`'s branch protection**, which was applied outside a plan after being carried unexecuted through two of them. Revisit if the repository gains a second maintainer.

5. **The security review is still not on `main`.** It lives only on `origin/claude/report-security-review-lb7lsz` (commit `a6777fe`). Five plans cite that path as their spec and it resolves for none of them.

6. **The original review's register is fully closed.** H-1, M-1 through M-5, and L-1 through L-8 are all addressed. A fresh review against the current tree — rather than the 2025-06-05 snapshot the original covered — is the natural next substantial piece of work.
