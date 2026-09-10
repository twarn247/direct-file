# Flow Snapshot Self-Rewrite Fix Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Stop `flowSnapshots.test.ts` overwriting its own expected output on mismatch, so a change to which screens a taxpayer sees cannot be silently blessed by a re-run.

**Architecture:** The test currently compares generated screen ordering against a tracked `.csv`, and *on mismatch writes the new output over the expectation before asserting*. Run one fails with the expectation already destroyed; run two passes. Replacing the hand-rolled compare-and-write with Vitest's `toMatchFileSnapshot` gives the correct semantics natively: it fails with a diff and rewrites only under `--update`. An explicit npm script provides the regeneration path the current behaviour was serving. A CI guard then asserts the working tree is clean after the client test steps, so any test that writes into the repository fails the build rather than being discovered later in a diff.

**Tech Stack:** Vitest 1.6.1, TypeScript, GitHub Actions.

**Spec:** Handback #2 of `docs/superpowers/plans/2026-09-02-clear-the-test-quarantine.md`, restated as handback #2 of `docs/superpowers/plans/2026-09-02-hsa-mfj-test-clock-drift.md`. Never actioned.

## Global Constraints

- **Backtick string literals in TypeScript.** ESLint enforces it repo-wide.
- **`npm run lint` must pass with `--max-warnings=0`.**
- **Run client commands from `direct-file/df-client`** (the workspace root) for installs; the app scripts run from `df-client-app`.
- **The 175 tracked `.csv` snapshots must not change content in this work.** This plan changes the mechanism, not the expectations. Any content change is a regression to investigate, not a snapshot to update.

---

## The defect

`direct-file/df-client/df-client-app/src/test/scenarioTests/flowSnapshots.test.ts:89-95`:

```ts
const screensMatchSnapshot = screens.join(`\n`) === flowSnapshot;
if (!screensMatchSnapshot) {
  // eslint-disable-next-line no-console
  console.warn(`Snapshot did not match for ${json} -- writing snapshot`);
  fs.writeFileSync(snapshotFileName, screens.join(`\n`));
}
expect(screensMatchSnapshot).toBe(true);
```

The write happens **before** the assertion, and to the expectation file itself. So:

1. Run one: mismatch → expectation overwritten with the new value → assertion fails.
2. Run two: the file now contains the new value → assertion passes.

The snapshots are tracked, not gitignored, so `git add -A` after a red run commits the blessed change. `git status` would show it, but the failing test has already told the developer "snapshot did not match — writing snapshot", which reads like the tool doing its job.

**What these files encode.** 175 `.csv` files under `src/test/scenarioTests/flow-snapshots/`, each the ordered list of screens a taxpayer walks through for one scenario. A silent change here is a change to the interview flow of a tax-filing application, and this suite is the only thing asserting that ordering.

**The behaviour is not gratuitous** — it is how snapshots get regenerated after an intentional flow change. The fix must keep that possible while making it deliberate.

---

## Task 1: Replace the hand-rolled write with `toMatchFileSnapshot`

**Files:**
- Modify: `direct-file/df-client/df-client-app/src/test/scenarioTests/flowSnapshots.test.ts:78-96`
- Modify: `direct-file/df-client/df-client-app/package.json` (add an update script)

**Interfaces:**
- Consumes: nothing.
- Produces: a test that fails without mutating its expectation. Task 2 verifies it.

**Why Vitest's native mechanism rather than an env-var guard on the existing code.** `toMatchFileSnapshot` already has exactly the required semantics, verified present in the installed Vitest 1.6.1: it fails with a diff on mismatch, rewrites only under `--update`/`-u`, and refuses to be used with `.not`. It also inherits Vitest's CI behaviour — `updateSnapshot` defaults to `'new'` locally (a *missing* snapshot is created, an *existing* mismatch fails) and `'none'` when `process.env.CI` is set, so CI cannot create one either. A hand-rolled env-var gate would reimplement that, less well.

`toMatchFileSnapshot` is **async** — it returns a promise and must be awaited, so the `it` callback becomes `async`.

- [ ] **Step 1: Record the current state, so any content drift is detectable**

```bash
cd /Users/thomaswarn/repo/direct-file/direct-file/df-client/df-client-app
ls src/test/scenarioTests/flow-snapshots/*.csv | wc -l
git status --short src/test/scenarioTests/flow-snapshots/ | wc -l
shasum -a 256 src/test/scenarioTests/flow-snapshots/*.csv | shasum -a 256
```

Expected: 175 files, 0 modified, and a digest to compare against in Task 2. Record the digest.

If any file already shows as modified, **stop** — a previous run has already rewritten a snapshot and that change needs investigating before it is buried by this work.

- [ ] **Step 2: Confirm the suite is green before changing it**

```bash
npx vitest --run src/test/scenarioTests/flowSnapshots.test.ts
git status --short src/test/scenarioTests/flow-snapshots/ | wc -l
```

Expected: all tests pass and still 0 modified files. A green run must not touch the snapshots.

- [ ] **Step 3: Replace the comparison**

In `src/test/scenarioTests/flowSnapshots.test.ts`, replace the body of the `it` at lines 79-95:

```ts
      it(`${json} produces the same snapshot`, () => {
        const fileName = s.folder + `/` + json;
        // add a suffix to snapshot filename so we can differentiate the ero from non-ero files
        const prefix = s.folder === ERO_SCENARIO_FOLDER ? `ero-` : ``;
        const snapshotFileName = FLOW_SNAPSHOTS_FOLDER + `/${prefix}` + json.replace(`.json`, `.csv`);
        const jsonString = fs.readFileSync(fileName, `utf-8`);
        const flowSnapshot = fs.existsSync(snapshotFileName) ? fs.readFileSync(snapshotFileName, `utf-8`) : undefined;
        const factJson = JSON.parse(jsonString);
        const { factGraph } = setupFactGraph(factJson.facts);
        const screens = getFlowScreenOrderingFromFlowConfig(factGraph);
        const screensMatchSnapshot = screens.join(`\n`) === flowSnapshot;
        if (!screensMatchSnapshot) {
          // eslint-disable-next-line no-console
          console.warn(`Snapshot did not match for ${json} -- writing snapshot`);
          fs.writeFileSync(snapshotFileName, screens.join(`\n`));
        }
        expect(screensMatchSnapshot).toBe(true);
      });
```

with:

```ts
      it(`${json} produces the same snapshot`, async () => {
        const fileName = s.folder + `/` + json;
        // add a suffix to snapshot filename so we can differentiate the ero from non-ero files
        const prefix = s.folder === ERO_SCENARIO_FOLDER ? `ero-` : ``;
        const snapshotFileName = FLOW_SNAPSHOTS_FOLDER + `/${prefix}` + json.replace(`.json`, `.csv`);
        const jsonString = fs.readFileSync(fileName, `utf-8`);
        const factJson = JSON.parse(jsonString);
        const { factGraph } = setupFactGraph(factJson.facts);
        const screens = getFlowScreenOrderingFromFlowConfig(factGraph);

        // toMatchFileSnapshot rather than a hand-rolled compare-and-write: the previous
        // version wrote the new ordering over the expectation BEFORE asserting, so a
        // failing run destroyed what it was checking against and the next run passed.
        // These files are the only assertion that the interview presents screens in the
        // order it should, so a silently blessed change here is a real one.
        //
        // Regenerate deliberately with `npm run test:update-flow-snapshots`.
        await expect(screens.join(`\n`)).toMatchFileSnapshot(snapshotFileName);
      });
```

The `flowSnapshot` local and the `fs.existsSync` read are no longer used — remove them, but leave `fs` imported, since the surrounding code still uses `readFileSync`/`readdirSync`.

- [ ] **Step 4: Add the explicit regeneration script**

In `direct-file/df-client/df-client-app/package.json`, alongside the other test scripts:

```json
    "test:update-flow-snapshots": "vitest run --update src/test/scenarioTests/flowSnapshots.test.ts",
```

Verify the JSON still parses:

```bash
node -e "JSON.parse(require('fs').readFileSync('package.json','utf8')); console.log('package.json parses')"
```

- [ ] **Step 5: Run the suite and confirm nothing changed**

```bash
npx vitest --run src/test/scenarioTests/flowSnapshots.test.ts
git status --short src/test/scenarioTests/flow-snapshots/ | wc -l
shasum -a 256 src/test/scenarioTests/flow-snapshots/*.csv | shasum -a 256
```

Expected: all pass, 0 modified files, and the digest **identical** to Step 1's.

**If the digest differs, `toMatchFileSnapshot` is serializing differently from the raw string the old code wrote** — most likely adding quoting or escaping. In that case do not accept the rewritten files. Revert them (`git checkout -- src/test/scenarioTests/flow-snapshots/`) and fall back to keeping the hand-rolled comparison, gated so it only writes under an explicit flag:

```ts
        const screensMatchSnapshot = screens.join(`\n`) === flowSnapshot;
        if (!screensMatchSnapshot && process.env.UPDATE_FLOW_SNAPSHOTS === `1`) {
          fs.writeFileSync(snapshotFileName, screens.join(`\n`));
        }
        expect(screensMatchSnapshot).toBe(true);
```

with the npm script set to `UPDATE_FLOW_SNAPSHOTS=1 vitest run …`. Report which path was taken and why — the fallback is equally correct on the thing that matters, and guessing wrong about serialization is exactly what Step 1's digest exists to catch.

- [ ] **Step 6: Lint and commit**

```bash
npm run lint
cd ../../..
git add direct-file/df-client/df-client-app/src/test/scenarioTests/flowSnapshots.test.ts \
        direct-file/df-client/df-client-app/package.json
git commit -m "fix(client): stop flow snapshots overwriting their own expectations

On mismatch the test wrote the new screen ordering over the expected .csv
BEFORE asserting, so a failing run destroyed what it was checking against
and a second run passed. The files are tracked, so git add -A after a red
run committed the blessed change -- and the warning it printed
(\"snapshot did not match -- writing snapshot\") read like the tool
working correctly.

These 175 files are the only assertion that the interview shows screens
in the order it should. toMatchFileSnapshot fails with a diff and
rewrites only under --update, which is now npm run
test:update-flow-snapshots.

No snapshot content changed: digest of all 175 files verified identical
before and after."
```

---

## Task 2: Prove the guard actually holds

**Files:** none modified — this task only verifies.

**Interfaces:**
- Consumes: Task 1.
- Produces: evidence for the PR.

A fix to a "silently passes when it should fail" defect has to be demonstrated failing. Do not skip this on the grounds that the code obviously does the right thing — that is what was believed about the old code.

- [ ] **Step 1: Perturb a snapshot and confirm the test fails**

```bash
cd /Users/thomaswarn/repo/direct-file/direct-file/df-client/df-client-app
target=$(ls src/test/scenarioTests/flow-snapshots/*.csv | head -1)
echo "using: $target"
cp "$target" /tmp/snapshot-backup.csv
printf '\n/flow/fake/injected-screen' >> "$target"

npx vitest --run src/test/scenarioTests/flowSnapshots.test.ts 2>&1 | tail -20; echo "exit=$?"
```

Expected: **a failure**, naming that scenario and showing a diff.

- [ ] **Step 2: Confirm the failing run did NOT rewrite the expectation**

This is the whole point of the change.

```bash
diff "$target" /tmp/snapshot-backup.csv > /dev/null && echo "UNEXPECTED: file was restored/rewritten" || echo "GOOD: perturbation still present, test did not overwrite it"
```

Expected: `GOOD` — the file still contains the injected line, meaning the test failed without touching it.

Under the old code this file would have been rewritten to the *correct* ordering, and a second run would pass. Confirm that is no longer true:

```bash
npx vitest --run src/test/scenarioTests/flowSnapshots.test.ts > /dev/null 2>&1; echo "second run exit=$?"
```

Expected: non-zero again. A passing second run means the fix did not take.

- [ ] **Step 3: Confirm the deliberate update path works**

```bash
npm run test:update-flow-snapshots > /dev/null 2>&1
diff "$target" /tmp/snapshot-backup.csv > /dev/null && echo "GOOD: update script restored the correct ordering" || echo "PROBLEM: update script did not regenerate"
```

Expected: `GOOD`.

- [ ] **Step 4: Restore and confirm the tree is clean**

```bash
cp /tmp/snapshot-backup.csv "$target"
git status --short src/test/scenarioTests/flow-snapshots/ | wc -l
npx vitest --run src/test/scenarioTests/flowSnapshots.test.ts > /dev/null 2>&1; echo "exit=$?"
rm -f /tmp/snapshot-backup.csv
```

Expected: 0 modified files and `exit=0`.

Record all four outcomes in the PR description. There is no commit in this task.

---

## Task 3: Fail CI if any test writes into the repository

**Files:**
- Modify: `.github/workflows/ci.yml` (the `client` job)
- Modify: `direct-file/README.md`

**Interfaces:**
- Consumes: Tasks 1 and 2.
- Produces: a general guard, not specific to this suite.

Task 1 fixes the one suite known to do this. A working-tree check catches the next one for free, and costs one step.

- [ ] **Step 1: Add the guard after the client test steps**

In `.github/workflows/ci.yml`'s `client` job, after `Test (all screens)`:

```yaml
      # A test that writes into the repository is almost always a test rewriting its own
      # expectation -- which is how flowSnapshots.test.ts silently blessed changes to the
      # interview's screen ordering until 2026-09-09. `always()` so this reports even when
      # an earlier test step failed, which is exactly when a self-rewriting test does its
      # damage.
      - name: No test may modify tracked files
        if: always()
        working-directory: .
        run: |
          if ! git diff --exit-code --stat; then
            echo "::error::The test run modified tracked files (listed above). A test that"
            echo "::error::rewrites its own expected output cannot fail twice -- fix the test."
            exit 1
          fi
```

`working-directory: .` overrides the job's `defaults.run.working-directory` of `direct-file/df-client/df-client-app`, so `git diff` covers the whole repository rather than one subtree.

- [ ] **Step 2: Verify the workflow parses**

```bash
cd /Users/thomaswarn/repo/direct-file
python3 -c "import yaml; yaml.safe_load(open('.github/workflows/ci.yml')); print('ci.yml parses')"
```

- [ ] **Step 3: Verify the guard's logic locally**

```bash
cd /Users/thomaswarn/repo/direct-file
git diff --exit-code --stat > /dev/null && echo "clean tree -> guard passes"
target=$(ls direct-file/df-client/df-client-app/src/test/scenarioTests/flow-snapshots/*.csv | head -1)
printf '\n# temp' >> "$target"
git diff --exit-code --stat > /dev/null || echo "dirty tree -> guard fails, as intended"
git checkout -- "$target"
git diff --exit-code --stat > /dev/null && echo "restored"
```

Expected: all three lines print.

- [ ] **Step 4: Document it**

In `direct-file/README.md`'s client CI section, add:

````markdown
The client job ends with a check that the test run modified no tracked files. A test that
writes into the repository is nearly always one rewriting its own expected output, which
cannot then fail twice — `flowSnapshots.test.ts` did exactly this until 2026-09-09, silently
blessing changes to the interview's screen ordering.

Flow snapshots are regenerated deliberately, never automatically:

```sh
cd direct-file/df-client/df-client-app && npm run test:update-flow-snapshots
```

Review the resulting diff as a behavioural change, because that is what it is.
````

- [ ] **Step 5: Commit**

```bash
git add .github/workflows/ci.yml direct-file/README.md
git commit -m "ci: fail the build if a test modifies tracked files

Generalises the flow-snapshot fix. A test that writes into the repository
is almost always one rewriting its own expectation, which makes it unable
to fail twice -- and the working-tree check catches the next one without
anyone having to notice it first.

Runs with always() so it reports even when an earlier test step failed,
which is precisely when a self-rewriting test does its damage."
```

---

## Handbacks

1. **The ERO snapshots remain unverified.** `backend-scenarios-ero` is a dangling symlink in this checkout, so the `ero-*.csv` expectations have no inputs to check them against. They are skipped, not asserted, and this change does not alter that.

2. **A guard on tracked files does not catch a test writing outside the repository** — to `/tmp`, a cache, or a global config. That is usually benign, but it is not covered.

3. **The snapshot mechanism asserts ordering, not correctness.** These files record what the flow *does*, not what it *should* do. Regenerating them after a deliberate change is legitimate; nothing here can distinguish an intended change from a regression, so the diff still needs a human read. That is the argument for keeping the regeneration path explicit.

4. **Moderate and low dependency findings are still ungated** in both ecosystems — 4 MEDIUM in the client npm tree as of 2026-09-09, Maven unmeasured. Raising the threshold is the natural next ratchet now that both scans are clean at CRITICAL/HIGH.

5. **`df-static-site` still ships `'unsafe-inline'` in `script-src`.** Materially looser than `df-client-app`'s hashed policy, and untouched since it was moved to a response header.

6. **Branch protection on `main` is still not applied** — `gh api repos/twarn247/direct-file/branches/main/protection` returns 404. Seventh plan to carry this. It now gates two blocking dependency scans and a working-tree check, none of which is required to merge.
