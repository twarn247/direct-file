# Client Dependency Scanning Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Put the client's npm dependency tree under the same blocking Trivy scan the Maven modules now have, after first correcting a dependency misclassification that inflates the shipped tree and then upgrading the genuine residue.

**Architecture:** Same shape that worked for the Maven side, in the same order. Trivy reads `package-lock.json` natively and — verified empirically — honours the lockfile's `"dev": true` markers, so it already scopes to the production tree. That makes dependency classification load-bearing rather than cosmetic: `df-client-app/package.json` declares `vite` and `fast-xml-parser` as runtime `dependencies` despite neither being reachable from shipped code, which drags `rollup`, `postcss`, `browserslist`, `nanoid`, and `picomatch` into the scanned tree with them. So Task 1 corrects the classification and re-measures, Task 2 upgrades whatever real exposure survives, and only then does Task 3 wire the scan into CI as a blocking check with the same SARIF upload and the same `.trivyignore` the Maven scan uses.

**Tech Stack:** npm workspaces, Trivy, GitHub Actions, GitHub Code Scanning, Vite, Vitest.

**Spec:** Handback #2 of `docs/superpowers/plans/2026-09-03-dependency-vulnerability-triage.md` — "The client's npm tree is not scanned at all […] `df-client` has a `package-lock.json` with its own transitive tree and no SCA of any kind." This extends L-7, which covered only the Maven modules.

## Global Constraints

- **Backtick string literals in TypeScript.** ESLint enforces it repo-wide.
- **`npm run lint` must pass with `--max-warnings=0`**, and all three vitest suites must stay green.
- **Run npm commands from `direct-file/df-client`** (the workspace root), not from `df-client-app`. Installing scoped to the app alone silently skips workspace-root devDependencies — this is documented in `direct-file/README.md` and was a real CI failure once already.
- **Node 18.20.4**, pinned in `direct-file/df-client/.nvmrc`.
- **Do not silence a finding by narrowing the scan.** Every finding that stops appearing must be fixed, genuinely moved out of the production tree, or entered in `direct-file/.trivyignore` with a justification and an expiry.

---

## The measured baseline

Measured 2026-09-05 against `main` at `65fc4e8`.

**Trivy** (`trivy fs --scanners vuln --severity CRITICAL,HIGH direct-file/df-client/package-lock.json`): **35 findings across 14 distinct packages.**

```
@remix-run/router  brace-expansion  browserslist  fast-uri  fast-xml-parser
flatted  immutable  js-yaml  minimatch  nanoid  picomatch  postcss  rollup  vite
```

**`npm audit`** for cross-reference: 32 advisories over the whole tree (5 critical, 17 high, 8 moderate, 2 low); **22** with `--omit=dev` (1 critical, 15 high, 5 moderate, 1 low). The one production critical is `fast-xml-parser`, with a fix at `5.11.1`.

**Trivy excludes dev dependencies, verified rather than assumed.** It reports none of `vitest`, `@vitest/ui`, `@vitest/coverage-v8`, or `happy-dom` — all of which `npm audit` flags as critical in the full tree — and its 14 packages line up with npm audit's `--omit=dev` set. This is the fact the whole plan rests on: it means moving a package to `devDependencies` genuinely removes it from the gate, rather than just relabelling it.

**The misclassification.** `direct-file/df-client/df-client-app/package.json` lists these under `dependencies`, not `devDependencies`:

| Package | Imported from | Reachable at runtime? |
| --- | --- | --- |
| `vite` | nothing under `src/` | **No** — pure build tool |
| `fast-xml-parser` | `src/fact-dictionary/generate-src/readRawFacts.ts` only | **No** — build-time dictionary generator |
| `js-yaml` | `src/locales/yaml-settings.ts`, plus scripts and tests | **Unknown** — Task 1 Step 2 determines it |

`vite` alone accounts for a large share of the list: `rollup`, `postcss`, `browserslist`, `nanoid`, and `picomatch` are all in the scanned tree through it. How large is measured in Step 4, not estimated here.

There is also a second lockfile, `direct-file/df-client/df-common/package-lock.json`, which Task 3 scans as well.

---

## Task 1: Correct the dependency classification and re-measure

**Files:**
- Modify: `direct-file/df-client/df-client-app/package.json`
- Modify: `direct-file/df-client/package-lock.json` (regenerated, not hand-edited)

**Interfaces:**
- Consumes: nothing.
- Produces: a re-measured finding list that Task 2 works from.

**This is not tidying.** Because Trivy scopes to the production tree, a build tool declared as a runtime dependency is scanned as though it ships. Correcting that reduces real gate noise and makes the remaining findings mean what they say.

- [ ] **Step 1: Record the starting numbers**

```bash
cd /Users/thomaswarn/repo/direct-file
trivy fs --scanners vuln --severity CRITICAL,HIGH --quiet \
  direct-file/df-client/package-lock.json | tee /tmp/client-baseline.txt | tail -3
cd direct-file/df-client && npm audit --omit=dev 2>&1 | tail -3
```

Expected: 35 Trivy findings across 14 packages; npm audit reporting 22 production advisories. If either differs materially, the advisory databases have moved since 2026-09-05 — record the new numbers and carry on, but say so in the PR, because every count below is relative to these.

- [ ] **Step 2: Determine whether `js-yaml` is reachable from shipped code**

`vite` and `fast-xml-parser` are settled. `js-yaml` is not: `src/locales/yaml-settings.ts` sits under `src/`, and whether it reaches a bundle depends on who imports it.

```bash
cd /Users/thomaswarn/repo/direct-file/direct-file/df-client/df-client-app
grep -rn "yaml-settings" src/ --include="*.ts" --include="*.tsx" | grep -v "\.test\."
```

Read each importer and follow it up to either an entry point (`src/main.tsx`, a screen, a component) or a script/test. Then confirm against a real build, which is the authority:

```bash
cd .. && npm ci && cd df-client-app
npm run build:development
grep -rl "js-yaml\|jsYaml" dist/assets/*.js 2>/dev/null | head
```

**If the grep over `dist/` finds nothing, `js-yaml` is not in the bundle** and moves with the others. If it does appear, leave `js-yaml` in `dependencies` — it is genuinely shipped, and Task 2 upgrades it instead. Record which it was and the evidence.

- [ ] **Step 3: Move the build-only packages**

In `direct-file/df-client/df-client-app/package.json`, move `vite` and `fast-xml-parser` (and `js-yaml` only if Step 2 proved it unbundled) from `"dependencies"` to `"devDependencies"`, keeping their version ranges exactly as they are. Do not change a version in this task — a reclassification and an upgrade landing together makes it impossible to tell which one caused a regression.

Then regenerate the lockfile:

```bash
cd /Users/thomaswarn/repo/direct-file/direct-file/df-client
npm install
git diff --stat package-lock.json
```

**Never hand-edit `package-lock.json`.** The diff should show `"dev": true` appearing on the moved packages and their exclusive transitive dependencies, with no version changes.

- [ ] **Step 4: Re-measure**

```bash
cd /Users/thomaswarn/repo/direct-file
trivy fs --scanners vuln --severity CRITICAL,HIGH --quiet \
  direct-file/df-client/package-lock.json | tee /tmp/client-after-reclass.txt | tail -3
diff <(grep -oE "^[a-z@][^ ]*" /tmp/client-baseline.txt | sort -u) \
     <(grep -oE "^[a-z@][^ ]*" /tmp/client-after-reclass.txt | sort -u) || true
```

Expected: a materially shorter list. `vite`, `rollup`, `postcss`, `browserslist`, `nanoid`, `picomatch`, and `fast-xml-parser` should all have dropped out, assuming nothing else in the production tree also depends on them. **Anything that does not drop is still genuinely shipped through another path** — note which, since Task 2 has to upgrade those rather than reclassify them.

- [ ] **Step 5: Prove the build and tests are unaffected**

Moving `vite` to `devDependencies` is safe for building and testing (both are dev-time) but would break any consumer installing this package with `--omit=dev` and expecting to build from it. Nothing in this repo does that; confirm the normal paths still work:

```bash
cd direct-file/df-client && npm ci
cd df-client-app
npm run lint
npm run test:ci && npm run test:ci:2 && npm run test:ci:3
npm run build:development
```

Expected: all green, and `dist/` produced.

- [ ] **Step 6: Commit**

```bash
cd /Users/thomaswarn/repo/direct-file
git add direct-file/df-client/df-client-app/package.json direct-file/df-client/package-lock.json
git commit -m "fix(client): declare build-only tooling as devDependencies

vite and fast-xml-parser were listed under dependencies despite neither
being reachable from shipped code -- vite is imported nowhere in src/,
and fast-xml-parser only by the build-time fact-dictionary generator.
That put them, and rollup/postcss/browserslist/nanoid/picomatch beneath
them, into the production dependency tree.

This is not cosmetic: Trivy honours the lockfile's \"dev\" markers
(verified -- it reports none of vitest, @vitest/ui, or happy-dom), so a
build tool declared as a runtime dependency is scanned as though it
ships.

No version changed. Lockfile regenerated with npm install."
```

---

## Task 2: Upgrade the genuine runtime residue

**Files:**
- Modify: `direct-file/df-client/df-client-app/package.json` and/or other workspace manifests
- Modify: `direct-file/df-client/package-lock.json`

**Interfaces:**
- Consumes: Task 1's re-measured list.
- Produces: a clean or near-clean scan for Task 3 to gate on.

**The exact set is measured, not predicted.** From the baseline, `@remix-run/router` (via `react-router`/`react-router-dom`), `immutable`, `flatted`, `brace-expansion`, `minimatch`, and `fast-uri` are the likely survivors, since none is pulled in by `vite`. Treat that as an expectation to check against Step 1's output, not a worklist.

- [ ] **Step 1: List what remains, with fix versions**

```bash
cd /Users/thomaswarn/repo/direct-file
trivy fs --scanners vuln --severity CRITICAL,HIGH --format json --quiet \
  direct-file/df-client/package-lock.json > /tmp/client-residue.json

python3 - <<'PY' | tee /tmp/client-residue.txt
import json
d = json.load(open('/tmp/client-residue.json'))
rows = {}
for r in d.get('Results') or []:
    for v in r.get('Vulnerabilities') or []:
        rows[(v.get('PkgName'), v.get('VulnerabilityID'))] = (
            v.get('Severity'), v.get('InstalledVersion'), v.get('FixedVersion') or '<NO FIX>')
for (pkg, cve), (sev, installed, fixed) in sorted(rows.items()):
    print(f'{sev:<9} {cve:<22} {pkg:<24} {installed:<12} -> {fixed}')
print(f'\ntotal: {len(rows)}')
PY
```

The `-> ` column splits this task from Task 3: a real version means upgrade it here; `<NO FIX>` means it goes to `.trivyignore` with a justification.

- [ ] **Step 2: Find what actually pins each one**

Most entries will be transitive. Upgrading the direct dependent is preferable to forcing a nested version, because an `overrides` entry silently diverges from what the dependent was tested against.

```bash
cd direct-file/df-client
for p in $(awk '{print $3}' /tmp/client-residue.txt | grep -v '^$' | sort -u); do
  echo "=== $p"; npm ls "$p" 2>/dev/null | head -8
done
```

- [ ] **Step 3: Upgrade, one package at a time**

For each, prefer in this order:

1. **Bump the direct dependent** so it pulls a fixed transitive version (`npm install react-router-dom@latest` for the `@remix-run/router` chain, for example).
2. **Bump the package directly** if it is itself a direct dependency.
3. **Only if neither works**, add an `overrides` entry in `direct-file/df-client/package.json` with a comment naming the CVE — and re-run the full test suite, because this is the option that can break a dependent.

After each change:

```bash
cd /Users/thomaswarn/repo/direct-file/direct-file/df-client && npm install
cd df-client-app && npm run lint && npm run test:ci && npm run test:ci:2 && npm run test:ci:3
```

**A major-version bump of `react-router`/`react-router-dom` is a routing API change, not a patch.** If the fix requires one, stop and report the scope rather than working through it inside this task — routing changes deserve their own review.

- [ ] **Step 4: Re-measure and record the residue**

```bash
cd /Users/thomaswarn/repo/direct-file
trivy fs --scanners vuln --severity CRITICAL,HIGH --quiet \
  direct-file/df-client/package-lock.json | tail -3
```

Expected: zero, or a short list where every entry is `<NO FIX>` or blocked by a breaking change reported in Step 3.

- [ ] **Step 5: Commit**

```bash
git add direct-file/df-client/df-client-app/package.json direct-file/df-client/package.json direct-file/df-client/package-lock.json
git commit -m "chore(client): upgrade the remaining vulnerable runtime dependencies

Upgraded the direct dependents where possible rather than forcing nested
versions via overrides -- an override silently diverges from what the
dependent was tested against.

Full lint and all three vitest suites re-run after each package."
```

---

## Task 3: Scan the client lockfiles in CI, blocking

**Files:**
- Modify: `.github/workflows/ci.yml` (the `dependency-scan` job)
- Modify: `direct-file/.trivyignore` if anything from Task 2 needs an exception

**Interfaces:**
- Consumes: a clean or justified scan from Task 2.
- Produces: a blocking client dependency scan.

This goes in the existing `dependency-scan` job (`ci.yml:100`), not the `client` job: it reuses the Trivy setup, the SARIF upload pattern, and the shared `.trivyignore`, and keeps every dependency finding on one Code Scanning surface regardless of ecosystem.

The Maven scan needs the SBOM pipeline because it scans resolved Maven trees. The npm lockfile is scanned directly with `trivy fs` — no SBOM step.

- [ ] **Step 1: Add the scan step**

In `.github/workflows/ci.yml`, after the `Scan SBOMs with Trivy` step, add:

```yaml
      # The npm tree is scanned straight from its lockfiles -- no SBOM step, because
      # trivy fs reads package-lock.json natively. It honours the lockfile's "dev": true
      # markers, so this covers the production tree only; devDependency findings do not
      # gate. That is why dependency classification is load-bearing here (see the
      # 2026-09-05 client dependency scanning plan).
      #
      # df-common has its own lockfile and is scanned separately. No `set -e`, matching
      # the SBOM loop above: one bad lockfile must not stop the other being scanned.
      - name: Scan client lockfiles with Trivy
        run: |
          mkdir -p trivy-results
          status=0
          for lock in direct-file/df-client/package-lock.json direct-file/df-client/df-common/package-lock.json; do
            [ -f "$lock" ] || { echo "::warning::$lock not found, skipping"; continue; }
            name=$(echo "$lock" | sed 's|direct-file/df-client/||; s|/package-lock.json||; s|package-lock.json|df-client|')
            echo "::group::Scanning $name"
            if ! trivy fs "$lock" \
                  --scanners vuln \
                  --format sarif \
                  --output "trivy-results/npm-$name.sarif" \
                  --severity CRITICAL,HIGH \
                  --ignorefile direct-file/.trivyignore \
                  --exit-code 1; then
              echo "::error::Trivy failed for $name (a finding, or a scan error -- see the group above)"
              status=1
            fi
            echo "::endgroup::"
          done
          exit "$status"
```

Confirm the `name` derivation produces `df-client` and `df-common` before relying on it:

```bash
for lock in direct-file/df-client/package-lock.json direct-file/df-client/df-common/package-lock.json; do
  echo "$lock" | sed 's|direct-file/df-client/||; s|/package-lock.json||; s|package-lock.json|df-client|'
done
```

Expected: `df-client` then `df-common`. If not, fix the expression — the SARIF filenames and upload categories depend on it.

- [ ] **Step 2: Add the SARIF uploads**

Two more steps, following the exact pattern of `Upload SARIF (backend)` (`ci.yml`), including the fork guard verbatim — `GITHUB_TOKEN` is read-only on fork PRs and these would fail on every external contributor's PR without it:

```yaml
      - name: Upload SARIF (npm df-client)
        if: always() && (github.event_name != 'pull_request' || github.event.pull_request.head.repo.full_name == github.repository)
        uses: github/codeql-action/upload-sarif@6f5948dfacef28e207b48d0905cf90c03365536d # v3.37.9
        with:
          sarif_file: trivy-results/npm-df-client.sarif
          category: trivy-npm-df-client

      - name: Upload SARIF (npm df-common)
        if: always() && (github.event_name != 'pull_request' || github.event.pull_request.head.repo.full_name == github.repository)
        uses: github/codeql-action/upload-sarif@6f5948dfacef28e207b48d0905cf90c03365536d # v3.37.9
        with:
          sarif_file: trivy-results/npm-df-common.sarif
          category: trivy-npm-df-common
```

Distinct categories are required: Code Scanning refuses multiple SARIF runs under one category, which this workflow hit before.

- [ ] **Step 3: Add `.trivyignore` entries for anything with no fix**

For each `<NO FIX>` entry from Task 2, add an entry to `direct-file/.trivyignore` in the shape the file already documents — CVE id, `exp:YYYY-MM-DD`, and a reason covering why it does not apply here and what would change that. Six months for "no upstream fix"; twelve for a structural reason.

The file currently has **no active entries**, all Maven findings having been fixed outright. Keep that bar: if you cannot write the "why" line honestly, the finding is real.

- [ ] **Step 4: Verify the workflow parses and the gate can fail**

```bash
cd /Users/thomaswarn/repo/direct-file
python3 -c "import yaml; yaml.safe_load(open('.github/workflows/ci.yml')); print('ci.yml parses')"

# Passes at current state:
trivy fs direct-file/df-client/package-lock.json --scanners vuln --severity CRITICAL,HIGH \
  --ignorefile direct-file/.trivyignore --exit-code 1 > /dev/null 2>&1; echo "current: $?"

# And genuinely fails when something is wrong -- MODERATE is not gated, so its presence
# proves the exit code tracks findings rather than always being 0:
trivy fs direct-file/df-client/package-lock.json --scanners vuln --severity MEDIUM \
  --ignorefile direct-file/.trivyignore --exit-code 1 > /dev/null 2>&1; echo "medium: $?"
```

Expected: `current: 0` and `medium: 1`. **If `medium` is also `0`**, there are no medium findings either and this check proves nothing — instead confirm the gate works by temporarily reverting one of Task 2's upgrades, observing a non-zero exit, and restoring it.

- [ ] **Step 5: Commit**

```bash
git add .github/workflows/ci.yml direct-file/.trivyignore
git commit -m "ci: scan the client lockfiles, blocking

The npm tree had no SCA of any kind while the Maven modules had a
blocking scan -- 35 CRITICAL/HIGH findings across 14 production packages
were never reported anywhere.

Scanned with trivy fs straight from the lockfiles: same tool, same SARIF
upload, same shared .trivyignore as the Maven scan, so exceptions look
identical whichever ecosystem they came from. Trivy honours the
lockfile's dev markers, so this gates the production tree only.

df-common has its own lockfile and is scanned separately.

Closes handback 2 of the dependency vulnerability triage plan."
```

---

## Task 4: Document it

**Files:**
- Modify: `direct-file/README.md`

- [ ] **Step 1: Extend the dependency-scan section**

The README describes the scan as covering the Maven modules. Add:

```markdown
The client's npm tree is scanned too, straight from `df-client/package-lock.json` and
`df-client/df-common/package-lock.json` with `trivy fs` — no SBOM step, since Trivy reads
lockfiles natively. It is blocking, on the same CRITICAL/HIGH threshold and the same shared
`direct-file/.trivyignore` as the Maven scan.

**Trivy honours the lockfile's `"dev": true` markers, so only the production tree gates.**
That makes dependency classification a security decision, not a style preference: a build tool
declared under `dependencies` is scanned as though it ships. Before adding a package to
`dependencies`, confirm it is actually reachable from bundled code — `npm run build:development`
then grepping `dist/assets/` is the authority.
```

- [ ] **Step 2: Commit**

```bash
git add direct-file/README.md
git commit -m "docs: record client dependency scanning and why classification matters"
```

---

## Handbacks

1. **Moderate and low findings are not gated,** matching the Maven scan's CRITICAL/HIGH threshold. `npm audit` reports 8 moderate and 2 low across the full tree; none is visible in CI. Consistent with the existing bar, but it is a choice, not an oversight.

2. **`npm audit` and Trivy will not agree.** They use different advisory databases and count differently — 32 advisories versus 35 findings over 14 packages on the same tree. Trivy is the gate; `npm audit` is a developer convenience. Anyone comparing the two numbers and expecting them to match will conclude something is broken.

3. **Dev-tree vulnerabilities are real, just not gated.** `vitest`, `@vitest/ui`, `@vitest/coverage-v8`, and `happy-dom` all carry critical advisories and run on developer machines and CI runners with repository access. Not shipped, so out of scope here — but "not in the bundle" is not the same as "harmless", and a supply-chain attack on test tooling is a live technique.

4. **`js-yaml`'s classification depends on Task 1 Step 2's finding** and may remain a runtime dependency. If so it is upgraded rather than moved, and `src/locales/yaml-settings.ts` parsing YAML at runtime is worth its own look — YAML parsers are a recurring source of deserialization issues.

5. **Branch protection on `main` is still not applied** — `gh api repos/twarn247/direct-file/branches/main/protection` returns 404. Sixth plan to carry this, and it now gates two blocking scans that block nothing without it.

6. **The Maven `.trivyignore` is empty and should stay that way.** The 3.5.16 bump plus direct pins cleared every finding outright. If client work adds the file's first entries, that is a meaningful change in posture and belongs in the PR description.
