# CI Pipeline and Dependency Scanning Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Stand up a GitHub Actions pipeline that builds and tests the Java services on every pull request, and scan the resulting dependency graph for known vulnerabilities — closing L-7 and making every guard test written so far actually run.

**Architecture:** One workflow, two jobs. `build-and-test` reproduces the build order the existing `scripts/build-*.sh` files encode — publish the Scala fact-graph to the local Maven repo, install the shared `libs`, then build and test each service — with dependency caching so the Scala step is paid once. `dependency-scan` consumes the CycloneDX SBOMs the Maven build can already emit and runs Trivy against them, publishing SARIF so findings surface in the repository's security tab. The jobs are separate so a vulnerability finding does not mask a test failure.

**Tech Stack:** GitHub Actions, Temurin JDK 21, Maven wrapper, sbt 1.9.2 / Scala 3, CycloneDX Maven plugin 2.9.1, Trivy.

**Spec:** `docs/security/2026-08-22_codebase-security-review.md` finding L-7 (on branch `origin/claude/report-security-review-lb7lsz`).

## Global Constraints

- **Java 21** (`java.version`, `direct-file/boms/irs-spring-boot-starter-parent/pom.xml:19`). Use Temurin.
- **sbt 1.9.2** (`direct-file/fact-graph-scala/project/build.properties`), Scala 3.
- **Use the Maven wrappers (`./mvnw`)**, never a system `mvn`. Every module ships one.
- **There is no root aggregator pom.** `direct-file/` is not a Maven project; each service is built from its own directory. Any workflow step must `cd` into the module.
- **Do not add or change build plugins.** This plan configures CI around the build that exists; changing the build is a separate concern.
- **Integration tests stay off by default.** `state-api`'s integration tests are gated behind `-DrunIntegrationTests` and need Docker/LocalStack. Plain `./mvnw test` skips them, which is what CI runs.

## Scope correction — the Scala build is not optional

The scope for this work was "Java services plus SCA, leaving the Scala and client builds for a follow-up." The client part holds. **The Scala part does not, and the plan is written accordingly.**

`direct-file/backend/pom.xml:78` declares:

```xml
<groupId>gov.irs.factgraph</groupId>
<artifactId>fact-graph_3</artifactId>
```

That artifact is not on Maven Central. It reaches the local `~/.m2` repository only through `scripts/build-fact-graph.sh`, which runs `sbt clean compile package publishM2`. `scripts/build-dependencies.sh` then runs `libs/mvnw clean install`, and only after both can any service build.

So CI must build the fact-graph as a **dependency**. What this plan does not do is run the fact-graph's own test suite or its Scala.js cross-build — those stay for the follow-up. The distinction is between *building* it (required, unavoidable) and *testing* it (deferred).

This is worth knowing before the first run: the Scala compile is the slowest step in the pipeline, which is why Task 1 caches it.

## Scope note

**Not in this plan:** the React client's `vitest` suites and lint, the fact-graph's own tests and Scala.js cross-build, and `utils/csp-simulator` (Python/poetry). Each is a coherent follow-up once the Java pipeline is green.

**Branch protection is not something this plan can do.** A workflow that runs but is not required to pass changes nothing about what can merge. Enabling required status checks is a repository setting only an admin can change; it is the first handback item.

## File structure

| File | Responsibility |
|---|---|
| `.github/workflows/ci.yml` | Build, test, and scan on pull requests and pushes to main |
| `direct-file/scripts/build-sbom.sh` | Fixed to match the modules this repository actually contains |
| `direct-file/README.md` | What CI runs, and how to reproduce a failure locally |

---

## Task 1: Build and test the Java services on every pull request

**Files:**
- Create: `.github/workflows/ci.yml`

**Interfaces:**
- Consumes: nothing from other tasks.
- Produces: a `build-and-test` job that Task 3 depends on by name, and a `~/.m2/repository` cache other jobs restore.

**Design note — one sequential job, not a matrix.** Every service needs the fact-graph and `libs` installed into `~/.m2` first, so a per-service matrix would either rebuild that prerequisite five times or depend on cache plumbing that is easy to get subtly wrong. For a repository with no CI at all, a single obviously-correct job that goes green is worth more than a fast one that is hard to review. Splitting the service builds into a matrix is a sensible follow-up once the baseline is trusted.

- [ ] **Step 1: Create the workflow**

Create `.github/workflows/ci.yml`:

```yaml
name: CI

on:
  pull_request:
  push:
    branches: [main]

# A newer push to the same branch makes an in-flight run obsolete.
concurrency:
  group: ${{ github.workflow }}-${{ github.ref }}
  cancel-in-progress: true

permissions:
  contents: read

jobs:
  build-and-test:
    name: Build and test Java services
    runs-on: ubuntu-latest
    timeout-minutes: 60

    steps:
      - uses: actions/checkout@v4

      - name: Set up JDK 21
        uses: actions/setup-java@v4
        with:
          distribution: temurin
          java-version: '21'
          cache: maven

      - name: Set up sbt
        uses: sbt/setup-sbt@v1

      # The Scala compile is the slowest step in the pipeline and its output only
      # changes when fact-graph-scala does. Keyed on that subtree alone so a change
      # to any Java service still gets a cache hit.
      - name: Cache Scala build
        uses: actions/cache@v4
        with:
          path: |
            ~/.ivy2/cache
            ~/.sbt
            ~/.cache/coursier
            direct-file/fact-graph-scala/target
            direct-file/fact-graph-scala/project/target
          key: scala-${{ runner.os }}-${{ hashFiles('direct-file/fact-graph-scala/**/*.scala', 'direct-file/fact-graph-scala/build.sbt', 'direct-file/fact-graph-scala/project/build.properties') }}
          restore-keys: |
            scala-${{ runner.os }}-

      # backend/pom.xml declares gov.irs.factgraph:fact-graph_3, which is not on
      # Maven Central. publishM2 is the only thing that puts it in ~/.m2, so no
      # service can compile until this runs. Mirrors scripts/build-fact-graph.sh.
      - name: Publish fact-graph to the local Maven repository
        working-directory: direct-file/fact-graph-scala
        run: sbt compile package publishM2

      # Builds the boms, data-models, and starters aggregate. Mirrors
      # scripts/build-dependencies.sh.
      - name: Install shared libraries
        working-directory: direct-file/libs
        run: ./mvnw --batch-mode --no-transfer-progress clean install

      - name: Build and test backend
        working-directory: direct-file/backend
        run: ./mvnw --batch-mode --no-transfer-progress verify

      - name: Build and test state-api
        working-directory: direct-file/state-api
        run: ./mvnw --batch-mode --no-transfer-progress verify

      - name: Build and test status
        working-directory: direct-file/status
        run: ./mvnw --batch-mode --no-transfer-progress verify

      - name: Build and test submit
        working-directory: direct-file/submit
        run: ./mvnw --batch-mode --no-transfer-progress verify

      - name: Build and test email-service
        working-directory: direct-file/email-service
        run: ./mvnw --batch-mode --no-transfer-progress verify

      - name: Upload test reports
        if: always()
        uses: actions/upload-artifact@v4
        with:
          name: surefire-reports
          path: direct-file/*/target/surefire-reports/
          if-no-files-found: warn
          retention-days: 14
```

`verify` rather than `test` so Spotless, PMD, and SpotBugs run too — those are already configured in the parent pom and are the reason the repository's formatting has stayed consistent by convention. Making them enforced is most of the value of having CI at all.

- [ ] **Step 2: Push to a branch and watch the first run**

```bash
git checkout -b ci/initial-pipeline
git add .github/workflows/ci.yml
git commit -m "ci: build and test the Java services on pull requests"
git push -u origin ci/initial-pipeline
gh pr create --fill
gh run watch
```

**Expect the first run to fail, and treat that as information rather than a setback.** Likely causes, in the order they will appear:

- `sbt/setup-sbt@v1` unavailable or wrong version — pin to the tag the action's README specifies.
- The Scala build needs more heap. Add `JAVA_OPTS: -Xmx4g` to the step's `env`.
- Spotless fails on a file nobody formatted. **Fix the file, do not add `-Dspotless.check.skip`.** A formatter that CI does not enforce is a formatter that drifts.
- SpotBugs or PMD fails on pre-existing findings. See Step 3 — this is the one case where a judgment call is required.

- [ ] **Step 3: Decide what to do about pre-existing static-analysis findings**

The build has SpotBugs 4.8.6 with FindSecBugs 1.12.0 and PMD configured, and until now nothing has been failing a build on them. It is likely there is a backlog.

If `verify` fails on pre-existing findings, do **not** disable the plugin and do **not** raise its threshold globally. Either:

- **Preferred:** fix the findings if they are few. The repository already uses targeted `@SuppressFBWarnings` and `@SuppressWarnings("PMD...")` annotations with justifications — follow that pattern, and make each suppression name its reason.
- **If there are many:** change the workflow's per-service step to `./mvnw --batch-mode --no-transfer-progress test` for now, and open a follow-up issue to move to `verify`. Record the decision and the count in the PR description so the debt is visible rather than silently skipped.

Whichever you choose, say which in the PR. A green pipeline that quietly checks less than it appears to is worse than a red one.

- [ ] **Step 4: Confirm the guard tests actually run**

The point of this task is that tests written to prevent regressions now execute automatically. Prove it:

```bash
gh run view --log | grep -E "LogbackEncoderAllowlistTest|ErrorMessageExposureTest|EncryptionBackfillWorkerTest"
```

**Expected: all three appear and pass.** If they do not appear, the backend's surefire run is not picking them up and the pipeline is not yet doing its job.

- [ ] **Step 5: Prove the pipeline fails when it should**

A pipeline that has never gone red has not been tested. On the same branch, temporarily break one guard:

```bash
# In logback.xml, delete one <includeKeyValueKeyName> line.
git commit -am "TEMP: prove CI catches an encoder allowlist regression"
git push
gh run watch
```

**Expected: `LogbackEncoderAllowlistTest` fails and the run goes red.** Then revert:

```bash
git revert --no-edit HEAD
git push
```

Record in the PR that this was verified. It is the only evidence that the pipeline detects the regressions it exists to detect.

- [ ] **Step 6: Merge**

Once green, merge the PR. Do not squash away the temporary-break-and-revert commits if reviewers want to see the evidence; otherwise squash is fine.

---

## Task 2: Fix the SBOM script for the modules this repository actually has

`scripts/build-sbom.sh` cannot run here. It is a prerequisite for Task 3 and broken independently of it.

**Files:**
- Modify: `direct-file/scripts/build-sbom.sh`

**Interfaces:**
- Consumes: nothing from other tasks.
- Produces: a `build-sbom.sh` that completes against this repository's module set.

**Why it is broken.** The script iterates modules that were removed for the public release. Verified absent from `origin/main`:

| Module referenced | Present |
|---|---|
| `analytics` | **No** |
| `data-import` | **No** |
| `utils/csp-simulator` | Yes |

`set -e` is on, so the first `cd ../analytics` fails and the script stops. Its `cyclonedx merge` step then also lists `analytics/target/bom.json` and `data-import/target/bom.json` as inputs.

- [ ] **Step 1: Confirm the module inventory before editing**

Do not trust the table above — re-derive it, because the repository may have changed:

```bash
cd /Users/thomaswarn/repo/direct-file/direct-file
for m in backend email-service analytics state-api status submit data-import fact-graph-scala libs/data-models utils/csp-simulator utils/pdf-to-yaml; do
  printf '%-28s ' "$m"; [ -d "$m" ] && echo present || echo ABSENT
done
```

- [ ] **Step 2: Remove the absent modules**

In `direct-file/scripts/build-sbom.sh`, delete the `analytics` and `data-import` generation blocks:

```sh
echo "Writing analytics sbom"
cd ../analytics
./mvnw cyclonedx:makeBom
```

```sh
echo "Writing data-import sbom"
cd ../data-import
./mvnw cyclonedx:makeBom
```

and delete their two lines from the `cyclonedx merge --input-files` list:

```
  analytics/target/bom.json \
  data-import/target/bom.json \
```

Watch the `cd` chain as you delete — the script navigates with relative paths (`cd ../state-api` assumes the previous `cd` landed in a sibling). Removing a block changes what the next `cd` is relative to. Re-read the whole sequence after editing and confirm each `cd` still resolves.

- [ ] **Step 3: Add a note about why they are gone**

At the top of the script, under the existing comment block:

```sh
# Note: the analytics and data-import modules referenced by earlier versions of this
# script are not part of the public release (see README.md, "Exempted Code"), so they
# are not generated or merged here.
```

- [ ] **Step 4: Run it**

```bash
cd /Users/thomaswarn/repo/direct-file/direct-file
./scripts/build-sbom.sh
```

This needs `cyclonedx-cli` (`brew install cyclonedx/cyclonedx/cyclonedx-cli`), `sbt`, `node`, `python3`, and `poetry` for the csp-simulator step. **Expected: `sbom.json` at `direct-file/sbom.json`.**

If `poetry` is unavailable, note it and skip that module rather than installing a Python toolchain for one SBOM — Task 3 does not depend on the merged file.

- [ ] **Step 5: Commit**

```bash
git add direct-file/scripts/build-sbom.sh
git commit -m "fix(scripts): drop absent modules from the SBOM script

analytics and data-import are not part of the public release, so the script
failed at the first cd under set -e."
```

---

## Task 3: Scan dependencies for known vulnerabilities

**Files:**
- Modify: `.github/workflows/ci.yml`

**Interfaces:**
- Consumes: the `build-and-test` job from Task 1 (`needs:`), and the `~/.m2` state it populates.
- Produces: a `dependency-scan` job publishing SARIF to the repository's security tab.

**Design note — per-module BOMs, not the merged one.** Task 2's script produces a single merged `sbom.json`, but it needs `cyclonedx-cli`, Node, Python, and poetry — four toolchains to install on a runner for a file Trivy does not need. The CycloneDX Maven plugin is already configured in the parent pom (`irs-spring-boot-starter-parent/pom.xml:421`), so each module can emit its own `target/bom.json` and Trivy can scan each in turn. Fewer moving parts, and a failure points at one module.

Note the plugin has **configuration but no `<executions>`**, so it is not bound to a lifecycle phase — `cyclonedx:makeBom` must be invoked explicitly.

**Design note — why this starts non-blocking.** Nobody knows what this will find. The review flagged `springdoc 2.1.0` (2023) and `jaxb-api 2.3.1` (2018) as notably stale, but did not assess CVE exposure. A scan that fails the build on its first run against an unknown backlog will be switched off within a day. It starts reporting-only, and the handback asks for a date to make it blocking once the backlog is known and triaged.

- [ ] **Step 1: Add the scan job**

Append to `.github/workflows/ci.yml`, and extend the top-level `permissions` block so SARIF upload is allowed:

```yaml
permissions:
  contents: read
  security-events: write
```

```yaml
  dependency-scan:
    name: Dependency vulnerability scan
    runs-on: ubuntu-latest
    needs: build-and-test
    timeout-minutes: 30

    steps:
      - uses: actions/checkout@v4

      - name: Set up JDK 21
        uses: actions/setup-java@v4
        with:
          distribution: temurin
          java-version: '21'
          cache: maven

      - name: Set up sbt
        uses: sbt/setup-sbt@v1

      - name: Restore Scala build
        uses: actions/cache@v4
        with:
          path: |
            ~/.ivy2/cache
            ~/.sbt
            ~/.cache/coursier
            direct-file/fact-graph-scala/target
            direct-file/fact-graph-scala/project/target
          key: scala-${{ runner.os }}-${{ hashFiles('direct-file/fact-graph-scala/**/*.scala', 'direct-file/fact-graph-scala/build.sbt', 'direct-file/fact-graph-scala/project/build.properties') }}
          restore-keys: |
            scala-${{ runner.os }}-

      # The BOM records resolved dependencies, so the fact-graph and libs must be in
      # ~/.m2 for resolution to succeed -- same prerequisite as the build job.
      - name: Publish fact-graph to the local Maven repository
        working-directory: direct-file/fact-graph-scala
        run: sbt compile package publishM2

      - name: Install shared libraries
        working-directory: direct-file/libs
        run: ./mvnw --batch-mode --no-transfer-progress clean install -DskipTests

      # cyclonedx-maven-plugin is configured in the parent pom but has no <executions>,
      # so it is not bound to a phase and must be invoked by goal.
      - name: Generate CycloneDX SBOMs
        working-directory: direct-file
        run: |
          set -e
          for module in backend state-api status submit email-service libs/data-models; do
            echo "::group::SBOM for $module"
            (cd "$module" && ./mvnw --batch-mode --no-transfer-progress cyclonedx:makeBom)
            echo "::endgroup::"
          done

      - name: Collect SBOMs
        working-directory: direct-file
        run: |
          mkdir -p ../sboms
          for module in backend state-api status submit email-service libs/data-models; do
            cp "$module/target/bom.json" "../sboms/$(echo "$module" | tr '/' '-').bom.json"
          done
          ls -la ../sboms

      - name: Upload SBOMs
        uses: actions/upload-artifact@v4
        with:
          name: cyclonedx-sboms
          path: sboms/
          retention-days: 30

      # Reporting-only for now. See the handback: this becomes blocking once the
      # existing backlog is known and triaged.
      - name: Scan SBOMs with Trivy
        uses: aquasecurity/trivy-action@0.28.0
        with:
          scan-type: sbom
          scan-ref: sboms/
          format: sarif
          output: trivy-results.sarif
          severity: CRITICAL,HIGH
          exit-code: '0'

      - name: Upload SARIF to the security tab
        if: always()
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: trivy-results.sarif
          category: trivy-dependencies

      - name: Summarise findings
        if: always()
        run: |
          echo "### Dependency scan" >> "$GITHUB_STEP_SUMMARY"
          echo "" >> "$GITHUB_STEP_SUMMARY"
          echo "Reporting-only. Findings are in the Security tab under 'trivy-dependencies'." >> "$GITHUB_STEP_SUMMARY"
```

Check `aquasecurity/trivy-action`'s current major tag and whether `scan-type: sbom` accepts a **directory** in that version. If it requires a single file, loop over `sboms/*.bom.json` with the Trivy CLI directly and merge the SARIF, or run the action once per file with a distinct `category` on each SARIF upload.

- [ ] **Step 2: Push and read what it finds**

```bash
git add .github/workflows/ci.yml
git commit -m "ci: scan dependencies for known vulnerabilities"
git push
gh run watch
```

**Expected: green** — `exit-code: '0'` means findings do not fail the job. The output is the point, not the status.

- [ ] **Step 3: Record the baseline**

This is the deliverable that turns L-7 from a guess into data. From the Security tab or the SARIF artifact, write the counts into the PR description:

```
Trivy baseline, <date>:
  CRITICAL: <n>
  HIGH:     <n>
  Modules with the most findings: <...>
  Notable: springdoc 2.1.0 (2023), jaxb-api 2.3.1 (2018) — flagged as stale in the
           2026-08-22 review; confirmed/not confirmed as carrying CVEs.
```

Without this number written down somewhere durable, the next person has to rediscover it.

- [ ] **Step 4: Merge**

---

## Task 4: Document what CI does

**Files:**
- Modify: `direct-file/README.md`

**Interfaces:**
- Consumes: Tasks 1 and 3.
- Produces: no code interface.

- [ ] **Step 1: Add a CI section**

Add to `direct-file/README.md`:

```markdown
## Continuous integration

`.github/workflows/ci.yml` runs on every pull request and on pushes to `main`.

**`build-and-test`** publishes the Scala fact-graph to the local Maven repository,
installs the shared `libs`, then runs `./mvnw verify` for `backend`, `state-api`,
`status`, `submit`, and `email-service`. `verify` includes Spotless, PMD, and SpotBugs
as well as the test suites.

The fact-graph step is not optional: `backend/pom.xml` depends on
`gov.irs.factgraph:fact-graph_3`, which is not published to Maven Central and reaches
`~/.m2` only via `sbt publishM2`. This mirrors `scripts/build-dependencies.sh`.

`state-api`'s integration tests are gated behind `-DrunIntegrationTests` and need
Docker; CI does not run them. Run them locally with `state-api/integrationtest.sh`.

**`dependency-scan`** generates a CycloneDX SBOM per module and scans them with Trivy.
Results appear in the Security tab under `trivy-dependencies`. **It is currently
reporting-only and does not fail the build** — see the handback in
`docs/superpowers/plans/2026-08-29-ci-pipeline-and-dependency-scanning.md`.

### Reproducing a CI failure locally

```sh
cd direct-file/fact-graph-scala && sbt compile package publishM2
cd ../libs && ./mvnw clean install
cd ../backend && ./mvnw verify     # or whichever service failed
```

Not the React client or the fact-graph's own test suite — neither is in CI yet.
```

- [ ] **Step 2: Commit**

```bash
git add direct-file/README.md
git commit -m "docs: describe what CI builds, tests, and scans"
```

---

## Verification

- [ ] **A pull request runs both jobs and goes green**

```bash
gh pr checks
```

Expected: `build-and-test` and `dependency-scan` both pass.

- [ ] **The guard tests ran**

```bash
gh run view --log | grep -E "LogbackEncoderAllowlistTest|ErrorMessageExposureTest|EncryptionBackfillWorkerTest|StateApiServiceImplTest"
```

Expected: all present and passing. These are the regression guards that previously ran only when someone remembered.

- [ ] **The pipeline has been proven to go red** (Task 1 Step 5)

Expected: recorded in the PR, with the run link.

- [ ] **SBOMs are downloadable and the baseline is written down**

```bash
gh run download --name cyclonedx-sboms
```

Expected: one BOM per module, and the CRITICAL/HIGH counts recorded in the PR description.

- [ ] **`build-sbom.sh` completes**

```bash
cd direct-file && ./scripts/build-sbom.sh && ls -la sbom.json
```

Expected: `sbom.json` written. Note if the poetry step was skipped.

## Handback to the milestone owner

1. **Enable branch protection on `main` and make `build-and-test` a required status check.** This is the one that decides whether any of this matters — a workflow that runs but cannot block a merge is advisory. Repository admin only; nothing in this plan can do it.
2. **Set a date to make `dependency-scan` blocking.** It ships reporting-only because the backlog is unknown. Once Task 3 Step 3's baseline is triaged, change `exit-code: '0'` to `'1'` and decide the severity floor. Left open indefinitely, this becomes a dashboard nobody reads.
3. **Decide who reviews the Security tab and how often.** SARIF upload puts findings somewhere; it does not put them in front of anyone.
4. **Decide whether the pre-existing SpotBugs/PMD backlog is fixed or deferred** (Task 1 Step 3). If the workflow shipped with `test` instead of `verify`, that debt is real and currently invisible.
5. **The React client and the fact-graph's own tests are still uncovered.** The client has three separate `test:ci` scripts and its own lint; the fact-graph has a Scala.js cross-build. Both are follow-ups, and until they land a green pipeline does not mean the whole repository is tested.
