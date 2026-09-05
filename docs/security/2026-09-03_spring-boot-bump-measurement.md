# Spring Boot version bump — measured impact

**Methodology:** `./mvnw cyclonedx:makeBom` + `trivy sbom` run per-module against
`backend`, `state-api`, `status`, `submit`, `email-service`, `libs/data-models` —
the same six modules and the same tool chain CI's dependency-scan job uses.
Counts below are the raw sum across modules, **not deduplicated** — the same CVE
appearing in five modules counts five times. This is why these numbers differ
from both the stale `ci.yml` comment (which quoted a raw count from an older
run) and from GitHub Code Scanning's dashboard total (62 open alerts, 14
critical / 48 high), which dedupes a shared CVE across modules down to one
alert. All three numbers are legitimate; they answer different questions. This
document's numbers answer "how many raw per-module findings does each Spring
Boot line produce," because that is what Task 2 through Task 5 act on.

Each version was applied to `boms/irs-spring-boot-starter-parent/pom.xml`
in isolation, measured, then reverted — no production change lands from this
task. The pom edits made for measurement were reverted via `git checkout --`
before this file was written; `git status --short` shows only this new file.

**A build-breaking finding changed the measurement setup for every row after
3.3.10.** `spring-boot-dependencies` manages `com.squareup.okhttp3:okhttp-bom`
at 4.12.0 through 3.3.x, and drops it entirely starting at 3.4.0 — verified
directly against the cached `spring-boot-dependencies` POMs for 3.3.13 and
3.4.13 (`grep okhttp` on the 3.3.13 POM finds the BOM import at version
4.12.0; the same grep against 3.4.13 finds nothing). `backend` and
`state-api` each declare `okhttp`/`mockwebserver` as test-scope dependencies
with no explicit version, relying entirely on that BOM — so both modules
fail to even load their POM ("`dependencies.dependency.version` ... is
missing") on any Spring Boot line at or above 3.4.0, independent of any CVE
work.

The fix: import `okhttp-bom` directly in
`boms/irs-spring-boot-starter-parent/pom.xml`, pinned to the same 4.12.0
that 3.3.x already resolves via Spring Boot's own BOM — this restores
exactly today's resolved versions, it does not pin backward or introduce a
new one. To keep every row in the table on identical footing, the import
was added before measuring and **all four rows below include it** (added,
then measured — including re-measuring 3.3.13, where it is a true no-op:
re-running 3.3.13 with the import in place reproduced its own without-import
numbers exactly, 49 CRITICAL / 240 HIGH both times). The import is not part
of this task's committed changes — it was applied only for measurement and
reverted along with every version bump. Task 2 or Task 3 will need to add it
for real if a 3.4+ line is chosen, since without it the affected services
don't build at all.

## Results

| Version | CRITICAL | HIGH | Builds? | Notes |
|---|---|---|---|---|
| 3.3.10 (current) | 49 | 257 | yes | Baseline. No okhttp-bom import needed — 3.3.x manages it natively. |
| 3.3.13 | 49 | 240 | yes | Latest 3.3.x patch. 0 CRITICAL cleared; 17 fewer HIGH (257→240, -7%). All tests pass (backend 240/240, state-api 136 run/11 skipped/0 fail, email-service 33/33). |
| 3.4.13 | 49 | 214 | yes, with the okhttp-bom import above (fails to build without it) | 0 CRITICAL cleared; 43 fewer HIGH than baseline (257→214, -17%). Same test results as 3.3.13 with the import in place. |
| 3.5.16 | 24 | 35 | yes, with the same okhttp-bom import | 25 fewer CRITICAL than baseline (49→24, -51%); 222 fewer HIGH (257→35, -86%). Same test results: backend 240/240, state-api 136 run/11 skipped/0 fail, email-service 33/33. |

## Recommendation

**3.5.16.** It is the only candidate that meaningfully moves the CRITICAL
count at all — both patch-level 3.3.x and the 3.4.x minor bump leave all 49
raw CRITICAL findings standing, while 3.5.16 clears roughly half of them and
the large majority of HIGH findings. This confirms the plan's working
hypothesis: 3.3.x is old enough that its own patch releases are not carrying
security backports for the bulk of this transitive cluster (tomcat-embed-core,
the `io.netty` cluster, `spring-security-web`, `thymeleaf`, and the rest of
what `spring-boot-starter-parent` transitively manages) — only a jump to a
currently-supported minor line does. All three services plus
`libs/data-models` build cleanly and pass their existing test suites
unchanged at 3.5.16, with no exclusions, no transitive pin-backs, and no
disabled tests — the only change beyond the version bump itself is the
okhttp-bom import restoring a test-scope dependency Spring Boot itself
stopped managing, at the exact version already in use today.

## What a bump does not fix

3.5.16 still leaves 24 raw CRITICAL / 35 raw HIGH findings. This residue —
not the version bump — is what Task 3 (direct `<dependencyManagement>` pins
for anything with a `FixedVersion`) and Task 4 (`.trivyignore` for anything
without one) exist to close. Task 3 should parse the residue from 3.5.16's
own `trivy sbom --format json` output, not from this raw per-module sum: a
CVE that shows up as, say, six raw findings across six modules is one pin,
not six.
