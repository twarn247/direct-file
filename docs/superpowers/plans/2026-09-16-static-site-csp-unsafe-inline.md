# Remove `'unsafe-inline'` from the Static Site's script-src Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace `'unsafe-inline'` in `df-static-site`'s `script-src` with a hash of its single inline script, staging the change in report-only mode first — the capability header delivery unlocked and has not yet been used.

**Architecture:** `df-static-site`'s policy permits any inline script, which is the exact class of injection a CSP exists to stop. The page has one inline `<script>` — the Google Tag Manager bootstrap — and it is byte-identical to the one `df-client-app` already allows by SHA-256 hash, so the replacement value is known-good and already enforcing in production for the sibling app. Because the policy now ships as a response header, the tightened version can be staged as `Content-Security-Policy-Report-Only` alongside the enforcing one and exercised in a browser before anything is enforced. Task 1 does that and gates on a manual pass; Task 2 applies it to both the header and the `<meta>` tag, which an existing test already keeps in sync; Task 3 documents it.

**Tech Stack:** nginx, Docker Compose, Vite, Vitest, CSP Level 3.

**Spec:** Handback #4 of `docs/superpowers/plans/2026-09-03-framing-protection-and-csp-headers.md` — "`df-static-site`'s policy is materially looser than the app's — `'unsafe-inline'` in `script-src`, a jQuery CDN, and several third-party origins." Handback #3 of the same plan noted report-only staging became possible and was still unused; this plan uses it.

## Global Constraints

- **Backtick string literals in TypeScript.** ESLint enforces it repo-wide.
- **`npm run lint` must pass with `--max-warnings=0`.**
- **The header and `<meta>` policies must stay identical apart from `frame-ancestors`.** `df-client-app/src/test/contentSecurityPolicy.test.ts` enforces this for both apps; a change to one without the other fails the build.
- **Do not change any directive other than `script-src` and, if Task 1 justifies it, `script-src-attr`.** The looser third-party origins and `style-src 'unsafe-inline'` are separate decisions with separate breakage risks.
- **Docker is required** for Task 1's verification. If unavailable, stop and say so — this change must not be enforced without a browser pass.

---

## What is being changed and why it is low-risk

`direct-file/df-client/nginx/df-static-site.conf` and `df-static-site/index.html` both carry:

```
script-src 'self' 'unsafe-inline' https://*.googletagmanager.com https://resources.digital-cloud-gov.medallia.com https://dap.digitalgov.gov http://resources.digital-cloud-gov.medallia.com https://www.ssa.gov/accessibility/andi/ https://ajax.googleapis.com/ajax/libs/jquery/3.7.1/jquery.min.js https://stage.connect.irs.gov https://connect.irs.gov
```

`'unsafe-inline'` permits *any* inline script, including one an attacker injects. Everything else in that list is an origin allowlist, which `'unsafe-inline'` makes largely moot for the injection case.

Measured on the page as it stands:

| Property | Count |
| --- | --- |
| inline `<script>` blocks | **1** (the GTM bootstrap) |
| `<script src=…>` elements | 1 (external, already allowlisted) |
| inline event handlers (`onclick=` etc.) | **0** |

The single inline script hashes to:

```
sha256-hC4yLITI6QgJ9q9gPxAnKXkGcJVe+lNpHs4+YYDrr20=
```

**That is the same hash already present in `df-client-app`'s enforcing `script-src`** — the two pages carry the identical GTM bootstrap. So this is not a new value to validate; it is a value already proven to work in an enforcing policy on the sibling application.

**The residual risk is runtime-injected inline script, not the bootstrap.** GTM custom HTML tags can inject further inline scripts, and ANDI (the SSA accessibility tool at `https://www.ssa.gov/accessibility/andi/`) manipulates the DOM heavily. A bootstrap-only hash does not cover those. That is precisely what Task 1's report-only pass is for, and it is the reason this plan does not simply flip the directive and ship.

---

## Task 1: Stage the tightened policy in report-only and verify it in a browser

**Files:**
- Modify: `direct-file/df-client/nginx/df-static-site.conf` (temporary — reverted at the end of this task)

**Interfaces:**
- Consumes: nothing.
- Produces: a recorded verdict on whether the hashed policy holds, which Task 2 acts on. **No production change lands in this task.**

**Why report-only rather than enforcing-and-see.** When this policy lived in a `<meta>` tag, report-only was impossible — that limitation is why the original CSP work used a blocking manual pass against an enforcing policy. Moving to a response header removed it. A report-only header applies the tightened policy, reports every violation to the console, and **breaks nothing** if it is wrong, so the page can be exercised fully rather than abandoned at the first failure.

- [ ] **Step 1: Confirm the hash against the current file**

Do not take the value above on trust — the file may have changed.

```bash
cd /Users/thomaswarn/repo/direct-file/direct-file/df-client/df-static-site
python3 -c "
import re, hashlib, base64
html = open('index.html').read()
blocks = re.findall(r'<script>([\s\S]*?)</script>', html)
print('inline script blocks:', len(blocks))
for b in blocks:
    print('  sha256-' + base64.b64encode(hashlib.sha256(b.encode()).digest()).decode())
"
```

Expected: exactly one block, hashing to `sha256-hC4yLITI6QgJ9q9gPxAnKXkGcJVe+lNpHs4+YYDrr20=`.

**If there is more than one block, every one needs its own hash in the directive.** If the hash differs from the value above, use the computed one and note the discrepancy — the file has changed since 2026-09-16.

- [ ] **Step 2: Confirm the built output preserves the script byte-for-byte**

The hash covers the exact bytes between the tags. Vite processes `index.html` during the build, so the source hash is only correct if the build leaves the inline script untouched.

```bash
cd /Users/thomaswarn/repo/direct-file/direct-file/df-client
docker compose -f ../docker-compose.yaml build df-static-site 2>&1 | tail -5
cid=$(docker create $(docker compose -f ../docker-compose.yaml config --images df-static-site 2>/dev/null | head -1) 2>/dev/null) || cid=""
if [ -n "$cid" ]; then
  docker cp "$cid:/static/index.html" /tmp/built-index.html && docker rm "$cid" > /dev/null
  python3 -c "
import re, hashlib, base64
html = open('/tmp/built-index.html').read()
for b in re.findall(r'<script>([\s\S]*?)</script>', html):
    print('built:', 'sha256-' + base64.b64encode(hashlib.sha256(b.encode()).digest()).decode())
"
fi
```

Expected: the built hash matches the source hash from Step 1.

**If they differ, the source hash is the wrong value to ship** — use the built one, and note in the PR that the two diverge, because the sync test compares the header against the *source* `index.html`'s meta tag and that assumption would then be wrong.

- [ ] **Step 3: Add the report-only header**

In `direct-file/df-client/nginx/df-static-site.conf`, add **alongside** the existing enforcing `Content-Security-Policy` — do not modify that one yet:

```nginx
    # TEMPORARY, Task 1 only. The tightened policy, staged in report-only so violations
    # are reported without breaking the page. Report-only became possible when this
    # policy moved from a <meta> tag to a response header. Removed in Task 2, which
    # either promotes this policy to enforcing or records why it could not be.
    add_header Content-Security-Policy-Report-Only "default-src 'self'; object-src 'none'; form-action 'none'; style-src 'self' 'unsafe-inline' https://www.ssa.gov/accessibility/andi/andi.css https://www.ssa.gov/accessibility/andi/gandi.css https://www.ssa.gov/accessibility/andi/landi.css https://www.ssa.gov/accessibility/andi/handi.css https://www.ssa.gov/accessibility/andi/candi.css https://www.ssa.gov/accessibility/andi/sandi.css https://stage.connect.irs.gov https://connect.irs.gov; style-src-elem 'self' 'unsafe-inline' https://stage.connect.irs.gov https://connect.irs.gov; frame-src https://www.youtube.com https://stage.connect.irs.gov https://connect.irs.gov; script-src 'self' 'sha256-hC4yLITI6QgJ9q9gPxAnKXkGcJVe+lNpHs4+YYDrr20=' https://*.googletagmanager.com https://resources.digital-cloud-gov.medallia.com https://dap.digitalgov.gov http://resources.digital-cloud-gov.medallia.com https://www.ssa.gov/accessibility/andi/ https://ajax.googleapis.com/ajax/libs/jquery/3.7.1/jquery.min.js https://stage.connect.irs.gov https://connect.irs.gov; script-src-attr 'self' 'unsafe-inline' https://stage.connect.irs.gov https://connect.irs.gov; img-src 'self' data: https://*.google-analytics.com https://*.googletagmanager.com https://www.ssa.gov; frame-ancestors 'none';" always;
```

This is the existing policy with **one change**: `'unsafe-inline'` removed from `script-src` and the hash added. `script-src-attr` is left as-is for now — Step 5 decides it.

There is no `report-uri`, so violations surface in the browser console only. That is sufficient for a manual pass and avoids standing up a collector for a one-off verification.

- [ ] **Step 4: Run it and exercise the page**

```bash
cd /Users/thomaswarn/repo/direct-file/direct-file
docker compose build df-static-site && docker compose up -d df-static-site
curl -sI http://localhost:3500/ | grep -ic "content-security-policy-report-only"
```

Expected: `1`.

Then open `http://localhost:3500/` with the browser console open and work through all of these. **This is a blocking manual step — a human has to do it.** Record each outcome:

- [ ] Landing page loads with zero `Content-Security-Policy-Report-Only` violations in the console
- [ ] **Google Tag Manager still loads** — Network tab shows `gtm.js` returning 200, and `dataLayer` is defined in the console
- [ ] Scroll the full page; expand any accordions or disclosure widgets
- [ ] The YouTube embed renders and plays
- [ ] Any form or eligibility-screener interaction on the page completes
- [ ] The eGain/Medallia widget loads if it is reachable in this build
- [ ] If ANDI is activatable on this page, activate it and confirm no violations

Any violation reported names the directive and the blocked resource. A `script-src` violation naming an inline script means GTM or ANDI injects one the bootstrap hash does not cover.

- [ ] **Step 5: Decide `script-src-attr`**

The source page has **zero** inline event handlers, so `script-src-attr` could go to `'none'`. But third-party scripts can add them at runtime, and `'unsafe-inline'` there currently permits that silently.

Re-run Step 4 with `script-src-attr 'none'` substituted in the report-only header and repeat the checklist. If no `script-src-attr` violations appear, tighten it in Task 2. If any appear, leave the directive unchanged and record what triggered it — a real dependency on inline handlers is worth knowing about regardless.

- [ ] **Step 6: Revert and record**

```bash
cd /Users/thomaswarn/repo/direct-file
docker compose -f direct-file/docker-compose.yaml down df-static-site
git checkout -- direct-file/df-client/nginx/df-static-site.conf
git diff --exit-code direct-file/df-client/nginx/df-static-site.conf && echo "reverted cleanly"
```

Write the verdict into the PR description: every checklist item's outcome, whether any violations appeared, and the `script-src-attr` decision with its evidence. **If violations appeared that the hash cannot cover, stop here** — the correct outcome is then a documented "`'unsafe-inline'` is required because X", not a policy that gets reverted after it breaks the public site.

---

## Task 2: Apply the tightened policy

**Files:**
- Modify: `direct-file/df-client/nginx/df-static-site.conf`
- Modify: `direct-file/df-client/df-static-site/index.html`
- Modify: `direct-file/df-client/df-client-app/src/test/contentSecurityPolicy.test.ts`

**Interfaces:**
- Consumes: Task 1's verdict.
- Produces: an enforcing policy with no `'unsafe-inline'` in `script-src`.

Do not start unless Task 1's manual pass was clean.

- [ ] **Step 1: Update the header**

In `direct-file/df-client/nginx/df-static-site.conf`, in the enforcing `Content-Security-Policy` header, replace `'unsafe-inline'` in `script-src` with `'sha256-hC4yLITI6QgJ9q9gPxAnKXkGcJVe+lNpHs4+YYDrr20='` (or Step 1's computed value). Apply the `script-src-attr` decision from Task 1 Step 5. Update the comment above the directive:

```nginx
    # script-src allows the inline GTM bootstrap by SHA-256 hash rather than
    # 'unsafe-inline', so injected inline script is still blocked. This is the same
    # bootstrap, and the same hash, df-client-app enforces. Editing that script changes
    # its hash -- df-client-app/src/test/contentSecurityPolicy.test.ts fails until this
    # and the <meta> tag in df-static-site/index.html are both updated.
```

- [ ] **Step 2: Update the meta tag to match**

In `direct-file/df-client/df-static-site/index.html`, make the identical `script-src` change to the `<meta http-equiv="Content-Security-Policy">` content.

**Both must change together.** The existing sync test asserts the header equals the meta plus `frame-ancestors`; changing one alone fails it — which is the mechanism working, not an obstacle.

- [ ] **Step 3: Extend the test to cover the static site**

`src/test/contentSecurityPolicy.test.ts:37-43` asserts no `'unsafe-inline'` in `script-src`, but only for `df-client-app` — it reads the module-level `cspMatch`, which is hardcoded to that app's `index.html`. Add the equivalent for the static site inside the existing `describe(\`CSP header and meta stay in sync\`)` block, which already iterates both apps via its `cases` array (lines 88-99):

```ts
    it(`${name}: script-src does not permit arbitrary inline script`, () => {
      // 'unsafe-inline' in script-src defeats the main reason the policy exists. Both
      // pages carry the same GTM bootstrap and allow it by the same hash instead.
      const header = parsePolicy(headerPolicyFrom(readFileSync(conf, `utf8`)));
      const scriptSrc = header.get(`script-src`);

      expect(scriptSrc, `${name} has no script-src directive`).toBeDefined();
      expect(scriptSrc).not.toContain(`'unsafe-inline'`);
      expect(scriptSrc).toMatch(/'sha256-[A-Za-z0-9+/=]+'/);
    });
```

This runs for both apps, so it also locks in `df-client-app`'s existing property against regression — the current assertion covers the meta tag, this covers the header.

- [ ] **Step 4: Run the tests**

```bash
cd /Users/thomaswarn/repo/direct-file/direct-file/df-client/df-client-app
npx vitest --run src/test/contentSecurityPolicy.test.ts
```

Expected: all assertions pass, including the sync check confirming header and meta still agree.

- [ ] **Step 5: Verify the enforcing policy in a browser**

Report-only proved the policy does not *report* violations; this proves it does not *block* anything.

```bash
cd /Users/thomaswarn/repo/direct-file/direct-file
docker compose build df-static-site && docker compose up -d df-static-site
curl -sI http://localhost:3500/ | grep -i "content-security-policy:" | grep -c "unsafe-inline" 
```

Expected: the `grep -c` prints a count that does **not** include a `script-src 'unsafe-inline'` — inspect the header directly to confirm, since `style-src` legitimately still contains `'unsafe-inline'` and would match a naive count.

Then reload the page with the console open and re-run Task 1 Step 4's checklist against the **enforcing** header. Expected: identical behaviour, zero violations.

```bash
docker compose down df-static-site
```

- [ ] **Step 6: Lint and commit**

```bash
cd df-client/df-client-app && npm run lint && cd ../../..
git add direct-file/df-client/nginx/df-static-site.conf \
        direct-file/df-client/df-static-site/index.html \
        direct-file/df-client/df-client-app/src/test/contentSecurityPolicy.test.ts
git commit -m "fix(client): allow df-static-site's inline script by hash, not 'unsafe-inline'

script-src permitted any inline script, which is the class of injection a
CSP exists to stop -- and it made the origin allowlist beside it largely
moot for that case.

The page has exactly one inline script, the GTM bootstrap, and it is
byte-identical to the one df-client-app already enforces by the same
SHA-256 hash. Zero inline event handlers in the source.

Staged in Content-Security-Policy-Report-Only first and exercised in a
browser before enforcing -- the capability that became available when
this policy moved from a <meta> tag to a response header, and had not
been used since.

The no-unsafe-inline assertion now runs for both apps against the header,
alongside the existing meta-tag one."
```

---

## Task 3: Record it

**Files:**
- Modify: `direct-file/README.md`

- [ ] **Step 1: Extend the security-headers section**

```markdown
Neither application's `script-src` permits `'unsafe-inline'`. Both carry the same inline
Google Tag Manager bootstrap and both allow it by the same SHA-256 hash, so injected inline
script is blocked. Editing that script changes its hash and
`df-client-app/src/test/contentSecurityPolicy.test.ts` fails until every copy is updated —
`df-client-app/index.html`, `df-static-site/index.html`, and both files under
`df-client/nginx/`.

Because the policy is header-delivered, a tightening can be staged as
`Content-Security-Policy-Report-Only` alongside the enforcing header and exercised in a
browser before it blocks anything. There is no report collector, so violations appear in the
browser console — enough for a pre-merge pass, which is how the `'unsafe-inline'` removal was
verified.
```

- [ ] **Step 2: Commit**

```bash
git add direct-file/README.md
git commit -m "docs: record that neither app's script-src allows 'unsafe-inline'"
```

---

## Handbacks

1. **`style-src` still carries `'unsafe-inline'` in both apps.** Materially lower risk than script — it enables CSS-based exfiltration and UI redressing, not code execution — and removing it typically requires hashing or noncing every injected style, which component libraries make impractical. Untouched deliberately.

2. **`df-static-site`'s origin allowlist is still broad** — a jQuery CDN (`ajax.googleapis.com`), `dap.digitalgov.gov`, an SSA path, and Medallia over **plain `http://`** as well as `https://`. That `http://` entry is worth a look on its own: it permits a script loaded over cleartext, which an on-path attacker can replace. This plan changed only `script-src`'s inline handling.

3. **A bootstrap-only hash does not cover GTM-injected inline scripts.** If a GTM container later adds a custom HTML tag with inline script, it will be blocked in production with no staging signal, because there is no report collector. Standing one up — or adding `report-uri`/`report-to` pointing at one — would turn that from an outage into an alert.

4. **Moderate and low dependency findings remain ungated** in both ecosystems — 4 MEDIUM in the client npm tree as of 2026-09-09, Maven unmeasured. The natural next ratchet now that both scans are clean at CRITICAL/HIGH.

5. **Dev-tree vulnerabilities are still out of scope and still real.** `vitest`, `@vitest/ui`, and `happy-dom` carry critical advisories and execute on CI runners with repository access.

6. **Branch protection on `main` is still not applied** — `gh api repos/twarn247/direct-file/branches/main/protection` returns 404. Eighth plan to carry this; it now gates two dependency scans and a working-tree guard, none of which is required to merge.
