# Framing Protection and CSP Response Headers Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Close D-4 as far as this repository can: give both client applications framing protection and a header-delivered Content-Security-Policy in the nginx configurations the repo actually ships, and state precisely what still depends on the production edge.

**Architecture:** Both nginx configurations currently live inside escaped `RUN echo "…"` shell strings in their Dockerfiles. A CSP contains double quotes, single quotes, and semicolons, all of which have to survive two layers of escaping to land correctly — so the first move is extracting each configuration to a checked-in file. `df-client-app`'s config is parameterised by `DF_CLIENT_PUBLIC_PATH`, so it becomes an nginx *template* processed by the official image's `envsubst` entrypoint; `df-static-site`'s takes no parameters and becomes a plain conf. Each then gains a `Content-Security-Policy` response header carrying the same policy as its existing `<meta>` tag plus `frame-ancestors 'none'`, an `X-Frame-Options: DENY`, and `always` on every security header. A test in `df-client-app`'s suite asserts the header and meta policies stay identical apart from `frame-ancestors`, so the two cannot silently diverge.

**Tech Stack:** nginx (official Docker image), Docker, Vitest 1.6.1, TypeScript.

**Spec:** `docs/security/2026-09-02_delta-security-review.md` finding D-4, left deliberately open by PR #11.

## Global Constraints

- **Backtick string literals in TypeScript.** ESLint enforces it repo-wide (`const x = \`value\`;`).
- **`npm run lint` must pass with `--max-warnings=0`.**
- **Docker is required** for Tasks 1 and 2's verification steps. If it is unavailable, say so and stop — do not mark a config verified that was never parsed by nginx.
- **The build context for both Dockerfiles is `direct-file/df-client`** (`docker-compose.yaml:131,142`), so `COPY` paths are relative to that directory.
- **Do not change either policy's existing directives.** This plan moves a policy to a header and adds framing protection. Any other directive change is a separate decision with its own breakage risk.

---

## What is and is not being fixed

Neither application has clickjacking protection of any kind. A repository-wide search finds no `X-Frame-Options`, no `frame-ancestors`, and no Spring Security `frameOptions` — the only match is the comment in `df-client-app/index.html:9` explaining that meta delivery cannot express it.

**The honest limit of this plan: both Dockerfiles are named `-local`.** They are the local/dev serving path; production serving is not in this repository. Fixing them does not fix production, and this plan must not be described as closing D-4 outright.

What it does accomplish is real:

1. The repo's own serving layer stops shipping an app with zero framing protection.
2. The intended policy becomes explicit, checked in, and reviewable in a diff instead of being an assumption about someone else's CDN.
3. Header delivery recovers what meta delivery costs — `frame-ancestors`, and the option of `report-uri` and report-only staging later.

`Dockerfile-local`'s nginx already sets `add_header X-Content-Type-Options nosniff;`, which is the proof that this layer is a legitimate place for security headers. Note it lacks `always`, so it is absent from error responses; Task 1 fixes that too.

---

## Task 1: Extract and harden the `df-client-app` nginx configuration

**Files:**
- Create: `direct-file/df-client/nginx/df-client-app.conf.template`
- Modify: `direct-file/df-client/Dockerfile-local:42-65`

**Interfaces:**
- Consumes: nothing from other tasks.
- Produces: `direct-file/df-client/nginx/df-client-app.conf.template`, which Task 3's sync test reads.

**Why a template rather than a plain conf.** The current config interpolates `${DF_CLIENT_PUBLIC_PATH}` (a build `ARG`) into two `location` blocks. The official nginx image's entrypoint runs `envsubst` over `/etc/nginx/templates/*.template` into `/etc/nginx/conf.d/` at container start, which preserves that parameterisation without a build-time `sed`. It substitutes only variables that are actually exported in the environment, so nginx's own `$uri` survives untouched — but `DF_CLIENT_PUBLIC_PATH` must become an `ENV`, not just an `ARG`, or it will not be in the environment at start time and the location paths will render empty.

Moving to `conf.d` also means the stock `/etc/nginx/nginx.conf` supplies `events {}`, `http {}`, `include mime.types`, and `sendfile on`, so the extracted file is just the `server` block. The stock image's own `default.conf` is overwritten by the rendered template, so nothing is left listening on port 80.

- [ ] **Step 1: Record the current behavior to compare against**

```bash
cd direct-file/df-client
sed -n '42,65p' Dockerfile-local
```

Expected: the `RUN echo "events {}…"` block. Note the four properties that must survive: `listen 3000`, `autoindex off`, `server_tokens off`, `gzip_static on`, plus `root /static` and the two `location` blocks.

- [ ] **Step 2: Create the template**

Create `direct-file/df-client/nginx/df-client-app.conf.template`:

```nginx
# Rendered to /etc/nginx/conf.d/default.conf at container start by the official nginx
# image's envsubst entrypoint, which substitutes DF_CLIENT_PUBLIC_PATH. nginx's own
# runtime variables ($uri) are untouched: envsubst only replaces variables that are
# exported in the environment.
#
# Extracted from Dockerfile-local, where this lived inside an escaped `RUN echo "..."`
# shell string. The Content-Security-Policy below has double quotes, single quotes, and
# semicolons in it; keeping it in a checked-in file is what makes it reviewable.
server {
    listen 3000;
    autoindex off;
    server_name _;
    server_tokens off;
    root /static;
    gzip_static on;

    # `always` on every one of these: without it nginx omits the header from error
    # responses, so a 404 rendering the SPA shell would ship without a policy.
    add_header X-Content-Type-Options nosniff always;

    # Clickjacking protection. The <meta> CSP in index.html cannot express
    # frame-ancestors -- it is header-only -- which is why this header exists.
    # X-Frame-Options is redundant for browsers that honour frame-ancestors and is kept
    # for those that do not.
    add_header X-Frame-Options DENY always;

    # Identical to the <meta http-equiv="Content-Security-Policy"> in
    # df-client-app/index.html, plus frame-ancestors. Both are enforced and the effective
    # policy is their intersection, so they must not diverge --
    # src/test/contentSecurityPolicy.test.ts fails if they do.
    add_header Content-Security-Policy "default-src 'self'; base-uri 'self'; object-src 'none'; form-action 'self'; script-src 'self' 'sha256-hC4yLITI6QgJ9q9gPxAnKXkGcJVe+lNpHs4+YYDrr20=' https://*.googletagmanager.com https://stage.connect.irs.gov https://connect.irs.gov https://resources.digital-cloud-gov.medallia.com; style-src 'self' 'unsafe-inline' https://stage.connect.irs.gov https://connect.irs.gov; style-src-elem 'self' 'unsafe-inline' https://stage.connect.irs.gov https://connect.irs.gov; img-src 'self' data: https://*.google-analytics.com https://*.googletagmanager.com; font-src 'self' data:; connect-src 'self' https://*.google-analytics.com https://*.googletagmanager.com https://stage.connect.irs.gov https://connect.irs.gov; frame-src https://*.googletagmanager.com https://stage.connect.irs.gov https://connect.irs.gov; frame-ancestors 'none';" always;

    location ~ ${DF_CLIENT_PUBLIC_PATH}/(assets|favicon|imgs)/ {
        try_files $uri =404;
    }

    location / {
        try_files $uri ${DF_CLIENT_PUBLIC_PATH}/index.html;
    }
}
```

**The CSP value must match `df-client-app/index.html`'s meta content exactly, directive for directive, with `frame-ancestors 'none'` appended.** The meta version is spread across lines; this is the same policy on one line. Task 3's test is what proves they agree — do not hand-verify and move on.

**`add_header` does not inherit into a `location` that has its own `add_header`.** Neither location here declares one, so the server-level headers apply to both. If a future change adds an `add_header` to a location block, every header above must be repeated there.

- [ ] **Step 3: Replace the echo blob in the Dockerfile**

In `direct-file/df-client/Dockerfile-local`, replace lines 42-65 (from the `# 2. serve static build with nginx.` comment through the closing `> /etc/nginx/nginx.conf`) with:

```dockerfile
# 2. serve static build with nginx
FROM nginx:latest
ARG DF_CLIENT_PUBLIC_PATH=/df/file
# ENV, not just ARG: the entrypoint's envsubst runs at container start, so the variable
# has to be in the environment then, not only at build time.
ENV DF_CLIENT_PUBLIC_PATH=${DF_CLIENT_PUBLIC_PATH}
COPY --from=df-client-builder /build/df-client-app/dist/ /static/${DF_CLIENT_PUBLIC_PATH}
COPY nginx/df-client-app.conf.template /etc/nginx/templates/default.conf.template
```

The `COPY` source is relative to the build context, `direct-file/df-client`.

- [ ] **Step 4: Verify nginx actually parses it**

`nginx -t` cannot read a `.template`, so render it the way the entrypoint would and check the result:

```bash
cd direct-file/df-client
DF_CLIENT_PUBLIC_PATH=/df/file envsubst '${DF_CLIENT_PUBLIC_PATH}' \
  < nginx/df-client-app.conf.template > /tmp/df-client-app.conf
docker run --rm -v /tmp/df-client-app.conf:/etc/nginx/conf.d/default.conf:ro nginx:latest nginx -t
```

Expected: `syntax is ok` and `test is successful`.

If `envsubst` is not installed locally, run it inside the image instead:

```bash
docker run --rm -e DF_CLIENT_PUBLIC_PATH=/df/file \
  -v "$PWD/nginx/df-client-app.conf.template:/etc/nginx/templates/default.conf.template:ro" \
  nginx:latest nginx -t
```

**If Docker is unavailable, stop and report.** Do not proceed on the assumption the config is valid.

- [ ] **Step 5: Verify the headers are actually served**

Building the whole image needs the backend build context, so build it the way compose would:

```bash
cd direct-file
docker build -f df-client/Dockerfile-local \
  --build-context backend=./backend \
  -t df-client-headers-check ./df-client
docker run --rm -d -p 3000:3000 --name df-headers-check df-client-headers-check
curl -sI http://localhost:3000/df/file/index.html | grep -iE "content-security-policy|x-frame-options|x-content-type"
docker rm -f df-headers-check
```

Expected: all three headers present, and the CSP ending in `frame-ancestors 'none';`.

Also confirm a 404 carries them, which is what `always` buys:

```bash
docker run --rm -d -p 3000:3000 --name df-headers-check df-client-headers-check
curl -sI http://localhost:3000/df/file/assets/does-not-exist.js | head -1
curl -sI http://localhost:3000/df/file/assets/does-not-exist.js | grep -ic "content-security-policy"
docker rm -f df-headers-check
```

Expected: `HTTP/1.1 404`, and a count of `1`.

- [ ] **Step 6: Commit**

```bash
cd ../..
git add direct-file/df-client/nginx/df-client-app.conf.template direct-file/df-client/Dockerfile-local
git commit -m "fix(client): serve a CSP response header with frame-ancestors for df-client-app

The app that renders taxpayer data had no clickjacking protection of any
kind -- no X-Frame-Options, no frame-ancestors, nothing. Its CSP is
delivered by <meta>, and frame-ancestors is header-only, so the gap was
not closeable without a response header.

The nginx config moves out of the escaped RUN echo string into a checked-in
template. A policy containing double quotes, single quotes, and semicolons
should not have to survive two layers of shell escaping to be correct, and
it could not be reviewed in a diff where it did.

The header policy is identical to the meta policy plus frame-ancestors;
both are enforced and the effective policy is their intersection, so a
test keeps them in sync. Adds `always` so the headers reach error
responses too -- the existing nosniff header lacked it.

This is the -local serving path. Production serving is not in this
repository and is still unverified. Refs D-4."
```

---

## Task 2: Extract and harden the `df-static-site` nginx configuration

**Files:**
- Create: `direct-file/df-client/nginx/df-static-site.conf`
- Modify: `direct-file/df-client/Dockerfile-static-site-local:37-55`

**Interfaces:**
- Consumes: nothing from other tasks.
- Produces: `direct-file/df-client/nginx/df-static-site.conf`, which Task 3's sync test reads.

This config takes no build parameters, so it is a plain `.conf` copied straight into `conf.d` — no template, no `envsubst`. It currently sets **no security headers at all**, not even the `nosniff` the app config has.

- [ ] **Step 1: Create the config**

Create `direct-file/df-client/nginx/df-static-site.conf`:

```nginx
# Copied to /etc/nginx/conf.d/default.conf, replacing the stock one. No build
# parameters, so unlike df-client-app.conf.template this needs no envsubst.
#
# Extracted from Dockerfile-static-site-local, where it lived inside an escaped
# `RUN echo "..."` shell string.
server {
    listen 3500;
    autoindex off;
    server_name _;
    server_tokens off;
    root /static;
    gzip_static on;

    # This config previously set no security headers at all.
    add_header X-Content-Type-Options nosniff always;
    add_header X-Frame-Options DENY always;

    # Identical to the <meta http-equiv="Content-Security-Policy"> in
    # df-static-site/index.html, plus frame-ancestors. Kept in sync by
    # df-client-app's src/test/contentSecurityPolicy.test.ts.
    #
    # This policy is looser than df-client-app's -- 'unsafe-inline' in script-src, a
    # jQuery CDN, several third-party origins. That is the existing policy for the
    # public marketing site and this plan does not change it; it only moves it to a
    # header and adds framing protection.
    add_header Content-Security-Policy "default-src 'self'; object-src 'none'; form-action 'none'; style-src 'self' 'unsafe-inline' https://www.ssa.gov/accessibility/andi/andi.css https://www.ssa.gov/accessibility/andi/gandi.css https://www.ssa.gov/accessibility/andi/landi.css https://www.ssa.gov/accessibility/andi/handi.css https://www.ssa.gov/accessibility/andi/candi.css https://www.ssa.gov/accessibility/andi/sandi.css https://stage.connect.irs.gov https://connect.irs.gov; style-src-elem 'self' 'unsafe-inline' https://stage.connect.irs.gov https://connect.irs.gov; frame-src https://www.youtube.com https://stage.connect.irs.gov https://connect.irs.gov; script-src 'self' 'unsafe-inline' https://*.googletagmanager.com https://resources.digital-cloud-gov.medallia.com https://dap.digitalgov.gov http://resources.digital-cloud-gov.medallia.com https://www.ssa.gov/accessibility/andi/ https://ajax.googleapis.com/ajax/libs/jquery/3.7.1/jquery.min.js https://stage.connect.irs.gov https://connect.irs.gov; script-src-attr 'self' 'unsafe-inline' https://stage.connect.irs.gov https://connect.irs.gov; img-src 'self' data: https://*.google-analytics.com https://*.googletagmanager.com https://www.ssa.gov; frame-ancestors 'none';" always;

    location / {
        try_files $uri /index.html;
    }
}
```

> **`frame-src https://www.youtube.com` and `frame-ancestors 'none'` do not conflict.** `frame-src` controls what this page may embed; `frame-ancestors` controls who may embed this page. Adding the latter does not affect the embedded YouTube player.

- [ ] **Step 2: Replace the echo blob**

In `direct-file/df-client/Dockerfile-static-site-local`, replace lines 37-55 (from the `# 2. serve static build with nginx.` comment through `> /etc/nginx/nginx.conf`) with:

```dockerfile
# 2. serve static build with nginx
FROM nginx:latest
COPY --from=df-static-site-builder /build/df-static-site/dist/ /static
COPY nginx/df-static-site.conf /etc/nginx/conf.d/default.conf
```

- [ ] **Step 3: Verify nginx parses it**

```bash
cd direct-file/df-client
docker run --rm -v "$PWD/nginx/df-static-site.conf:/etc/nginx/conf.d/default.conf:ro" nginx:latest nginx -t
```

Expected: `syntax is ok` and `test is successful`.

- [ ] **Step 4: Verify the headers are served**

This service is active in compose (unlike `df-client`), so build it through compose:

```bash
cd ..
docker compose build df-static-site
docker compose up -d df-static-site
curl -sI http://localhost:3500/ | grep -iE "content-security-policy|x-frame-options|x-content-type"
docker compose down df-static-site
```

Expected: all three headers, CSP ending in `frame-ancestors 'none';`.

If the compose service name differs from `df-static-site`, read it from `docker-compose.yaml` rather than guessing.

- [ ] **Step 5: Commit**

```bash
cd ..
git add direct-file/df-client/nginx/df-static-site.conf direct-file/df-client/Dockerfile-static-site-local
git commit -m "fix(client): serve security headers for df-static-site

This config set no security headers at all -- not even the nosniff the
df-client-app config had. It now sends the same CSP as the page's <meta>
tag plus frame-ancestors 'none', X-Frame-Options, and nosniff, all with
`always` so they reach error responses.

Config extracted from the escaped RUN echo string for the same reason as
df-client-app's: a policy with quotes and semicolons in it should be
reviewable in a diff.

The policy's own directives are unchanged -- it is looser than the app's,
and tightening it is a separate decision. Refs D-4."
```

---

## Task 3: Keep the header and meta policies from diverging

**Files:**
- Modify: `direct-file/df-client/df-client-app/src/test/contentSecurityPolicy.test.ts`

**Interfaces:**
- Consumes: the two nginx files from Tasks 1 and 2.
- Produces: nothing other tasks consume.

**Why this test earns its place.** Both delivery mechanisms are enforcing, and when a page carries both, the browser applies their **intersection**. A directive tightened in one and not the other silently narrows the effective policy — most likely breaking the app rather than weakening it, but breaking it in a way that reproduces only in a container, not in `npm run dev`. The inline GTM bootstrap's `sha256-` hash is in both copies, so editing `index.html`'s script now desynchronises three things rather than two.

`df-client-app`'s suite is the only client test suite in CI, so the `df-static-site` check lives here too.

- [ ] **Step 1: Add the parser and both checks**

Append to `direct-file/df-client/df-client-app/src/test/contentSecurityPolicy.test.ts`. **No new imports are needed** — the file already imports `readFileSync` from `fs` and `resolve` from `path` at lines 2-3.

The file also already has a module-level `indexHtml` constant and a `cspMatch` regex, both hardcoded to `df-client-app/index.html`. Leave them alone; the helpers below take a path so they can serve both applications. The small duplication is deliberate — rewriting the existing assertions to use the new helpers would mix a refactor into a security change.

```ts
/**
 * Parses a CSP into directive -> value. Order and whitespace are not significant to a
 * browser, so comparing normalised maps avoids a test that fails on reformatting.
 */
const parsePolicy = (policy: string): Map<string, string> =>
  new Map(
    policy
      .split(`;`)
      .map((directive) => directive.trim().replace(/\s+/g, ` `))
      .filter((directive) => directive.length > 0)
      .map((directive) => {
        const firstSpace = directive.indexOf(` `);
        return firstSpace === -1
          ? ([directive, ``] as const)
          : ([directive.slice(0, firstSpace), directive.slice(firstSpace + 1)] as const);
      })
  );

const metaPolicyFrom = (html: string): string => {
  const match = /http-equiv="Content-Security-Policy"\s*\n?\s*content="([^"]*)"/.exec(html);
  if (match === null) {
    throw new Error(`no <meta http-equiv="Content-Security-Policy"> found`);
  }
  return match[1];
};

const headerPolicyFrom = (nginxConf: string): string => {
  const match = /add_header\s+Content-Security-Policy\s+"([^"]*)"/.exec(nginxConf);
  if (match === null) {
    throw new Error(`no add_header Content-Security-Policy found`);
  }
  return match[1];
};

describe(`CSP header and meta stay in sync`, () => {
  // Both delivery mechanisms are enforcing and a browser applies their INTERSECTION, so
  // a directive changed in one place and not the other silently narrows the real policy.
  const cases = [
    {
      name: `df-client-app`,
      html: resolve(__dirname, `../../index.html`),
      conf: resolve(__dirname, `../../../nginx/df-client-app.conf.template`),
    },
    {
      name: `df-static-site`,
      html: resolve(__dirname, `../../../df-static-site/index.html`),
      conf: resolve(__dirname, `../../../nginx/df-static-site.conf`),
    },
  ];

  cases.forEach(({ name, html, conf }) => {
    it(`${name}: the header policy is the meta policy plus frame-ancestors`, () => {
      const meta = parsePolicy(metaPolicyFrom(readFileSync(html, `utf8`)));
      const header = parsePolicy(headerPolicyFrom(readFileSync(conf, `utf8`)));

      // frame-ancestors is the whole reason the header exists -- meta delivery ignores it.
      expect(header.get(`frame-ancestors`)).toBe(`'none'`);
      header.delete(`frame-ancestors`);

      expect(Object.fromEntries([...header].sort())).toEqual(Object.fromEntries([...meta].sort()));
    });

    it(`${name}: the nginx config sends X-Frame-Options with always`, () => {
      expect(readFileSync(conf, `utf8`)).toMatch(/add_header\s+X-Frame-Options\s+DENY\s+always;/);
    });
  });
});
```

Confirm the relative paths resolve. From `df-client-app/src/test/`: `../..` is `df-client-app`, `../../..` is `df-client`. So `../../index.html` is the app's page and `../../../nginx/…` and `../../../df-static-site/index.html` are siblings under `df-client`.

- [ ] **Step 2: Run the test**

```bash
cd direct-file/df-client/df-client-app
npx vitest --run src/test/contentSecurityPolicy.test.ts
```

Expected: the pre-existing assertions plus four new ones, all passing.

**If the sync assertion fails, the fix is in the nginx file, not the test.** A mismatch means Task 1 or 2 transcribed the policy imperfectly — that is precisely what this test is for. Read the diff in the failure output and correct the config.

- [ ] **Step 3: Prove the test detects drift**

```bash
sed -i.bak "s/font-src 'self' data:; //" ../nginx/df-client-app.conf.template
npx vitest --run src/test/contentSecurityPolicy.test.ts
```

Expected: FAILS on the `df-client-app` sync assertion, showing `font-src` present in meta and absent from header.

Restore and confirm clean:

```bash
mv ../nginx/df-client-app.conf.template.bak ../nginx/df-client-app.conf.template
git diff --exit-code ../nginx/df-client-app.conf.template && echo "restored cleanly"
npx vitest --run src/test/contentSecurityPolicy.test.ts
```

Expected: `restored cleanly`, then all assertions pass.

- [ ] **Step 4: Run the full suite and lint**

```bash
npm run lint && npm run test:ci
```

Expected: both green.

- [ ] **Step 5: Commit**

```bash
cd ../../..
git add direct-file/df-client/df-client-app/src/test/contentSecurityPolicy.test.ts
git commit -m "test(client): assert the CSP header and meta policies stay in sync

Both delivery mechanisms are enforcing and a browser applies their
intersection, so a directive changed in one place and not the other
silently narrows the effective policy -- and would reproduce only in a
container, not under npm run dev. The inline bootstrap's sha256 hash now
lives in two files, so editing that script desynchronises three things.

Compares normalised directive maps rather than strings, so reformatting
either file does not fail the test. Covers df-static-site too: this is
the only client suite in CI."
```

---

## Task 4: Record what is and is not covered

**Files:**
- Modify: `direct-file/README.md`

**Interfaces:**
- Consumes: Tasks 1-3.
- Produces: nothing other tasks consume.

The delta review is a dated artifact and is **not** rewritten — it records what was true on 2026-09-02. The README is the live document.

- [ ] **Step 1: Add a section to the README**

Add under the client documentation:

```markdown
### Security headers

Both client applications are served by nginx configurations checked in under
`df-client/nginx/`, rather than embedded in their Dockerfiles. Each sends
`Content-Security-Policy`, `X-Frame-Options: DENY`, and `X-Content-Type-Options: nosniff`,
all with `always` so they reach error responses.

The CSP is delivered **twice**: as a response header and as the `<meta http-equiv>` tag in
each `index.html`. Both are enforcing and a browser applies their intersection, so they must
stay identical apart from `frame-ancestors`, which meta delivery cannot express — that is the
whole reason the header exists. `df-client-app/src/test/contentSecurityPolicy.test.ts` fails
if they diverge, for both applications.

**These are the `-local` Dockerfiles.** Production serving is not in this repository, so
whether production sends these headers is unverified and cannot be verified from here. If the
production edge or CDN sets its own CSP, it will intersect with the meta tag exactly as these
do, and the two need to be reconciled deliberately rather than discovered. See finding D-4 in
`docs/security/2026-09-02_delta-security-review.md`.
```

- [ ] **Step 2: Commit**

```bash
git add direct-file/README.md
git commit -m "docs: record the client security headers and what they do not cover

Both apps now send CSP, X-Frame-Options, and nosniff from checked-in
nginx configs, with the CSP delivered twice and kept in sync by test.

States the limit plainly: these are the -local Dockerfiles, production
serving is not in this repository, and D-4 is not closed by this work."
```

---

## Handbacks

1. **D-4 is not closed.** This plan hardens the serving path this repository ships, which is the local/dev one. Whether production sends framing protection still requires someone who can inspect the deployment edge, and that answer should be recorded in the review's D-4 entry when it is known.

2. **A production edge CSP would intersect with the meta tag.** If the edge sets its own `Content-Security-Policy`, the effective policy becomes edge ∩ meta, and a directive the edge omits is not thereby permitted — it is still constrained by the meta tag, and vice versa. That interaction is invisible from this repository and is a likely source of "it works locally" breakage. Removing the meta tag once a header is guaranteed everywhere would make the policy single-sourced, but only once that guarantee actually exists.

3. **`report-uri` and report-only staging are now possible and still unused.** Header delivery removes the limitation that made them impossible, so a future change could stage policy changes in report-only mode rather than shipping them enforcing. Nothing in this plan does that.

4. **`df-static-site`'s policy is materially looser than the app's** — `'unsafe-inline'` in `script-src`, a jQuery CDN, and several third-party origins. Untouched here deliberately, since moving a policy and changing a policy are different risks, but it is worth a look on its own terms.

5. **Branch protection on `main` is still not applied** — `gh api repos/twarn247/direct-file/branches/main/protection` returns 404. Fourth plan to carry this.

6. **The original review's register is fully closed except D-4**; H-1, M-1 through M-5, L-1 through L-8, and D-1, D-2, D-3, D-5 are all addressed.
