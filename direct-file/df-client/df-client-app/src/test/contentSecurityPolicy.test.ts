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

    const hash = createHash(`sha256`).update(scriptMatch![1], `utf8`).digest(`base64`);

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
