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
