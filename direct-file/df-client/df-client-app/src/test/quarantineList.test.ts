import { readFileSync } from 'fs';
import { resolve } from 'path';

const appRoot = resolve(__dirname, `../..`);

// Keep in sync with the README's CI quarantine table -- both describe the same three files.
const QUARANTINED = [
  `src/misc/apiHelpers.test.ts`,
  `src/test/factDictionaryTests/hsa.test.ts`,
  `src/test/scenarioTests/flowSnapshots.test.ts`,
].sort();

describe(`test:ci quarantine list`, () => {
  it(`excludes exactly the documented known-failing files`, () => {
    const pkg = JSON.parse(readFileSync(resolve(appRoot, `package.json`), `utf8`));
    const testCiScript: string = pkg.scripts[`test:ci`];

    // test:ci's --exclude value is a single brace-expanded glob, e.g.
    // --exclude 'src/{a/*,b/*,misc/apiHelpers.test.ts}'. Repeated --exclude flags are not
    // supported by this vitest CLI version (it throws "Expected a single value for option").
    const excludeMatch = testCiScript.match(/--exclude '([^']+)'/);
    expect(excludeMatch, `test:ci script must have an --exclude flag`).not.toBeNull();

    const excludeGlob = excludeMatch![1];
    const braceMatch = excludeGlob.match(/^src\/\{(.+)\}$/);
    expect(braceMatch, `expected a single src/{...} brace-expanded glob, got: ${excludeGlob}`).not.toBeNull();

    const entries = braceMatch![1].split(`,`).map((entry) => `src/${entry}`);
    const quarantinedFiles = entries.filter((entry) => entry.endsWith(`.test.ts`) || entry.endsWith(`.test.tsx`)).sort();

    expect(quarantinedFiles).toEqual(QUARANTINED);
  });
});
