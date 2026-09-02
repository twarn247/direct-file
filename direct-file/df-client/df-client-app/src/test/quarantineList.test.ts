import { readFileSync } from 'fs';
import { resolve } from 'path';

const appRoot = resolve(__dirname, `../..`);

// Keep in sync with the README's CI quarantine table -- both describe the same two files.
const QUARANTINED = [`src/misc/apiHelpers.test.ts`, `src/test/scenarioTests/flowSnapshots.test.ts`].sort();

describe(`test:ci quarantine list`, () => {
  it(`excludes exactly the documented known-failing files`, () => {
    const pkg = JSON.parse(readFileSync(resolve(appRoot, `package.json`), `utf8`));
    const testCiScript: string = pkg.scripts[`test:ci`];

    // test:ci's --exclude value is a single brace-expanded glob, e.g.
    // --exclude 'src/{a/*,b/*,misc/apiHelpers.test.ts}'. Repeated --exclude flags are not
    // supported by this vitest CLI version (it throws "Expected a single value for option").
    const excludeMatch = testCiScript.match(/--exclude '([^']+)'/);
    if (!excludeMatch) {
      throw new Error(`test:ci script must have an --exclude flag`);
    }

    const excludeGlob = excludeMatch[1];
    const braceMatch = excludeGlob.match(/^src\/\{(.+)\}$/);
    if (!braceMatch) {
      throw new Error(`expected a single src/{...} brace-expanded glob, got: ${excludeGlob}`);
    }

    const entries = braceMatch[1].split(`,`).map((entry) => `src/${entry}`);
    const quarantinedFiles = entries
      .filter((entry) => entry.endsWith(`.test.ts`) || entry.endsWith(`.test.tsx`))
      .sort();

    expect(quarantinedFiles).toEqual(QUARANTINED);
  });

  it(`the quarantine-watch script runs exactly the same files`, () => {
    // test:ci excludes these files; test:ci:quarantine-watch runs only them, inverting the
    // exit code so CI stays green while they're still failing and goes red the moment any
    // of them starts passing -- that's the signal to remove it from both places above.
    const pkg = JSON.parse(readFileSync(resolve(appRoot, `package.json`), `utf8`));
    const watchScript: string = pkg.scripts[`test:ci:quarantine-watch`];

    const fileArgs = watchScript
      .replace(/^vitest run --silent /, ``)
      .replace(/; test \$\? -ne 0$/, ``)
      .split(` `)
      .sort();

    expect(fileArgs).toEqual(QUARANTINED);
  });
});
