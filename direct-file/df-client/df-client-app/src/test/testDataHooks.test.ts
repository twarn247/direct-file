import { existsSync, readFileSync } from 'fs';
import { resolve } from 'path';

const appRoot = resolve(__dirname, `../..`);

describe(`test-data loading hooks`, () => {
  it(`is not enabled by any committed production env file`, () => {
    // Vite loads .env.production and .env.production.local for production builds.
    // Neither should exist with this flag set.
    for (const name of [`.env.production`, `.env.production.local`, `.env`]) {
      const path = resolve(appRoot, name);
      if (existsSync(path)) {
        expect(readFileSync(path, `utf8`)).not.toMatch(/^VITE_ALLOW_LOADING_TEST_DATA=(?!false)/m);
      }
    }
  });

  it(`is guarded by a build-time assertion in vite.config.ts`, () => {
    // The hooks read query parameters into browser storage. The only thing keeping them
    // out of a production bundle today is that no .env.production exists -- Vite also
    // reads VITE_* from the process environment, so that is not a guarantee.
    const viteConfig = readFileSync(resolve(appRoot, `vite.config.ts`), `utf8`);

    expect(viteConfig).toContain(`VITE_ALLOW_LOADING_TEST_DATA`);
  });
});
