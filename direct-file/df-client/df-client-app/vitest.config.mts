import { mergeConfig, defineConfig } from 'vitest/config';
import { configOptions } from './vite.config';
import { DefaultReporter } from 'vitest/reporters';

// vite.config.ts's default export is now a factory (({ mode }) => ...) so it can assert
// VITE_ALLOW_LOADING_TEST_DATA is unset for production builds -- mergeConfig only accepts
// plain config objects, not factories, so this merges the named configOptions export
// instead. That's also the more correct choice here: a test run has no reason to trigger
// the production-mode build guard.
export default mergeConfig(
  configOptions,
  defineConfig({
    test: {
      reporters: [new DefaultReporter()],
    },
  })
);
