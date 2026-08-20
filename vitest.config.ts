import { defineConfig } from 'vitest/config';

export default defineConfig({
  test: {
    globals: false,
    projects: [
      {
        test: {
          name: 'unit',
          environment: 'node',
          include: [
            'packages/*/src/**/*.test.ts',
            'apps/server/src/**/*.test.ts',
            'apps/web/src/**/*.test.ts',
          ],
          exclude: ['**/node_modules/**', '**/*.integration.test.ts'],
        },
      },
      {
        test: {
          name: 'integration',
          environment: 'node',
          include: ['apps/server/src/**/*.integration.test.ts'],
          exclude: ['**/node_modules/**'],
          // Must run before any test module is imported: config/env.ts
          // validates process.env at import time and exits on failure.
          setupFiles: ['apps/server/src/__tests__/setup.ts'],
          // mongodb-memory-server downloads a binary on first run and real
          // socket round trips are slower than pure unit work.
          testTimeout: 60_000,
          hookTimeout: 120_000,
          fileParallelism: false,
        },
      },
    ],
  },
});
