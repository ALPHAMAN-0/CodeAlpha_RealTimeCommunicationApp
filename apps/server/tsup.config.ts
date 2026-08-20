import { defineConfig } from 'tsup';

export default defineConfig({
  entry: ['src/main.ts', 'src/scripts/seed.ts'],
  format: ['esm'],
  target: 'node22',
  platform: 'node',
  outDir: 'dist',
  clean: true,
  sourcemap: true,
  // Workspace packages export source, so they get inlined here. That is the
  // point: no build ordering, no stale dist/ in packages/.
  noExternal: ['@rtc/shared', '@rtc/crypto'],
  splitting: false,
});
