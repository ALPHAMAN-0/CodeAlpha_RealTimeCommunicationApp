# CLAUDE.md

## Commands (from package.json)
- `pnpm dev` — start Mongo via Docker, seed if empty, run server + web concurrently
- `pnpm dev:server` — `pnpm --filter @rtc/server dev` (tsx watch apps/server/src/main.ts)
- `pnpm dev:web` — `pnpm --filter @rtc/web dev` (vite)
- `pnpm build` — build web then server (`pnpm --filter @rtc/web build && pnpm --filter @rtc/server build`)
- `pnpm typecheck` — `pnpm -r --parallel typecheck` (all workspace packages)
- `pnpm lint` — `eslint .`
- `pnpm test` — `vitest run`
- `pnpm test:watch` — `vitest`

## Rules
- pnpm workspace only — `"packageManager": "pnpm@10.5.1"` pinned in root package.json; do not use npm/yarn
- Internal packages are referenced as `"workspace:*"` (apps/server, apps/web, packages/crypto package.json) — link, don't duplicate, shared code
- ESM throughout: every package.json has `"type": "module"`; import specifiers use explicit `.js` extensions even from `.ts`/`.tsx` files (observed in apps/server/src/main.ts, apps/web/src/App.tsx)

## Read first
- README.md
- docs/ARCHITECTURE.md
- docs/SECURITY.md

Architecture: see ARCHITECTURE.md — read before structural changes
