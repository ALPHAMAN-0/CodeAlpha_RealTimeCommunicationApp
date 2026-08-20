# Single-origin production image.
#
# The API process also serves the built SPA. That is not laziness — it is what
# makes __Host- cookies, SameSite=Strict and a 'self'-only CSP work without
# exceptions. Almost every "my httpOnly cookie doesn't work" bug in this stack
# is a two-origin bug, so the deployment removes the second origin.

# ── deps: full install, for building ────────────────────────────────────────
FROM node:22-bookworm-slim AS deps
ENV PNPM_HOME=/pnpm
ENV PATH=$PNPM_HOME:$PATH
RUN corepack enable && corepack prepare pnpm@10.5.1 --activate
WORKDIR /repo

# Manifests first, so a source-only change does not reinstall.
COPY pnpm-workspace.yaml pnpm-lock.yaml package.json .npmrc ./
COPY packages/shared/package.json packages/shared/
COPY packages/crypto/package.json packages/crypto/
COPY apps/server/package.json apps/server/
COPY apps/web/package.json apps/web/
RUN pnpm install --frozen-lockfile

# ── build ───────────────────────────────────────────────────────────────────
FROM deps AS build
WORKDIR /repo
COPY tsconfig.base.json ./
COPY packages ./packages
COPY apps ./apps
# Both builds typecheck first, so a type error fails here rather than shipping.
RUN pnpm --filter @rtc/web build && pnpm --filter @rtc/server build

# ── prod-deps: production-only install, same layout ─────────────────────────
#
# A separate stage rather than pruning the build stage: pnpm's node_modules is
# a tree of symlinks into .pnpm, so a clean --prod install is far more
# predictable than trying to delete dev packages out of it.
FROM node:22-bookworm-slim AS prod-deps
ENV PNPM_HOME=/pnpm
ENV PATH=$PNPM_HOME:$PATH
RUN corepack enable && corepack prepare pnpm@10.5.1 --activate
WORKDIR /repo
COPY pnpm-workspace.yaml pnpm-lock.yaml package.json .npmrc ./
COPY packages/shared/package.json packages/shared/
COPY packages/crypto/package.json packages/crypto/
COPY apps/server/package.json apps/server/
COPY apps/web/package.json apps/web/
RUN pnpm install --frozen-lockfile --prod --ignore-scripts=false

# ── runtime ─────────────────────────────────────────────────────────────────
FROM node:22-bookworm-slim AS runtime
ENV NODE_ENV=production
WORKDIR /repo/apps/server

# The whole tree stays at /repo so pnpm's relative symlinks resolve. Both
# node_modules directories are required: the workspace root holds .pnpm, and
# the package directory holds the links into it.
COPY --from=prod-deps /repo/node_modules /repo/node_modules
COPY --from=prod-deps /repo/apps/server/node_modules /repo/apps/server/node_modules
COPY --from=prod-deps /repo/package.json /repo/pnpm-workspace.yaml /repo/
COPY --from=prod-deps /repo/apps/server/package.json /repo/apps/server/

# @rtc/shared and @rtc/crypto are inlined by tsup, so no workspace links are
# needed at runtime — only these two build outputs.
COPY --from=build /repo/apps/server/dist /repo/apps/server/dist
COPY --from=build /repo/apps/web/dist /repo/apps/web/dist

RUN chown -R node:node /repo
USER node

ENV SERVE_STATIC=true
ENV WEB_DIST_DIR=/repo/apps/web/dist
ENV PORT=4000
EXPOSE 4000

# Node's own fetch, so the image needs neither curl nor wget.
HEALTHCHECK --interval=10s --timeout=5s --start-period=30s --retries=6 \
  CMD node -e "fetch('http://127.0.0.1:'+(process.env.PORT||4000)+'/api/health/ready').then(r=>process.exit(r.ok?0:1)).catch(()=>process.exit(1))"

CMD ["node", "dist/main.js"]
