# syntax=docker/dockerfile:1
#
# Scan-engine sandbox image (T3.2, Part A).
#
# Self-contained image that packages @anthrion/sandbox-runtime + @anthrion/scan-engine
# + their runtime deps + Chromium, so the worker can run each scan in a fresh,
# throwaway container (ARCHITECTURE.md §5, run-once pattern).
#
# Base: the OFFICIAL Playwright image, pinned to the SAME Playwright version the repo
# uses (1.60.0 — see packages/scan-engine/package.json). It already contains Chromium
# (build 1223) and every system library Chromium needs, version-matched to the
# Playwright npm package (CLAUDE.md §6) — far more reliable than installing Chromium +
# its dozens of shared libs by hand. Browsers live at /ms-playwright; we do NOT run
# `playwright install`.
#
# Build context = MONOREPO ROOT (needs pnpm-lock.yaml + the workspace). Build with:
#   docker build -f packages/sandbox-runtime/Dockerfile -t anthrion-scan-runtime:latest .
# or use scripts/build-sandbox-image.sh.
#
# Reproducible: base tag is version-pinned, pnpm is pinned via corepack, and deps come
# from the frozen lockfile.

ARG PLAYWRIGHT_VERSION=v1.60.0-noble

# ── Stage 1: build (compile scan-engine + sandbox-runtime, collect prod deps) ────
FROM mcr.microsoft.com/playwright:${PLAYWRIGHT_VERSION} AS builder

ENV PNPM_HOME=/pnpm
ENV PATH=$PNPM_HOME:$PATH
# Pin pnpm to the repo's version (package.json `packageManager`) for reproducibility.
RUN corepack enable && corepack prepare pnpm@9.15.9 --activate

WORKDIR /build
# Copy the whole workspace (the .dockerignore keeps node_modules/dist/.git out so the
# install + build are reproducible from the lockfile, not from host artifacts).
COPY . .

# Install sandbox-runtime + its dependency graph (incl. dev deps needed to compile).
RUN pnpm install --frozen-lockfile --filter @anthrion/sandbox-runtime...

# Compile scan-engine then sandbox-runtime (pnpm runs them in dependency order).
RUN pnpm --filter @anthrion/sandbox-runtime... run build

# Produce a self-contained PROD deployment at /app: sandbox-runtime's files (incl.
# dist) + a real node_modules with only prod deps (scan-engine, playwright, zod).
RUN pnpm --filter @anthrion/sandbox-runtime deploy --prod /app

# ── Stage 2: runtime (minimal: deployed app on the Playwright base) ──────────────
FROM mcr.microsoft.com/playwright:${PLAYWRIGHT_VERSION} AS runtime

ENV NODE_ENV=production
# Chromium is preinstalled in the base here; make sure Playwright resolves it.
ENV PLAYWRIGHT_BROWSERS_PATH=/ms-playwright

WORKDIR /app
COPY --from=builder --chown=pwuser:pwuser /app /app

# Defense-in-depth: run as the image's non-root user (the worker additionally applies
# --cap-drop ALL, --read-only, --pids-limit, etc. at `docker run`). T2.6's Chromium
# `--no-sandbox` relies on this container isolation as its protection.
USER pwuser

# The entrypoint reads one job from stdin and writes one result line to stdout
# (see packages/sandbox-runtime/src/contract.ts). No CMD args — input arrives on stdin.
ENTRYPOINT ["node", "dist/entry.js"]
