# ANTHRION

**A security & trust platform for the agentic internet.**

ANTHRION scans applications, APIs, and on-chain dApps for security and
trust weaknesses — and, uniquely, red-teams the **AI / LLM** surface that
traditional scanners ignore.

> ⚠️ **Status: early development.** This is an early public release.
> Interfaces, schemas, and APIs may change without notice.

---

## Why ANTHRION

As software increasingly ships LLM-powered features and autonomous agents,
the attack surface shifts. Prompt injection, jailbreaks, unsafe tool use,
and data exfiltration through model output are not caught by conventional
web and API scanners.

ANTHRION's differentiator is its **AI red-team engine**: an adaptive
scanner that probes LLM-backed endpoints the way an attacker would,
alongside classic application, API, and Web3 security checks.

---

## What it scans (Phase 1 + Phase 1.5 Part A)

ANTHRION currently ships **four scan types**:

| Scan type            | What it looks for                                              |
|----------------------|---------------------------------------------------------------|
| 🤖 AI / LLM attack   | Prompt injection, jailbreaks, unsafe output handling, leakage |
| 🌐 Web app vuln      | Common web application vulnerabilities                        |
| 🔌 API security      | Authentication, authorization, and API-layer weaknesses       |
| ⛓️ Web3 dApp         | Smart-contract-facing and dApp trust / security issues        |

Each scan runs in an isolated, throwaway sandbox and produces a structured
report (viewable in the web client and downloadable as a PDF).

---

## Tech stack (high level)

- **Language:** TypeScript
- **Runtime:** Node.js
- **API:** NestJS
- **Web:** Next.js
- **Browser automation / scanning:** Playwright
- **Database:** PostgreSQL (via Prisma)
- **Queue:** Redis-backed job queue (BullMQ)
- **Payments:** x402-native (pay-per-scan; free in Phase 1)

The repository is a pnpm + Turborepo monorepo:

```
apps/
  api/      NestJS API — requests, auth, persistence, queueing
  worker/   scan workers, report generation, sandbox orchestration
  web/      Next.js web client
packages/
  scan-engine/      the scan engines (AI/LLM, web, API, Web3)
  sandbox-runtime/  isolated runtime contract for scans
  shared/           shared types, env, queue, payment helpers
  db/               Prisma client
  ui/               shared UI components
  config/           shared lint / tsconfig presets
```

---

## Getting started

> Note: this is an early release intended for transparency and review.
> A fuller setup guide will follow as the project stabilizes.

Prerequisites: Node.js (see `.nvmrc`), pnpm 9+, Docker.

```bash
pnpm install
cp .env.example .env       # then fill in the required values
docker compose up -d       # local Postgres, Redis, MinIO
pnpm build
```

Configuration is driven entirely by environment variables — see
`.env.example` for the full, documented list. **No credentials are
committed to this repository.**

---

## License

Licensed under the **Apache License 2.0**. See [LICENSE](./LICENSE).

Copyright 2026 Anthrion.
