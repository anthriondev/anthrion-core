import { z } from 'zod';

const envSchema = z.object({
  // Node
  NODE_ENV: z.enum(['development', 'production', 'test']).default('development'),

  // Database
  DATABASE_URL: z.string().url(),

  // Redis
  REDIS_URL: z.string().url(),

  // MinIO
  MINIO_ENDPOINT: z.string(),
  MINIO_PORT: z.coerce.number().int().positive(),
  MINIO_ACCESS_KEY: z.string(),
  MINIO_SECRET_KEY: z.string(),
  MINIO_BUCKET: z.string().default('anthrion'),

  // Auth — Privy
  PRIVY_APP_ID: z.string(),
  PRIVY_APP_SECRET: z.string(),
  NEXT_PUBLIC_PRIVY_APP_ID: z.string().optional(),

  // LLM — OpenRouter (gateway; model is read from env, not hardcoded — TECH_STACK.md)
  OPENROUTER_API_KEY: z.string(),
  // Two model tiers (T2.4). Callers choose the tier based on task type. Slugs are
  // REQUIRED: there is no default model — the operator picks the OpenRouter slug for
  // each tier so no specific model is baked into the codebase. The app will fail to
  // start at env-load with a clear Zod error if either is unset.
  LLM_MODEL_LIGHT: z.string().min(1),
  LLM_MODEL_HEAVY: z.string().min(1),
  // Token budget cap per scan (input+output) — REQUIRED (ARCHITECTURE.md §4.2).
  // Replaces the old OPENROUTER_TOKEN_BUDGET (name is clearer: per-scan).
  LLM_TOKEN_BUDGET_PER_SCAN: z.coerce.number().int().positive().default(20000),

  // Payment
  PAYMENT_USDC_BASE_ADDRESS: z.string(),
  PAYMENT_USDC_SOLANA_ADDRESS: z.string(),
  // Per-scan price in USDC ATOMIC units (6 decimals), as a non-negative integer string —
  // e.g. "10000" = 0.01 USDC. "0" (the Phase 1 default) is a valid FREE_PRICING value: all
  // scans pass without an on-chain transaction (T5.1, locked decision). Global price for
  // Phase 1 (not per scan type) — see payments/pricing.ts.
  SCAN_PRICE_USDC_ATOMIC: z
    .string()
    .regex(/^\d+$/, 'SCAN_PRICE_USDC_ATOMIC must be a non-negative integer (atomic USDC units)')
    .default('0'),
  // Treasury address that receives USDC for paid scans (the x402 `payTo`). Empty in Phase 1
  // (price is 0 → never used). Set together with the treasury wallet/KMS package before paid
  // pricing is enabled. NOT a secret (a public address); no private keys live in env.
  PAYMENT_PAYTO_BASE_ADDRESS: z.string().default(''),

  // ── Rate limiting (Phase 1.5 Sprint B1, T-B1.1) ───────────────────────────
  // Public deployment requires honest, env-driven rate limits — the strictest cap is on
  // `POST /scans` because that is the route that triggers real LLM cost (OpenRouter).
  //
  // Two named throttlers, applied via the api's global guard (`AuthAwareThrottlerGuard`):
  //  - `default` — broad per-IP burst cap applied to ALL routes. Catches casual abuse
  //    and accidental client loops without affecting normal interactive use.
  //  - `scans`   — strict per-identity-or-IP cap applied ONLY to `POST /scans`. Caps the
  //    LLM-cost surface for free-pricing Phase 1.5: by the time the throttler runs the
  //    AuthGuard has already populated `privyUser.userId`, so the tracker is the user id
  //    (not the IP), which is the right thing — sharing a NAT must not share quota.
  //
  // Numbers are deliberate but adjustable per environment (this is the only place that
  // sets them — no magic numbers in code):
  //  - default: 60 req/min per IP — generous for a normal SPA + SSE session.
  //  - scans:   10 scan creations/hour per identity — enough for real exploration during
  //    Phase 1.5; aggressive enough that a leaked token cannot burn unbounded LLM cost.
  RATE_LIMIT_DEFAULT_PER_MINUTE: z.coerce.number().int().positive().default(60),
  RATE_LIMIT_SCANS_PER_HOUR: z.coerce.number().int().positive().default(10),
  // Escape hatch for tests + local benchmarks. NEVER set true in production. The guard
  // skips all enforcement when this is true; explicit, never silent. Uses an enum
  // transform (not `z.coerce.boolean()`, which would coerce the string "false" to true).
  RATE_LIMIT_DISABLED: z
    .enum(['true', 'false'])
    .default('false')
    .transform((v) => v === 'true'),

  // ── Web3 L3 provider keys (Phase 1.5 Sprint A3, T-A3.7) ───────────────────
  // OPTIONAL: when both are set, the sandbox builds a real RemoteOnChainContextProvider
  // and the L3 layer fetches verified-source / proxy / admin / deployment-age data for
  // every contract the dApp references. When EITHER is missing, L3 is honestly skipped
  // and the report surfaces a coverage gap (`web3-l3-provider-not-configured`) on every
  // address — the L1/L2 layers still run end-to-end. This matches the graceful-
  // degradation contract baked into RemoteOnChainContextProvider (T-A3.4) and lets
  // operators run web3-dapp scans in dev / unbilled environments without keys.
  // Keys travel into the sandbox over stdin (NEVER docker env), so they never appear
  // in `docker inspect` and never leak into a Finding (sub-agent rubric §12).
  WEB3_ALCHEMY_API_KEY: z.string().optional(),
  WEB3_ETHERSCAN_API_KEY: z.string().optional(),

  // ── CORS (Phase 1.5 Sprint B1, T-B1.4) ────────────────────────────────────
  // Exact allowed origin for `apps/api`. NEVER a wildcard — credentials cross the
  // boundary (Privy bearer tokens, future X-PAYMENT) and a wildcard would either
  // break credentialed CORS or, worse, accept any caller. Set per environment:
  //   - local dev: http://localhost:3000
  //   - production: https://app.anthrion.xyz
  // Default targets local dev so a fresh checkout works without extra config.
  API_CORS_ORIGIN: z.string().url().default('http://localhost:3000'),
});

export type Env = z.infer<typeof envSchema>;

const _parsed = envSchema.safeParse(process.env);

if (!_parsed.success) {
  console.error('❌ Invalid environment variables:');
  console.error(_parsed.error.flatten().fieldErrors);
  process.exit(1);
}

export const env: Env = _parsed.data;
