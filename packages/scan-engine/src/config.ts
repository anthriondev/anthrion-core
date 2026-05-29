import { z } from 'zod';

import { apiHttpMethodSchema } from './api-target';

/**
 * Scan types supported by the engine. Phase 1 introduced `ai-llm-attack` and
 * `web-app-vuln`; Phase 1.5 Sprint A1 adds `api-scan` (API security scan); Sprint
 * A3 (T-A3.2) adds `web3-dapp` (three-layer Web3 dApp scan — L1 wallet interaction,
 * L2 frontend infrastructure, L3 on-chain context — ARCHITECTURE.md §4 + Phase 1.5
 * plan). Additive at the enum level; the matching Prisma `ScanType` enum value
 * (`WEB3_DAPP`) lands in the T-A3.7 additive migration (§4 stop).
 */
export const scanTypeSchema = z.enum(['ai-llm-attack', 'web-app-vuln', 'api-scan', 'web3-dapp']);

export type ScanType = z.infer<typeof scanTypeSchema>;

/**
 * Target kind for an AI/LLM attack scan (ARCHITECTURE.md §4.1). Two modes since
 * Phase 1: an agent API endpoint or a pasted system prompt.
 */
export const targetKindSchema = z.enum(['endpoint', 'system-prompt']);

export type TargetKind = z.infer<typeof targetKindSchema>;

/**
 * Optional authentication for the target endpoint (T2.2). Many agent endpoints
 * are protected, so the adapter must be able to send credentials:
 * - `bearer`  → `Authorization: Bearer <value>` header.
 * - `apiKey`  → a header named `headerName` (default `X-API-Key`) containing `value`.
 *
 * SECURITY NOTE: `value` is sensitive data (token/key). Never log it, and never
 * include it in a `Finding` or any public report output.
 */
export const endpointAuthSchema = z.discriminatedUnion('type', [
  z.object({
    type: z.literal('bearer'),
    value: z.string().min(1),
  }),
  z.object({
    type: z.literal('apiKey'),
    value: z.string().min(1),
    headerName: z.string().min(1).default('X-API-Key'),
  }),
]);

export type EndpointAuth = z.infer<typeof endpointAuthSchema>;

/**
 * Agent API endpoint target — OpenAI-compatible chat completions (Phase 1).
 * `model` is optionally sent in the body when the endpoint requires it; `auth`
 * is optional for protected endpoints. Custom request formats will follow as
 * additional adapters without touching attack logic (T2.2 decision).
 */
export const endpointTargetSpecSchema = z.object({
  kind: z.literal('endpoint'),
  url: z.string().url(),
  model: z.string().min(1).optional(),
  auth: endpointAuthSchema.optional(),
});

export type EndpointTargetSpec = z.infer<typeof endpointTargetSpecSchema>;

/**
 * System prompt target pasted by the user. `prompt` is the text under test.
 */
export const systemPromptTargetSpecSchema = z.object({
  kind: z.literal('system-prompt'),
  prompt: z.string().min(1),
});

export type SystemPromptTargetSpec = z.infer<typeof systemPromptTargetSpecSchema>;

/**
 * AI scan target specification. Discriminated union on `kind` — the worker uses
 * this to construct the appropriate `ScanTarget` adapter (T2.2).
 */
export const aiTargetSpecSchema = z.discriminatedUnion('kind', [
  endpointTargetSpecSchema,
  systemPromptTargetSpecSchema,
]);

export type AiTargetSpec = z.infer<typeof aiTargetSpecSchema>;

/**
 * AI/LLM attack scan config. `tokenBudget` is the token-budget cap per scan —
 * REQUIRED (ARCHITECTURE.md §4.2); enforcement is implemented in T2.4/T2.5.
 *
 * `maxIterationsPerCategory` (T2.5) — Layer 2 mutation iteration limit per
 * category (sanity guard, Context §1). Optional; the engine applies a conservative
 * default. Comes from scan config, not scattered hardcoding.
 */
export const aiLlmAttackScanConfigSchema = z.object({
  type: z.literal('ai-llm-attack'),
  target: aiTargetSpecSchema,
  tokenBudget: z.number().int().positive(),
  maxIterationsPerCategory: z.number().int().positive().max(10).optional(),
});

/**
 * Default per-operation timeouts for the web scan (T2.6 Context §3), in ms.
 *
 * Timeouts here are a GUARD for stuck/hanging operations (slow target, hanging
 * connection, trap) — NOT a knife that cuts off probes running normally. They are
 * deliberately set LOOSE, comfortably above normal durations, so that a legitimate
 * operation ALWAYS finishes before its timeout; only genuinely stuck operations
 * are caught. A too-short timeout corrupts scan results — that is what these
 * generous values avoid.
 *
 * - `navigation` (30s): page load via `page.goto`. The dominant hang risk. A
 *   normal page loads in well under 5s; 30s only catches a load that is truly
 *   stuck. Matches `DEFAULT_ENDPOINT_TIMEOUT_MS` (the AI endpoint adapter) for
 *   consistency across the engine.
 * - `probe` (10s): applied to EACH probe independently. Observational probes
 *   finish in milliseconds; 10s only catches a probe whose browser round-trip
 *   (cookies/TLS/DOM read) hangs. Per-operation, not one global "whole scan max".
 *
 * If a timeout IS hit, the result is HONEST: the affected probe is reported as
 * `not-executed`, never as "safe" (see `web-scan.ts`).
 */
export const DEFAULT_WEB_NAVIGATION_TIMEOUT_MS = 30_000;
export const DEFAULT_WEB_PROBE_TIMEOUT_MS = 10_000;

/**
 * Layered, per-operation timeouts for the web scan. Each operation has its own
 * timeout (not a single coarse "whole scan max X then chop"). Configurable from
 * the scan config — never scattered hardcoding (Context §3). Both fields default
 * to the loose values above when omitted.
 */
export const webScanTimeoutsSchema = z.object({
  navigationMs: z.number().int().positive().default(DEFAULT_WEB_NAVIGATION_TIMEOUT_MS),
  probeMs: z.number().int().positive().default(DEFAULT_WEB_PROBE_TIMEOUT_MS),
});

export type WebScanTimeouts = z.infer<typeof webScanTimeoutsSchema>;

// ── Crawl budget (Phase 1.5 Sprint A2) ───────────────────────────────────────

/** Default crawl depth — BFS levels from the seed URL (0 = seed only). */
export const DEFAULT_CRAWL_MAX_DEPTH = 2;
/** Default crawl page count — hard ceiling on pages visited (includes the seed). */
export const DEFAULT_CRAWL_MAX_PAGES = 10;
/** Default for honoring robots.txt — conservative, on. */
export const DEFAULT_CRAWL_RESPECT_ROBOTS = true;

/**
 * Hard safety limits for a crawl scan (Sprint A2). This is the cost-ceiling
 * contract: `maxPages` is the per-scan upper bound, NOT a hint. Increasing it
 * widens the scan and widens the cost; the API/UI layer is responsible for
 * choosing a value the product can charge for.
 *
 * Lower-bound choice: `maxPages` ≥ 1 so a crawl always scans at least the seed
 * (a 0-page crawl would be indistinguishable from a no-op). `maxDepth` ≥ 0 so
 * "seed only" is expressible. Upper bounds (10 / 50) protect against absurd
 * configs without limiting the realistic product range.
 */
export const crawlBudgetSchema = z.object({
  maxDepth: z.number().int().min(0).max(10).default(DEFAULT_CRAWL_MAX_DEPTH),
  maxPages: z.number().int().min(1).max(50).default(DEFAULT_CRAWL_MAX_PAGES),
  respectRobots: z.boolean().default(DEFAULT_CRAWL_RESPECT_ROBOTS),
});

export type CrawlBudget = z.infer<typeof crawlBudgetSchema>;

/**
 * Web application vulnerability scan config — DAST against a live URL
 * (ARCHITECTURE.md §4.3). Does not use an LLM, so there is no token budget cap.
 *
 * Modes:
 *   - `crawl` ABSENT → single-page (the Phase 1 / T2.6 behavior, preserved).
 *     `target.url` is the one URL scanned.
 *   - `crawl` PRESENT → multi-page crawl (Phase 1.5 Sprint A2). The seed is
 *     `target.url`; discovery walks same-origin links breadth-first within the
 *     hard `maxDepth` / `maxPages` ceiling, honoring robots.txt when
 *     `respectRobots` is true.
 *
 * `timeouts` carries the per-operation guards (per page), reused identically in
 * both modes; it always resolves to a value (nested defaults applied) so the
 * engine never has to hardcode them.
 */
export const webAppVulnScanConfigSchema = z.object({
  type: z.literal('web-app-vuln'),
  target: z.object({
    url: z.string().url(),
  }),
  // Omitting `timeouts` applies both loose defaults; a partial object fills the
  // rest from the per-field defaults in `webScanTimeoutsSchema`.
  timeouts: webScanTimeoutsSchema.default({
    navigationMs: DEFAULT_WEB_NAVIGATION_TIMEOUT_MS,
    probeMs: DEFAULT_WEB_PROBE_TIMEOUT_MS,
  }),
  /**
   * Sprint A2: when set, the scan runs in CRAWL mode with this budget; when
   * omitted, the scan runs in SINGLE-PAGE mode (current Phase 1 behavior).
   * The field is purely additive — no existing payload changes meaning.
   */
  crawl: crawlBudgetSchema.optional(),
});

export type WebAppVulnScanConfig = z.infer<typeof webAppVulnScanConfigSchema>;

/**
 * Default API request timeout (ms). Each request sent by the API target adapter
 * is bounded by this — slow APIs are still cut so a probe never hangs the scan.
 */
export const DEFAULT_API_REQUEST_TIMEOUT_MS = 30_000;

/**
 * Default response body capture cap, measured in CHARACTERS of the decoded
 * response body string (not raw bytes). The adapter consumes `response.text()`,
 * which decodes UTF-8 into a JS UTF-16 string; counting chars here is what
 * actually bounds the in-memory representation (~2 bytes per stored char in
 * V8). Bodies longer than this are truncated and `ApiResponse.bodyTruncated`
 * is set so probes report a partial inspection honestly. 262_144 chars
 * (~512 KiB in V8 / up to 1 MiB of UTF-8 input) is ample for inspection-style
 * probes (status/headers/body shape) while keeping memory bounded.
 */
export const DEFAULT_API_BODY_CAPTURE_MAX_CHARS = 262_144;

/**
 * Raw-mode API target spec (Phase 1.5 Sprint A1). The user provides one
 * endpoint URL and (optionally) the HTTP method and auth. `endpoints()` on
 * this target returns exactly one endpoint — `raw` coverage means the report
 * layer honestly marks coverage as shallower than `spec` mode.
 *
 * `auth` reuses `endpointAuthSchema` (same shape as AI scan endpoint auth) —
 * the same security note applies: `value` is sensitive and MUST NOT appear in
 * logs, errors, or `Finding` evidence.
 */
export const apiRawTargetSpecSchema = z.object({
  kind: z.literal('raw'),
  /** Concrete endpoint URL — base origin + path; no template variables (no spec). */
  url: z.string().url(),
  /** HTTP method to probe (defaults to `GET`). */
  method: apiHttpMethodSchema.default('GET'),
  /** Optional auth, same shape as the AI scan endpoint auth. */
  auth: endpointAuthSchema.optional(),
});

export type ApiRawTargetSpec = z.infer<typeof apiRawTargetSpecSchema>;

/**
 * Spec-mode API target spec (Phase 1.5 Sprint A1). The user provides a
 * pre-parsed OpenAPI 3.x or Swagger 2.0 document; the adapter dereferences
 * internal `$ref`s, enumerates every operation in `paths`, and exposes them
 * via `endpoints()`.
 *
 * `document` is the ALREADY-PARSED object form (not a JSON / YAML string) —
 * scan-engine stays format-agnostic on purpose: the API/UI boundary
 * (T-A1.4) parses JSON or YAML before handing the object in. Passing a
 * string here is an SSRF risk because `SwaggerParser`'s `string` overload
 * means "file path or URL" — never let an untrusted string reach it.
 *
 * `baseUrl` is optional: when absent the adapter derives the origin from the
 * spec (`servers[0].url` in OpenAPI 3.x; `${schemes[0]}://${host}` in Swagger
 * 2.0). Provide it explicitly when the spec lacks server data or to target a
 * non-default deployment.
 *
 * `auth` is applied to every request unless the probe sets the same header
 * (same precedence rule as raw mode — needed for BFLA / broken-auth probes).
 */
export const apiSpecTargetSpecSchema = z.object({
  kind: z.literal('spec'),
  /** Pre-parsed OpenAPI / Swagger document. Plain object — never a string. */
  document: z.record(z.string(), z.unknown()),
  /** Optional explicit base URL; otherwise derived from the spec. */
  baseUrl: z.string().url().optional(),
  /** Optional auth, same shape as the AI scan endpoint auth. */
  auth: endpointAuthSchema.optional(),
});

export type ApiSpecTargetSpec = z.infer<typeof apiSpecTargetSpecSchema>;

/**
 * API target specification. Discriminated union on `kind` — `raw` (single
 * endpoint URL) or `spec` (pre-parsed OpenAPI/Swagger document).
 */
export const apiTargetSpecSchema = z.discriminatedUnion('kind', [
  apiRawTargetSpecSchema,
  apiSpecTargetSpecSchema,
]);

export type ApiTargetSpec = z.infer<typeof apiTargetSpecSchema>;

/**
 * API security scan config (Phase 1.5 Sprint A1). No LLM, no token budget.
 * `timeoutMs` bounds each individual request (covers connect + body read,
 * not just headers); `bodyCaptureMaxChars` caps the captured body length in
 * characters (see `DEFAULT_API_BODY_CAPTURE_MAX_CHARS`).
 */
export const apiScanConfigSchema = z.object({
  type: z.literal('api-scan'),
  target: apiTargetSpecSchema,
  timeoutMs: z.number().int().positive().default(DEFAULT_API_REQUEST_TIMEOUT_MS),
  bodyCaptureMaxChars: z.number().int().positive().default(DEFAULT_API_BODY_CAPTURE_MAX_CHARS),
});

export type ApiScanConfig = z.infer<typeof apiScanConfigSchema>;

// ── Web3 dApp scan (Phase 1.5 Sprint A3, T-A3.2) ─────────────────────────────

/**
 * Chains supported by the Web3 scan. Mainnet, READ-ONLY (Sprint A3 founder
 * decision): the scanner reads on-chain state via RPC and metadata via
 * explorer API. No private keys, no transaction broadcast. Two chains in
 * Sprint A3 — Ethereum mainnet and Base mainnet (the choice the founder
 * confirmed at sprint kick-off). Adding Solana / further EVM chains is
 * post-Part-B scope.
 */
export const web3ChainSchema = z.enum(['ethereum', 'base']);
export type Web3Chain = z.infer<typeof web3ChainSchema>;

/**
 * How deep L1 drives the dApp's wallet flow:
 *  - `landing-page-only` — navigate, capture whatever the page asks for on
 *    load. A dApp that gates wallet calls behind a Connect click will produce
 *    no interaction → L1 emits the honest `web3-l1-no-interactive-flow-observed`
 *    coverage gap.
 *  - `try-connect-button` — after navigation, the runner heuristically clicks
 *    a Connect button (text match `/connect( wallet)?/i`) to drive the dApp
 *    deeper. Default; matches the sprint plan.
 */
export const web3WalletInteractionDepthSchema = z.enum([
  'landing-page-only',
  'try-connect-button',
]);
export type Web3WalletInteractionDepth = z.infer<typeof web3WalletInteractionDepthSchema>;

export const DEFAULT_WEB3_WALLET_INTERACTION_DEPTH: Web3WalletInteractionDepth =
  'try-connect-button';

/**
 * Cap on how long, after navigation completes, L1 waits for the dApp's
 * post-load activity (provider detection, auto-connect, any wallet requests
 * triggered without user interaction). A guard for genuinely-stuck pages, NOT
 * a knife that cuts off active flows — set loose at 5s. The synthetic
 * provider's responses are immediate, so 5s is comfortably above any
 * realistic dApp's idle cadence; the honest "no interactive flow" coverage
 * gap fires if nothing is captured during the window.
 */
export const DEFAULT_WEB3_L1_OBSERVATION_MS = 5_000;

/**
 * Connect-button click is best-effort: if no button matches the heuristic,
 * the runner moves on (no failure). This timeout is for the click + post-click
 * settle, not for finding the button (which is an immediate DOM query).
 */
export const DEFAULT_WEB3_CONNECT_CLICK_SETTLE_MS = 3_000;

/**
 * Per-operation timeouts for the Web3 scan. Reuses `webScanTimeoutsSchema` for
 * navigation / probe guards (L1+L2 sit on the same Playwright page as the web
 * scan); adds `l1ObservationMs` (post-navigation observation window) and
 * `connectClickSettleMs` (best-effort Connect click). Each timeout is a GUARD
 * for stuck/hanging operations, never a budget cut.
 */
export const web3ScanTimeoutsSchema = z.object({
  navigationMs: z.number().int().positive().default(DEFAULT_WEB_NAVIGATION_TIMEOUT_MS),
  probeMs: z.number().int().positive().default(DEFAULT_WEB_PROBE_TIMEOUT_MS),
  l1ObservationMs: z.number().int().positive().default(DEFAULT_WEB3_L1_OBSERVATION_MS),
  connectClickSettleMs: z
    .number()
    .int()
    .positive()
    .default(DEFAULT_WEB3_CONNECT_CLICK_SETTLE_MS),
});

export type Web3ScanTimeouts = z.infer<typeof web3ScanTimeoutsSchema>;

/**
 * Web3 dApp scan target. The dApp URL is what Playwright navigates to;
 * `chain` selects the L3 read-only provider (Ethereum vs Base). NO private-key
 * field — by construction: the synthetic EIP-1193 provider returns plausible
 * fake responses, the L3 provider uses only read methods (`eth_call`,
 * `eth_getCode`, `eth_getStorageAt`). The UI form (T-A3.8) likewise has no
 * private-key input; a key would be a category mistake about what this scan
 * does (sub-agent rubric §10).
 */
export const web3DappTargetSpecSchema = z.object({
  url: z.string().url(),
  chain: web3ChainSchema,
  walletInteractionDepth: web3WalletInteractionDepthSchema.default(
    DEFAULT_WEB3_WALLET_INTERACTION_DEPTH,
  ),
});

export type Web3DappTargetSpec = z.infer<typeof web3DappTargetSpecSchema>;

/**
 * Web3 dApp scan config — read-only mainnet (Ethereum + Base). No LLM, no
 * token budget. `timeouts` carries per-operation guards reused identically by
 * L1 and L2 (single page foundation) plus the L1 observation window.
 */
export const web3DappScanConfigSchema = z.object({
  type: z.literal('web3-dapp'),
  target: web3DappTargetSpecSchema,
  timeouts: web3ScanTimeoutsSchema.default({
    navigationMs: DEFAULT_WEB_NAVIGATION_TIMEOUT_MS,
    probeMs: DEFAULT_WEB_PROBE_TIMEOUT_MS,
    l1ObservationMs: DEFAULT_WEB3_L1_OBSERVATION_MS,
    connectClickSettleMs: DEFAULT_WEB3_CONNECT_CLICK_SETTLE_MS,
  }),
});

export type Web3DappScanConfig = z.infer<typeof web3DappScanConfigSchema>;

/**
 * Config for running a scan. Discriminated union on `type` so that each scan
 * kind's parameters are strictly typed (e.g. tokenBudget exists only on AI scans).
 */
export const scanConfigSchema = z.discriminatedUnion('type', [
  aiLlmAttackScanConfigSchema,
  webAppVulnScanConfigSchema,
  apiScanConfigSchema,
  web3DappScanConfigSchema,
]);

export type ScanConfig = z.infer<typeof scanConfigSchema>;
