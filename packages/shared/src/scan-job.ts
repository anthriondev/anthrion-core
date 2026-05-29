import type { JobsOptions } from 'bullmq';
import { z } from 'zod';

/**
 * BullMQ scan queue contract (T3.1).
 *
 * This module lives in `packages/shared` on purpose: the scan job payload crosses
 * TWO apps — `apps/api` (producer, enqueues) and `apps/worker` (consumer, runs the
 * scan). `ARCHITECTURE.md` §2 designates `shared` as the home for cross-app types +
 * Zod schemas, and forbids `apps/*` from importing each other. Putting the contract
 * here keeps both apps depending only on `shared`.
 *
 * Relationship to `ScanConfig` (scan-engine) — DECISION (T3.1):
 * `packages/scan-engine` owns `ScanConfig` (the engine's internal run config). But
 * `shared` MUST NOT import `scan-engine` (`ARCHITECTURE.md` §2 — `shared` is the
 * most basic layer). So the job payload does NOT carry a `ScanConfig`. Instead it
 * carries the primitive REQUEST DATA (scan id + scan type + target parameters) that
 * is sufficient to run a scan. The worker — which MAY import `scan-engine` — maps
 * this validated payload into a `ScanConfig` (in T3.3, when it actually runs the
 * engine). The target schemas below intentionally MIRROR scan-engine's target specs
 * as plain wire data; they are defined independently here to respect §2, not copied
 * by import. Engine-only operational knobs (token budget, per-operation timeouts)
 * are NOT part of the wire payload — the worker supplies them when building the
 * `ScanConfig` (e.g. token budget from env, `ARCHITECTURE.md` §4.2).
 */

/** Name of the BullMQ queue scan jobs flow through. Single source of truth. */
export const SCAN_QUEUE_NAME = 'scan' as const;

/** Name given to every scan job added to the queue (the scan KIND lives in the payload). */
export const SCAN_JOB_NAME = 'run-scan' as const;

/** Scan kinds supported by the engine (mirrors scan-engine's `ScanType`, ARCHITECTURE.md §4). */
export const scanJobTypeSchema = z.enum(['ai-llm-attack', 'web-app-vuln', 'api-scan', 'web3-dapp']);

export type ScanJobType = z.infer<typeof scanJobTypeSchema>;

/**
 * Optional authentication for an agent endpoint target (mirrors scan-engine's
 * `EndpointAuth` as wire data). `headerName` is left without a default here so the
 * engine owns the default (`X-API-Key`) when it builds the `ScanConfig`.
 *
 * SECURITY NOTE: `value` is a secret (token/key). Never log it and never place it
 * in a `Finding` or any public output (`CLAUDE.md` §7).
 */
export const scanJobEndpointAuthSchema = z.discriminatedUnion('type', [
  z.object({ type: z.literal('bearer'), value: z.string().min(1) }),
  z.object({
    type: z.literal('apiKey'),
    value: z.string().min(1),
    headerName: z.string().min(1).optional(),
  }),
]);

export type ScanJobEndpointAuth = z.infer<typeof scanJobEndpointAuthSchema>;

/** Agent API endpoint target — the worker turns this into scan-engine's `EndpointTargetSpec`. */
export const scanJobEndpointTargetSchema = z.object({
  kind: z.literal('endpoint'),
  url: z.string().url(),
  model: z.string().min(1).optional(),
  auth: scanJobEndpointAuthSchema.optional(),
});

export type ScanJobEndpointTarget = z.infer<typeof scanJobEndpointTargetSchema>;

/** Pasted system-prompt target — the text under test. */
export const scanJobSystemPromptTargetSchema = z.object({
  kind: z.literal('system-prompt'),
  prompt: z.string().min(1),
});

export type ScanJobSystemPromptTarget = z.infer<typeof scanJobSystemPromptTargetSchema>;

/** AI scan target: endpoint or pasted system prompt (the two Phase 1 modes, ARCHITECTURE.md §4.1). */
export const scanJobAiTargetSchema = z.discriminatedUnion('kind', [
  scanJobEndpointTargetSchema,
  scanJobSystemPromptTargetSchema,
]);

export type ScanJobAiTarget = z.infer<typeof scanJobAiTargetSchema>;

// ── API scan targets (Phase 1.5 Sprint A1, T-A1.3) ──────────────────────────

/**
 * Raw-mode API scan target — single endpoint URL. Mirrors scan-engine's
 * `ApiRawTargetSpec` as wire data.
 */
export const scanJobApiRawTargetSchema = z.object({
  kind: z.literal('raw'),
  url: z.string().url(),
  method: z.enum(['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'HEAD', 'OPTIONS']).optional(),
  auth: scanJobEndpointAuthSchema.optional(),
});

export type ScanJobApiRawTarget = z.infer<typeof scanJobApiRawTargetSchema>;

/**
 * Spec-mode API scan target — pre-parsed OpenAPI/Swagger document (object form).
 * The api layer (T-A1.4) is responsible for parsing user-supplied JSON or YAML
 * BEFORE enqueueing the job; scan-engine intentionally does not accept a string
 * here (SwaggerParser would interpret it as a path/URL — SSRF risk).
 * Mirrors scan-engine's `ApiSpecTargetSpec` as wire data.
 */
export const scanJobApiSpecTargetSchema = z.object({
  kind: z.literal('spec'),
  document: z.record(z.string(), z.unknown()),
  baseUrl: z.string().url().optional(),
  auth: scanJobEndpointAuthSchema.optional(),
});

export type ScanJobApiSpecTarget = z.infer<typeof scanJobApiSpecTargetSchema>;

export const scanJobApiTargetSchema = z.discriminatedUnion('kind', [
  scanJobApiRawTargetSchema,
  scanJobApiSpecTargetSchema,
]);

export type ScanJobApiTarget = z.infer<typeof scanJobApiTargetSchema>;

/**
 * Web3 dApp scan target (Phase 1.5 Sprint A3, T-A3.7 wire boundary).
 * Mirrors scan-engine's `web3DappTargetSpecSchema` as wire data — `shared`
 * may not import `scan-engine` (ARCHITECTURE.md §2). Only the user-supplied
 * fields are on the wire; `walletInteractionDepth` / `timeouts` are engine
 * defaults applied worker-side. NO private-key field by construction —
 * the synthetic EIP-1193 provider returns plausible fakes; the L3 channel
 * uses only read-only RPC methods (sub-agent rubric §10).
 */
export const scanJobWeb3TargetSchema = z.object({
  url: z.string().url(),
  chain: z.enum(['ethereum', 'base']),
  /**
   * Wallet-interaction depth (Phase 1.5 Sprint A3, T-A3.8):
   *  - `landing-page-only`  — load and wait; do not drive a Connect button.
   *  - `try-connect-button` — heuristically click a Connect button after load
   *                          to drive the dApp deeper. The engine default
   *                          (DEFAULT_WEB3_WALLET_INTERACTION_DEPTH in
   *                          scan-engine/config.ts). OPTIONAL on the wire so
   *                          the engine schema applies the default — clients
   *                          can omit it and get the recommended behavior.
   */
  walletInteractionDepth: z.enum(['landing-page-only', 'try-connect-button']).optional(),
});

export type ScanJobWeb3Target = z.infer<typeof scanJobWeb3TargetSchema>;

/**
 * `scanId` references the `Scan` DB record. That record is created by `api` in T4.1
 * (model defined in T3.4); for T3.1 it is simply the job's correlation id.
 */
const scanIdSchema = z.string().min(1);

const aiScanJobSchema = z.object({
  scanId: scanIdSchema,
  scanType: z.literal('ai-llm-attack'),
  target: scanJobAiTargetSchema,
});

/**
 * Crawl budget for a web scan (Phase 1.5 Sprint A2). Mirrors scan-engine's
 * `crawlBudgetSchema` as wire data — duplicated here because `shared` may not
 * import `scan-engine` (ARCHITECTURE.md §2). Bounds match the engine schema
 * one-for-one and are kept in sync by `scanJobApiTargetSchema`-style review.
 *
 * Wire-side validation: defaults are NOT applied here (defaults belong to the
 * engine config, T-A2.3). On the wire the field is OPTIONAL and any client
 * that wants a non-default budget passes the value explicitly; the worker maps
 * it through to `scanConfigSchema`, which applies engine defaults to anything
 * left undefined.
 */
export const scanJobCrawlBudgetSchema = z.object({
  maxDepth: z.number().int().min(0).max(10).optional(),
  maxPages: z.number().int().min(1).max(50).optional(),
  respectRobots: z.boolean().optional(),
});

export type ScanJobCrawlBudget = z.infer<typeof scanJobCrawlBudgetSchema>;

const webScanJobSchema = z.object({
  scanId: scanIdSchema,
  scanType: z.literal('web-app-vuln'),
  target: z.object({ url: z.string().url() }),
  /**
   * Sprint A2: when present, the scan runs in CRAWL mode with this budget;
   * when omitted, the scan runs in SINGLE-PAGE mode (Phase 1 behavior).
   * Purely additive — existing payloads continue to mean single-page.
   */
  crawl: scanJobCrawlBudgetSchema.optional(),
});

const apiScanJobSchema = z.object({
  scanId: scanIdSchema,
  scanType: z.literal('api-scan'),
  target: scanJobApiTargetSchema,
});

const web3DappScanJobSchema = z.object({
  scanId: scanIdSchema,
  scanType: z.literal('web3-dapp'),
  target: scanJobWeb3TargetSchema,
});

/**
 * The scan job payload. Discriminated on `scanType` so each kind is strictly typed
 * (an AI scan always has an AI target; a web scan always has a single URL; an API
 * scan always has a raw-or-spec API target). Validated with Zod at BOTH ends: the
 * producer validates before enqueue, the consumer re-validates on receipt
 * (`CLAUDE.md` §3 — queue data is an external trust boundary).
 */
export const scanJobPayloadSchema = z.discriminatedUnion('scanType', [
  aiScanJobSchema,
  webScanJobSchema,
  apiScanJobSchema,
  web3DappScanJobSchema,
]);

export type ScanJobPayload = z.infer<typeof scanJobPayloadSchema>;

/**
 * Default BullMQ options for scan jobs.
 *
 * - `attempts: 3` + exponential backoff — scans depend on flaky externals (target
 *   endpoints, and the LLM attacker via OpenRouter, `ARCHITECTURE.md` §4.2). A small
 *   number of retries absorbs transient failures (rate limits, brief network blips)
 *   without hammering. 3 attempts = 1 try + 2 retries; exponential from 5s spaces
 *   them at ~5s, ~10s so a transient issue has time to clear. Deliberately modest —
 *   permanent failures (bad target, invalid payload) still surface quickly.
 * - `removeOnComplete` / `removeOnFail` — cap retained finished jobs so Redis does
 *   not grow unbounded; keep enough failed jobs for debugging.
 */
export const DEFAULT_SCAN_JOB_OPTIONS = {
  attempts: 3,
  backoff: { type: 'exponential', delay: 5_000 },
  removeOnComplete: { count: 1_000 },
  removeOnFail: { count: 5_000 },
} satisfies JobsOptions;

/**
 * Validate arbitrary input against the scan job payload schema. Throws `ZodError`
 * with a clear message on failure. Use at every trust boundary (enqueue, consume).
 */
export function parseScanJobPayload(input: unknown): ScanJobPayload {
  return scanJobPayloadSchema.parse(input);
}
