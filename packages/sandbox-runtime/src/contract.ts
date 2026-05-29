import { z } from 'zod';

import { findingSchema, scanConfigSchema, scanTypeSchema } from '@anthrion/scan-engine';

/**
 * Worker ↔ sandbox-container wire contract (T3.2).
 *
 * Communication mechanism for the run-once container pattern (ARCHITECTURE.md §5,
 * Pattern A):
 *   - INPUT  : the worker writes one {@link SandboxJob} as JSON to the container's
 *              STDIN, then closes stdin. stdin (not argv/env) is used so that future
 *              secret-bearing payloads (T3.3 endpoint auth, OpenRouter key) are NOT
 *              visible in `docker inspect` / `docker ps`.
 *   - OUTPUT : the container writes exactly one {@link SandboxResult} as a single
 *              JSON line to STDOUT, prefixed with {@link RESULT_LINE_PREFIX} so the
 *              worker can extract it even if a library prints stray text to stdout.
 *              All diagnostics/logs go to STDERR, never stdout.
 *
 * From the worker's point of view the result is EXTERNAL, untrusted data — it is
 * validated against {@link sandboxResultSchema} before use (CLAUDE.md §3). The
 * container ALSO validates its stdin against {@link sandboxJobSchema} (defense in
 * depth — stdin is external from the container's point of view too).
 *
 * This contract lives in `sandbox-runtime` (not `shared`) on purpose: the result
 * carries scan-engine `Finding`s, so the schema imports scan-engine's canonical
 * `findingSchema`. `shared` may NOT import `scan-engine` (ARCHITECTURE.md §2), so
 * a contract referencing `Finding` cannot live there. Using the canonical schema —
 * rather than re-mirroring it — avoids the drift CLAUDE.md §6 warns about.
 */

/** Prefix marking the single stdout line that carries the JSON result envelope. */
export const RESULT_LINE_PREFIX = '__ANTHRION_SANDBOX_RESULT__ ';

/**
 * Prefix marking a stdout line that carries a JSON scan-progress event (T4.2). The
 * container emits MANY of these DURING the scan (one per stage boundary), distinct from
 * the single {@link RESULT_LINE_PREFIX} line at the end and from ordinary log lines.
 * The worker streams stdout and routes lines by prefix: event → publish to Redis,
 * result → the final outcome, anything else → ignored as a log.
 */
export const EVENT_LINE_PREFIX = '__ANTHRION_SANDBOX_EVENT__ ';

/**
 * Env var that gates the diagnostic ops (`sleep`, `alloc`, `netcheck`). These ops
 * exist only to PROVE sandbox properties (lifetime limit, memory limit, network
 * isolation) from inside the real image. They are inert in production: the worker
 * sets this var only in tests, never on the production scan path.
 */
export const DIAGNOSTICS_ENV_VAR = 'ANTHRION_SANDBOX_DIAG';

// ── Job (worker → container, via stdin) ──────────────────────────────────────

/**
 * `selftest` — the T3.2 production-path proof. Runs REAL scan-engine Layer 1
 * static probes against an in-process deterministic target inside the sandbox and
 * reports the resulting (Zod-validated) `Finding`s plus the packaged Chromium
 * status. Proves the engine is packaged, executes in the sandbox, and that its
 * output crosses back to the worker.
 *
 * `selftest` remains a fast, dependency-free liveness/smoke op (no target, no LLM):
 * it proves the engine is packaged and the sandbox path works. The real per-scan op
 * is `scan` (below, T3.3), which runs the full engine from a mapped `ScanConfig`.
 */
const selftestJobSchema = z.object({ op: z.literal('selftest') });

/** `sleep` (diagnostic) — sleep `durationMs`, used to trip the container lifetime limit. */
const sleepJobSchema = z.object({
  op: z.literal('sleep'),
  durationMs: z.number().int().positive(),
});

/** `alloc` (diagnostic) — allocate `megabytes` of memory and hold, used to trip the memory limit (OOM). */
const allocJobSchema = z.object({
  op: z.literal('alloc'),
  megabytes: z.number().int().positive(),
  holdMs: z.number().int().nonnegative().default(10_000),
});

/** A single TCP reachability target for the `netcheck` diagnostic. */
export const netcheckTargetSchema = z.object({
  label: z.string().min(1),
  /** Literal IP/hostname, or the sentinel `"gateway"` resolved in-container to the default gateway (the host). */
  host: z.string().min(1),
  port: z.number().int().min(1).max(65_535),
  /** Per-attempt connect timeout. Loose enough that a reachable host always answers in time. */
  timeoutMs: z.number().int().positive().default(4_000),
});

export type NetcheckTarget = z.infer<typeof netcheckTargetSchema>;

/** `netcheck` (diagnostic) — probe TCP reachability of each target; used to prove network isolation. */
const netcheckJobSchema = z.object({
  op: z.literal('netcheck'),
  targets: z.array(netcheckTargetSchema).min(1),
});

/**
 * LLM runtime configuration sent into the container for an AI scan (T3.3).
 *
 * The pure `scan-engine` `ScanConfig` deliberately does NOT carry the OpenRouter key
 * or model slugs — those are LLM-client config, injected separately (scan-engine is
 * pure, T2.4). The worker supplies them here from validated env. `apiKey` is a SECRET
 * — it travels over stdin (never argv/env, so it is not in `docker inspect`) and is
 * never logged or placed in a `Finding` (CLAUDE.md §7).
 */
export const sandboxLlmConfigSchema = z.object({
  apiKey: z.string().min(1),
  models: z.object({ light: z.string().min(1), heavy: z.string().min(1) }),
  timeoutMs: z.number().int().positive().optional(),
  maxTokensPerCall: z.number().int().positive().optional(),
});

export type SandboxLlmConfig = z.infer<typeof sandboxLlmConfigSchema>;

/**
 * Web3 L3 provider configuration sent into the container for a web3-dapp scan
 * (Sprint A3, T-A3.7). Mirrors the SandboxLlmConfig pattern: secrets travel via
 * stdin (never argv/env), and the field is OPTIONAL — when both keys are unset
 * the sandbox runs L1/L2 normally and emits an honest coverage gap on L3
 * (rather than failing the whole scan). When set, the sandbox builds a real
 * AlchemyRpcClient + EtherscanExplorerClient and runs the L3 layer.
 *
 * Both keys are required TOGETHER for L3 to run — the loader (T-A3.4) needs
 * BOTH the RPC channel and the explorer channel to assemble an OnChainContext.
 * The schema accepts one-without-the-other (for forward compat), and run.ts
 * treats "either missing" the same as "both missing": L3 is skipped honestly.
 */
export const sandboxWeb3ConfigSchema = z.object({
  alchemyApiKey: z.string().min(1).optional(),
  etherscanApiKey: z.string().min(1).optional(),
});

export type SandboxWeb3Config = z.infer<typeof sandboxWeb3ConfigSchema>;

/**
 * `scan` — the real per-scan op (T3.3). Carries the scan-engine `ScanConfig` (built
 * by the worker from the validated job payload, T3.1 decision) and, for AI scans, the
 * `llm` runtime config. The container runs the full engine (`runHybridAiScan` /
 * `runWebAppScan`) from this config. `llm` is required for AI scans and absent for web
 * scans; the container enforces that (run.ts) — a missing key fails the scan honestly.
 * `web3` is optional and used only by `web3-dapp` scans (Sprint A3, T-A3.7).
 */
const scanJobSchema = z.object({
  op: z.literal('scan'),
  config: scanConfigSchema,
  llm: sandboxLlmConfigSchema.optional(),
  web3: sandboxWeb3ConfigSchema.optional(),
});

/** The job the worker sends to the container over stdin. */
export const sandboxJobSchema = z.discriminatedUnion('op', [
  selftestJobSchema,
  sleepJobSchema,
  allocJobSchema,
  netcheckJobSchema,
  scanJobSchema,
]);

export type SandboxJob = z.infer<typeof sandboxJobSchema>;

/** Ops that are gated behind {@link DIAGNOSTICS_ENV_VAR}. */
export const DIAGNOSTIC_OPS = ['sleep', 'alloc', 'netcheck'] as const;

// ── Result (container → worker, via stdout) ──────────────────────────────────

/** Chromium availability inside the image — proves the image is self-contained for web scans (T2.6/T3.3). */
export const chromiumStatusSchema = z.object({
  /** Path Playwright resolved for the bundled Chromium build. */
  executablePath: z.string(),
  /** Whether that executable exists on disk in the image. */
  present: z.boolean(),
  /** Whether a headless launch succeeded inside the sandbox (cap-drop, non-root, read-only fs). */
  launched: z.boolean(),
  /** Reported browser version when launched. */
  version: z.string().optional(),
  /** Launch failure reason, if `launched` is false. */
  error: z.string().optional(),
});

export type ChromiumStatus = z.infer<typeof chromiumStatusSchema>;

const runtimeInfoSchema = z.object({
  node: z.string(),
  user: z.string(),
});

/**
 * T-FIX.9: contract snapshot baked into the sandbox image at build time. The
 * worker compares this against its own source-of-truth schema at startup; a
 * mismatch means the image was built against a different scan-engine commit
 * (the "2-element scanTypeSchema" incident in T-A1.3 follow-up). Trips at
 * worker boot, not at first live scan.
 */
const sandboxContractSchema = z.object({
  /** `scanTypeSchema.options` as known to the image. */
  scanTypes: z.array(z.string()).min(1),
});

const selftestResultSchema = z.object({
  op: z.literal('selftest'),
  engine: z.object({
    layer1Outcome: z.string(),
    probesExecuted: z.number().int().nonnegative(),
    findingsCount: z.number().int().nonnegative(),
    /** Canonical, Zod-validated findings produced by the real engine run. */
    findings: z.array(findingSchema),
  }),
  chromium: chromiumStatusSchema,
  runtime: runtimeInfoSchema,
  /** Image-side schema snapshot for the worker drift guard (T-FIX.9). */
  contract: sandboxContractSchema,
});

const sleepResultSchema = z.object({
  op: z.literal('sleep'),
  sleptMs: z.number().int().nonnegative(),
});

const allocResultSchema = z.object({
  op: z.literal('alloc'),
  allocatedMegabytes: z.number().int().nonnegative(),
});

const netcheckResultSchema = z.object({
  op: z.literal('netcheck'),
  results: z.array(
    z.object({
      label: z.string(),
      host: z.string(),
      port: z.number().int(),
      reachable: z.boolean(),
    }),
  ),
});

// ── Scan result (the `scan` op, T3.3) ────────────────────────────────────────

/** Probe/coverage counts shared by both scan reports — coverage gaps stay visible. */
const scanStatsSchema = z.object({
  total: z.number().int().nonnegative(),
  executed: z.number().int().nonnegative(),
  detected: z.number().int().nonnegative(),
  clean: z.number().int().nonnegative(),
  notExecuted: z.number().int().nonnegative(),
});

/**
 * AI/LLM attack scan report — honest summary beyond just findings. `passedLayer1`
 * and the Layer 1/2 detail let consumers (T3.4) tell a genuine clean result from one
 * with coverage gaps (e.g. an unreachable target), per the T2.3 honesty principle.
 */
const aiScanReportSchema = z.object({
  scanType: z.literal('ai-llm-attack'),
  passedLayer1: z.boolean(),
  layer1Outcome: z.string(),
  layer1Stats: scanStatsSchema,
  layer2Ran: z.boolean(),
  layer2StoppedReason: z.string(),
  budgetUsed: z.number().int().nonnegative(),
  budgetCap: z.number().int().nonnegative(),
});

/**
 * Crawl-aggregate fields carried in a `web-app-vuln` scan report when the scan
 * ran in CRAWL mode (Phase 1.5 Sprint A2). Absent for single-page scans.
 *
 * Cost-ceiling rule (Sprint A2): `unvisitedDiscovered` and `robotsBlocked` are
 * capped at 50 entries each — enough to drive an honest coverage marker in the
 * UI/PDF without unbounded growth on a huge site. Counts always reflect the
 * full truth via `unvisitedDiscoveredCount` / `robotsBlockedCount`.
 *
 * Honesty rule: `pageLoaded` on the parent report is true iff `pagesLoaded > 0`
 * (i.e. AT LEAST ONE page in the crawl loaded). The worker's FAILED-path rule
 * then maps "no page loaded across the whole crawl" → FAILED (no clean bill
 * for an unreachable target — same posture as single-page T2.6).
 */
const crawlAggregateSchema = z.object({
  pagesVisited: z.number().int().nonnegative(),
  pagesLoaded: z.number().int().nonnegative(),
  pagesFailed: z.number().int().nonnegative(),
  pagesVulnerable: z.number().int().nonnegative(),
  stopReason: z.enum(['completed', 'budget-exhausted']),
  unvisitedDiscoveredCount: z.number().int().nonnegative(),
  robotsBlockedCount: z.number().int().nonnegative(),
  /** Up to 50 discovered-but-unvisited URLs (full count above). */
  unvisitedDiscovered: z.array(z.string()).max(50),
  /** Up to 50 robots-blocked URLs (full count above). */
  robotsBlocked: z.array(z.string()).max(50),
  /** Effective budget the crawl ran with — drives the UI/PDF caveat copy. */
  budget: z.object({
    maxDepth: z.number().int().nonnegative(),
    maxPages: z.number().int().positive(),
    respectRobots: z.boolean(),
  }),
});

export type CrawlAggregate = z.infer<typeof crawlAggregateSchema>;

/**
 * Web app vuln scan report. `pageLoaded === false` / `outcome === 'page-load-failed'`
 * is NOT "safe" — it is an unreachable target with no coverage (T2.6 honesty rule).
 *
 * Crawl extension (Sprint A2): when the scan ran in crawl mode, `crawl` is present
 * and carries the aggregate; `stats` then sums probe stats across all pages.
 * `pageLoaded` means "at least one page loaded" in crawl mode (FAILED rule above).
 * `httpStatus` / `finalUrl` are single-page concepts and stay absent for crawl.
 */
const webScanReportSchema = z.object({
  scanType: z.literal('web-app-vuln'),
  pageLoaded: z.boolean(),
  outcome: z.string(),
  stats: scanStatsSchema,
  httpStatus: z.number().int().optional(),
  finalUrl: z.string().optional(),
  loadError: z.string().optional(),
  crawl: crawlAggregateSchema.optional(),
});

/**
 * API security scan report (Phase 1.5 Sprint A1, T-A1.3). Mirrors `ApiScanReport`
 * from `scan-engine/api-scan.ts` at the wire boundary — primitive fields only,
 * no `Finding[]` or per-probe `results` (findings travel at the top of
 * {@link scanResultSchema}, lossless). `outcome === 'target-unreachable'` is
 * NOT "safe" — it means the baseline reachability check failed and no probe
 * meaningfully ran (T-A1.2 honesty rule); the worker maps this to a FAILED
 * scan (same rule as web `pageLoaded=false` and AI `target-unreachable`).
 * `coverage === 'raw'` surfaces the honest "shallow coverage" caveat — the
 * report layer (T-A1.4) is responsible for displaying it.
 */
const apiScanReportSchema = z.object({
  scanType: z.literal('api-scan'),
  /** `spec` = all operations enumerated; `raw` = single user-supplied endpoint. */
  coverage: z.enum(['spec', 'raw']),
  endpointCount: z.number().int().nonnegative(),
  outcome: z.enum(['vulnerable', 'passed', 'passed-with-gaps', 'target-unreachable']),
  stats: scanStatsSchema,
});

/**
 * Web3 dApp scan report (Sprint A3, T-A3.7). Mirrors the engine's three
 * per-layer report types (Web3L1Report / Web3L3Report / Web3L2Report) at the
 * wire boundary — primitive fields only, no `Finding[]` (findings travel at
 * the top of {@link scanResultSchema}, lossless across all layers).
 *
 * Target-unreachable for web3-dapp = `pageLoaded === false`: the page.goto
 * call could not reach the dApp at all. The L1 `no-interactive-flow-observed`
 * outcome is NOT target-unreachable — it means the page loaded but the
 * synthetic provider captured zero wallet requests; that case is an honest
 * coverage gap, not a billing-FAILED. Worker scan-runner maps `pageLoaded
 * === false` to ScanFailureReason='target-unreachable' (same rule as web).
 *
 * Per-layer stats are scanStatsSchema (5 fields) plus the L3/L2 extras the
 * engine surfaces (address coverage, aggregate finding count, coverage note
 * count). Drift between engine stats and these wire fields is caught at the
 * trust boundary — every report is re-validated when crossing the sandbox.
 */
const web3L3WireStatsSchema = scanStatsSchema.extend({
  addressCount: z.number().int().nonnegative(),
  unavailableAddressCount: z.number().int().nonnegative(),
  aggregateFindingCount: z.number().int().nonnegative(),
});

const web3L2WireStatsSchema = scanStatsSchema.extend({
  coverageNoteCount: z.number().int().nonnegative(),
});

const web3DappScanReportSchema = z.object({
  scanType: z.literal('web3-dapp'),
  chain: z.enum(['ethereum', 'base']),
  pageLoaded: z.boolean(),
  /** Honest reason the page did not load — present iff `pageLoaded === false`. */
  loadError: z.string().optional(),
  /** True iff the synthetic provider captured at least one wallet request. */
  observedInteractiveFlow: z.boolean(),
  l1Outcome: z.string(),
  l1Stats: scanStatsSchema,
  l3Outcome: z.string(),
  l3Stats: web3L3WireStatsSchema,
  l2Outcome: z.string(),
  l2Stats: web3L2WireStatsSchema,
  /** True iff L3 ran against the real provider (both Alchemy + Etherscan keys
   * present in `SandboxWeb3Config`). False = L3 was honestly skipped; the
   * sandbox installs a stub provider that returns `availability='unavailable'`
   * for every address, and the engine emits `web3-l3-on-chain-context-unavailable`
   * gaps as it would for any real provider outage — the worker-side report
   * surface (T-A3.7 follow-up) can frame the cause to the user from this
   * boolean. */
  l3ProviderConfigured: z.boolean(),
});

/** Engine report carried by a scan result — discriminated on scan type. */
export const scanReportSchema = z.discriminatedUnion('scanType', [
  aiScanReportSchema,
  webScanReportSchema,
  apiScanReportSchema,
  web3DappScanReportSchema,
]);

export type ScanReport = z.infer<typeof scanReportSchema>;
export type AiScanReport = z.infer<typeof aiScanReportSchema>;
export type WebScanReport = z.infer<typeof webScanReportSchema>;
export type ApiScanReport = z.infer<typeof apiScanReportSchema>;
export type Web3DappScanReport = z.infer<typeof web3DappScanReportSchema>;

/** Result of a full scan run inside the container (T3.3). */
const scanResultSchema = z.object({
  op: z.literal('scan'),
  /** Canonical, Zod-validated findings produced by the real engine run. */
  findings: z.array(findingSchema),
  report: scanReportSchema,
});

/** Emitted when the in-container op throws. The container also exits non-zero. */
const errorResultSchema = z.object({
  op: z.literal('error'),
  message: z.string(),
});

/** The result envelope the container writes to stdout. */
export const sandboxResultSchema = z.discriminatedUnion('op', [
  selftestResultSchema,
  sleepResultSchema,
  allocResultSchema,
  netcheckResultSchema,
  scanResultSchema,
  errorResultSchema,
]);

export type SandboxResult = z.infer<typeof sandboxResultSchema>;
export type SelftestResult = z.infer<typeof selftestResultSchema>;
export type NetcheckResult = z.infer<typeof netcheckResultSchema>;
export type ScanResult = z.infer<typeof scanResultSchema>;

/**
 * Extract and validate the result envelope from raw container stdout. The result
 * is the (last) line beginning with {@link RESULT_LINE_PREFIX}; everything else is
 * ignored. Returns the parsed, Zod-validated {@link SandboxResult}.
 *
 * Throws if no result line is present (container produced no result) or if the
 * JSON is malformed / fails schema validation (CLAUDE.md §3 — never trust the
 * container's output shape).
 */
export function parseSandboxResult(stdout: string): SandboxResult {
  const lines = stdout.split('\n');
  let payload: string | undefined;
  // Take the LAST matching line, so any earlier stray output cannot shadow it.
  for (const line of lines) {
    if (line.startsWith(RESULT_LINE_PREFIX)) {
      payload = line.slice(RESULT_LINE_PREFIX.length);
    }
  }
  if (payload === undefined) {
    throw new Error('Sandbox produced no result line on stdout.');
  }

  let json: unknown;
  try {
    json = JSON.parse(payload);
  } catch (cause) {
    throw new Error('Sandbox result line is not valid JSON.', { cause });
  }

  // Zod is the trust boundary: the parsed object is still untrusted until validated.
  return sandboxResultSchema.parse(json);
}
