import { existsSync, readFileSync } from 'node:fs';
import { connect } from 'node:net';

import { chromium } from 'playwright';

import {
  AlchemyRpcClient,
  ApiRawTargetAdapter,
  ApiSpecTargetAdapter,
  DEFAULT_LAUNCH_ARGS,
  EndpointTargetAdapter,
  EtherscanExplorerClient,
  LAYER1_PROBES,
  OpenRouterLlmClient,
  PlaywrightWeb3DAppTarget,
  RemoteOnChainContextProvider,
  SystemPromptTargetAdapter,
  TokenBudget,
  buildSyntheticProviderScript,
  runApiScan as runApiScanEngine,
  runHybridAiScan,
  runLayer1Probes,
  runWeb3Layer1,
  runWeb3Layer2,
  runWeb3Layer3,
  runWebAppCrawl,
  runWebAppScan,
  scanTypeSchema,
  type AiTargetSpec,
  type ApiTarget,
  type ApiTargetSpec,
  type AttackInput,
  type ContractAddress,
  type CrawlScanResult,
  type OnChainContext,
  type OnChainContextProvider,
  type ScanConfig,
  type ScanProgressCallback,
  type ScanTarget,
  type TargetResponse,
  type WebPageScanResult,
} from '@anthrion/scan-engine';

import type {
  ChromiumStatus,
  NetcheckTarget,
  SandboxJob,
  SandboxLlmConfig,
  SandboxResult,
  SandboxWeb3Config,
} from './contract';

/**
 * Executes a {@link SandboxJob} inside the sandbox container and returns the
 * {@link SandboxResult}. Pure of process I/O (no stdin/stdout here — that is
 * `entry.ts`), so it is unit-testable on the host.
 *
 * The real per-scan op is `scan` (T3.3): it runs the FULL engine from a mapped
 * `ScanConfig` — `runHybridAiScan` (Layer 1 + adaptive Layer 2) for AI/LLM attack
 * scans, or `runWebAppScan` (Chromium DAST) for web scans — and collects `Finding`s.
 * `selftest` remains a fast, dependency-free liveness op (Layer 1 vs an echo target).
 */
export async function runSandboxJob(
  job: SandboxJob,
  onProgress?: ScanProgressCallback,
): Promise<SandboxResult> {
  switch (job.op) {
    case 'scan':
      return runScan(job.config, job.llm, job.web3, onProgress);
    case 'selftest':
      return runSelftest();
    case 'sleep':
      return runSleep(job.durationMs);
    case 'alloc':
      return runAlloc(job.megabytes, job.holdMs);
    case 'netcheck':
      return runNetcheck(job.targets);
  }
}

/**
 * Run a full scan from a `ScanConfig` (T3.3). The discriminated `ScanConfig` (T2.1)
 * selects the scan type — no ad-hoc branching beyond it. `onProgress` (T4.2) is the
 * engine's stage-event sink; the entrypoint wires it to write events to stdout.
 */
async function runScan(
  config: ScanConfig,
  llm: SandboxLlmConfig | undefined,
  web3: SandboxWeb3Config | undefined,
  onProgress: ScanProgressCallback | undefined,
): Promise<SandboxResult> {
  switch (config.type) {
    case 'web-app-vuln':
      return runWebScan(config, onProgress);
    case 'ai-llm-attack':
      return runAiScan(config, llm, onProgress);
    case 'api-scan':
      return runApiScan(config, onProgress);
    case 'web3-dapp':
      return runWeb3DappScan(config, web3, onProgress);
  }
}

/**
 * Web app vulnerability scan. Two modes:
 *   - Single-page (Phase 1 / T2.6) when `config.crawl` is undefined: Chromium
 *     DAST against the one URL.
 *   - Crawl (Phase 1.5 Sprint A2) when `config.crawl` is set: multi-page BFS
 *     from the seed, calling the same single-page unit per discovered URL,
 *     within the hard `maxDepth` / `maxPages` budget and respecting robots.txt.
 *
 * The output envelope is the same `web-app-vuln` shape either way; the optional
 * `crawl` aggregate distinguishes crawl reports. `pageLoaded` always means "at
 * least one page loaded" — the worker's FAILED-path rule (no page loaded → FAILED)
 * holds identically in both modes.
 */
async function runWebScan(
  config: Extract<ScanConfig, { type: 'web-app-vuln' }>,
  onProgress: ScanProgressCallback | undefined,
): Promise<SandboxResult> {
  if (config.crawl !== undefined) {
    return runWebCrawl(config, onProgress);
  }
  const page = await runWebAppScan(config, onProgress !== undefined ? { onProgress } : {});
  return {
    op: 'scan',
    findings: page.findings,
    report: {
      scanType: 'web-app-vuln',
      pageLoaded: page.pageLoaded,
      outcome: page.outcome,
      stats: page.stats,
      ...(page.httpStatus !== undefined ? { httpStatus: page.httpStatus } : {}),
      ...(page.finalUrl !== undefined ? { finalUrl: page.finalUrl } : {}),
      ...(page.loadError !== undefined ? { loadError: page.loadError } : {}),
    },
  };
}

/**
 * Crawl mode (Sprint A2). Aggregates the per-page outcomes into the wire report:
 *   - `pageLoaded` = at least one page loaded (drives worker FAILED-path rule)
 *   - `outcome`    = `'vulnerable'` if any page is vulnerable; else
 *                    `'page-load-failed'` if no page loaded; else
 *                    `'passed-with-gaps'` if any probe across pages did not
 *                    execute OR the crawl was budget-exhausted; else `'passed'`.
 *   - `stats`      = sum of per-page probe stats (drives the existing
 *                    `web-probes-not-executed` coverage gap).
 *   - `loadError`  = the seed's load error iff NO page loaded (honest "what went
 *                    wrong" detail for a fully-unreachable crawl).
 *   - `crawl`      = the structured aggregate (page counts, stop reason, the
 *                    Sprint A2 honesty lists, the effective budget).
 */
async function runWebCrawl(
  config: Extract<ScanConfig, { type: 'web-app-vuln' }>,
  onProgress: ScanProgressCallback | undefined,
): Promise<SandboxResult> {
  const crawl: CrawlScanResult = await runWebAppCrawl(
    config,
    onProgress !== undefined ? { onProgress } : {},
  );
  const aggregateStats = aggregateProbeStats(crawl.pages);
  const pageLoaded = crawl.stats.pagesLoaded > 0;
  const outcome = deriveCrawlOutcome(crawl);
  const seedLoadError =
    !pageLoaded && crawl.pages.length > 0 ? crawl.pages[0]?.loadError : undefined;

  return {
    op: 'scan',
    findings: crawl.findings,
    report: {
      scanType: 'web-app-vuln',
      pageLoaded,
      outcome,
      stats: aggregateStats,
      ...(seedLoadError !== undefined ? { loadError: seedLoadError } : {}),
      crawl: {
        pagesVisited: crawl.stats.pagesVisited,
        pagesLoaded: crawl.stats.pagesLoaded,
        pagesFailed: crawl.stats.pagesFailed,
        pagesVulnerable: crawl.stats.pagesVulnerable,
        stopReason: crawl.stopReason,
        unvisitedDiscoveredCount: crawl.unvisitedDiscovered.length,
        robotsBlockedCount: crawl.robotsBlocked.length,
        // Cap the URL lists at 50 to match the wire schema bound — honesty via
        // the always-true total counts above; the lists are example-driven UX.
        unvisitedDiscovered: crawl.unvisitedDiscovered.slice(0, 50),
        robotsBlocked: crawl.robotsBlocked.slice(0, 50),
        budget: {
          maxDepth: crawl.budget.maxDepth,
          maxPages: crawl.budget.maxPages,
          respectRobots: crawl.budget.respectRobots,
        },
      },
    },
  };
}

function aggregateProbeStats(pages: readonly WebPageScanResult[]): {
  total: number;
  executed: number;
  detected: number;
  clean: number;
  notExecuted: number;
} {
  let total = 0;
  let executed = 0;
  let detected = 0;
  let clean = 0;
  let notExecuted = 0;
  for (const p of pages) {
    total += p.stats.total;
    executed += p.stats.executed;
    detected += p.stats.detected;
    clean += p.stats.clean;
    notExecuted += p.stats.notExecuted;
  }
  return { total, executed, detected, clean, notExecuted };
}

function deriveCrawlOutcome(crawl: CrawlScanResult): string {
  if (crawl.stats.pagesVulnerable > 0) return 'vulnerable';
  if (crawl.stats.pagesLoaded === 0) return 'page-load-failed';
  // A budget-exhausted crawl or any non-executed probe → coverage is incomplete:
  // honest "passed-with-gaps", never a clean "passed".
  const anyProbeNotExecuted = crawl.pages.some((p) => p.stats.notExecuted > 0);
  if (crawl.stopReason === 'budget-exhausted' || anyProbeNotExecuted) {
    return 'passed-with-gaps';
  }
  return 'passed';
}

/** AI/LLM attack scan: hybrid Layer 1 + adaptive Layer 2 (T2.5) against the target. */
async function runAiScan(
  config: Extract<ScanConfig, { type: 'ai-llm-attack' }>,
  llm: SandboxLlmConfig | undefined,
  onProgress: ScanProgressCallback | undefined,
): Promise<SandboxResult> {
  if (llm === undefined) {
    // Honest failure: an AI scan with no LLM runtime config cannot run (CLAUDE.md §4).
    throw new Error('AI scan requires llm runtime config (OpenRouter key + model slugs).');
  }

  const client = new OpenRouterLlmClient({
    apiKey: llm.apiKey,
    models: llm.models,
    ...(llm.timeoutMs !== undefined ? { timeoutMs: llm.timeoutMs } : {}),
    ...(llm.maxTokensPerCall !== undefined ? { maxTokensPerCall: llm.maxTokensPerCall } : {}),
  });
  // One TokenBudget per scan — the hard LLM-cost cap (ARCHITECTURE.md §4.2).
  const budget = new TokenBudget(config.tokenBudget);
  const target = buildAiTarget(config.target, client, budget);

  const report = await runHybridAiScan(target, {
    // Layer 2 attacker/evaluator use the heavy tier; budget shared across all calls.
    attackerLlm: client.caller('heavy', budget),
    budget,
    ...(config.maxIterationsPerCategory !== undefined
      ? { layer2: { maxIterationsPerCategory: config.maxIterationsPerCategory } }
      : {}),
    ...(onProgress !== undefined ? { onProgress } : {}),
  });

  return {
    op: 'scan',
    findings: report.findings,
    report: {
      scanType: 'ai-llm-attack',
      passedLayer1: report.passedLayer1,
      layer1Outcome: report.layer1.outcome,
      layer1Stats: report.layer1.stats,
      layer2Ran: report.layer2.ran,
      layer2StoppedReason: report.layer2.stoppedReason,
      budgetUsed: budget.used,
      budgetCap: budget.cap,
    },
  };
}

/**
 * Build the `ScanTarget` adapter for an AI scan (T2.2). Endpoint targets call the
 * user's URL directly; system-prompt targets execute the pasted prompt via our
 * workhorse (light) model so attack logic above is unaware of the target kind.
 */
function buildAiTarget(
  target: AiTargetSpec,
  client: OpenRouterLlmClient,
  budget: TokenBudget,
): ScanTarget {
  if (target.kind === 'endpoint') {
    return new EndpointTargetAdapter(target);
  }
  return new SystemPromptTargetAdapter(target, client.caller('light', budget));
}

/**
 * API security scan (Phase 1.5 Sprint A1, T-A1.3). The discriminated `ApiTargetSpec`
 * (raw vs spec) selects which adapter to build; the curated `API_PROBES` run via
 * `runApiScan` (T-A1.2). No LLM — API scan is HTTP-shaped (T-A1.1). The shared
 * per-request mechanics (origin lock, timeout, body cap) live inside the adapter
 * so raw and spec modes cannot drift on those properties.
 */
async function runApiScan(
  config: Extract<ScanConfig, { type: 'api-scan' }>,
  onProgress: ScanProgressCallback | undefined,
): Promise<SandboxResult> {
  const target = await buildApiTarget(config.target, {
    timeoutMs: config.timeoutMs,
    bodyCaptureMaxChars: config.bodyCaptureMaxChars,
  });

  const report = await runApiScanEngine(target, {
    ...(onProgress !== undefined ? { onProgress } : {}),
  });

  return {
    op: 'scan',
    findings: report.findings,
    report: {
      scanType: 'api-scan',
      coverage: report.coverage,
      endpointCount: report.endpointCount,
      outcome: report.outcome,
      stats: report.stats,
    },
  };
}

/**
 * Construct the API target adapter for an API scan. Raw mode synchronously wraps a
 * single endpoint URL; spec mode dereferences an OpenAPI/Swagger document, which is
 * async — its constructor is private, factory `create()` enforces the async path
 * and the safe-parse property (`resolve.external = false` blocks external `$ref`s).
 */
async function buildApiTarget(
  target: ApiTargetSpec,
  options: { timeoutMs: number; bodyCaptureMaxChars: number },
): Promise<ApiTarget> {
  if (target.kind === 'raw') {
    return new ApiRawTargetAdapter(target, options);
  }
  return ApiSpecTargetAdapter.create(target, options);
}

/**
 * Web3 dApp scan (Phase 1.5 Sprint A3, T-A3.7). Owns the Chromium lifecycle
 * end-to-end: launch → install synthetic EIP-1193 provider (BEFORE navigation)
 * → page.goto → wait the L1 observation window → assemble the
 * `PlaywrightWeb3DAppTarget` → run L1 (wallet interaction) → harvest contract
 * addresses → run L3 (on-chain context, real provider when keys configured,
 * stub provider with honest "unavailable" otherwise) → run L2 (frontend /
 * infrastructure) → aggregate findings + per-layer reports.
 *
 * Target-unreachable rule: a navigation failure / null response means
 * `pageLoaded === false` — the worker maps that to ScanFailureReason
 * 'target-unreachable' (same as the web-app-vuln rule). A page that loaded
 * but produced no wallet requests (L1 no-interactive-flow-observed) is NOT
 * target-unreachable; it is an honest coverage gap on L1, and L2/L3 still
 * run against the loaded page surface.
 *
 * Closure rule: the browser is closed in a `finally` so a thrown probe never
 * leaks Chromium across scans.
 */
async function runWeb3DappScan(
  config: Extract<ScanConfig, { type: 'web3-dapp' }>,
  web3: SandboxWeb3Config | undefined,
  onProgress: ScanProgressCallback | undefined,
): Promise<SandboxResult> {
  const browser = await chromium.launch({ headless: true, args: [...DEFAULT_LAUNCH_ARGS] });
  try {
    const context = await browser.newContext();
    try {
      const page = await context.newPage();
      // Synthetic provider MUST be installed before goto so the dApp's bootstrap
      // sees an EIP-1193 provider and the capture array is initialised before
      // the first wallet request lands. addInitScript runs in every new context.
      await page.addInitScript(buildSyntheticProviderScript(config.target.chain));

      let response;
      try {
        response = await page.goto(config.target.url, {
          timeout: config.timeouts.navigationMs,
          waitUntil: 'domcontentloaded',
        });
      } catch (cause) {
        return web3DappPageLoadFailed(config, cause instanceof Error ? cause.message : String(cause));
      }
      if (response === null) {
        return web3DappPageLoadFailed(config, 'navigation returned no main response');
      }

      // Observation window: the dApp's bootstrap (RainbowKit / wagmi / web3modal)
      // typically issues several read-only RPC calls a few hundred ms after
      // DOMContentLoaded. The window is bounded to keep scan cost predictable.
      await new Promise<void>((resolve) => setTimeout(resolve, config.timeouts.l1ObservationMs));

      const target = new PlaywrightWeb3DAppTarget(page, response, config.target.url, config.target.chain);

      // Layers: L1 (in-process wallet inspection) → harvest contracts → L3
      // (RPC + explorer, separate channel) → L2 (page-level + small outbound).
      // Each runner uses the SAME loaded page; the harvest call is memoised
      // inside `PlaywrightWeb3DAppTarget.referencedContracts()`.
      const l1 = await runWeb3Layer1(target, {
        probeTimeoutMs: config.timeouts.probeMs,
        ...(onProgress !== undefined ? { onProgress } : {}),
      });

      const referencedContracts = await target.referencedContracts();
      const alchemyKey = web3?.alchemyApiKey;
      const etherscanKey = web3?.etherscanApiKey;
      const providerConfigured = alchemyKey !== undefined && etherscanKey !== undefined;
      const provider: OnChainContextProvider = providerConfigured
        ? new RemoteOnChainContextProvider({
            chain: config.target.chain,
            rpc: new AlchemyRpcClient({ apiKey: alchemyKey, chain: config.target.chain }),
            explorer: new EtherscanExplorerClient({ apiKey: etherscanKey, chain: config.target.chain }),
          })
        : new NotConfiguredOnChainContextProvider(config.target.chain);
      const l3 = await runWeb3Layer3(referencedContracts, provider, {
        probeTimeoutMs: config.timeouts.probeMs,
        ...(onProgress !== undefined ? { onProgress } : {}),
      });

      const l2 = await runWeb3Layer2(target, {
        probeTimeoutMs: config.timeouts.probeMs,
        ...(onProgress !== undefined ? { onProgress } : {}),
      });

      return {
        op: 'scan',
        findings: [...l1.findings, ...l3.findings, ...l2.findings],
        report: {
          scanType: 'web3-dapp',
          chain: config.target.chain,
          pageLoaded: true,
          observedInteractiveFlow: l1.observedInteractiveFlow,
          l1Outcome: l1.outcome,
          l1Stats: pickScanStats(l1.stats),
          l3Outcome: l3.outcome,
          l3Stats: {
            ...pickScanStats(l3.stats),
            addressCount: l3.stats.addressCount,
            unavailableAddressCount: l3.stats.unavailableAddressCount,
            aggregateFindingCount: l3.stats.aggregateFindingCount,
          },
          l2Outcome: l2.outcome,
          l2Stats: {
            ...pickScanStats(l2.stats),
            coverageNoteCount: l2.stats.coverageNoteCount,
          },
          l3ProviderConfigured: providerConfigured,
        },
      };
    } finally {
      await context.close().catch(() => undefined);
    }
  } finally {
    await browser.close().catch(() => undefined);
  }
}

/** "Page did not load" honest result — every layer is `not-executed`, the worker
 * maps `pageLoaded: false` to ScanFailureReason='target-unreachable' (same rule
 * as web-app-vuln). No coverage is faked; the report carries empty stats. */
function web3DappPageLoadFailed(
  config: Extract<ScanConfig, { type: 'web3-dapp' }>,
  loadError: string,
): SandboxResult {
  const empty = { total: 0, executed: 0, detected: 0, clean: 0, notExecuted: 0 };
  return {
    op: 'scan',
    findings: [],
    report: {
      scanType: 'web3-dapp',
      chain: config.target.chain,
      pageLoaded: false,
      loadError,
      observedInteractiveFlow: false,
      l1Outcome: 'page-load-failed',
      l1Stats: empty,
      l3Outcome: 'no-contracts-observed',
      l3Stats: { ...empty, addressCount: 0, unavailableAddressCount: 0, aggregateFindingCount: 0 },
      l2Outcome: 'passed-with-gaps',
      l2Stats: { ...empty, coverageNoteCount: 0 },
      l3ProviderConfigured: false,
    },
  };
}

function pickScanStats(stats: {
  total: number;
  executed: number;
  detected: number;
  clean: number;
  notExecuted: number;
}): { total: number; executed: number; detected: number; clean: number; notExecuted: number } {
  return {
    total: stats.total,
    executed: stats.executed,
    detected: stats.detected,
    clean: stats.clean,
    notExecuted: stats.notExecuted,
  };
}

/**
 * Stub `OnChainContextProvider` used when the operator did not configure both
 * the Alchemy and Etherscan API keys. Every `getContractContext` call resolves
 * to an `OnChainContext` with `availability='unavailable'` and a clear,
 * key-free `unavailableReason`. The L3 runner then emits its
 * `web3-l3-on-chain-context-unavailable` coverage gap per address — exactly
 * the graceful-degradation path the loader (T-A3.4) was designed for. No
 * fabricated findings, no silent skip.
 */
class NotConfiguredOnChainContextProvider implements OnChainContextProvider {
  readonly chain: 'ethereum' | 'base';
  constructor(chain: 'ethereum' | 'base') {
    this.chain = chain;
  }
  getContractContext(address: ContractAddress): Promise<OnChainContext> {
    return Promise.resolve({
      address,
      chain: this.chain,
      kind: 'unknown',
      proxy: null,
      admin: null,
      explorer: null,
      availability: 'unavailable',
      unavailableReason:
        'On-chain context provider not configured (WEB3_ALCHEMY_API_KEY / WEB3_ETHERSCAN_API_KEY unset); L3 honestly skipped.',
    });
  }
}

/**
 * Deterministic self-test target: a REAL `ScanTarget` implementation that echoes
 * the attack payload back as the response. Echoing the planted canary tokens makes
 * the Layer 1 canary detectors fire, so the real engine produces real findings.
 * This is a test harness target, NOT a mock of a customer target or a fake scan.
 */
class EchoSelftestTarget implements ScanTarget {
  send(input: AttackInput): Promise<TargetResponse> {
    return Promise.resolve({ content: input.payload });
  }
}

async function runSelftest(): Promise<SandboxResult> {
  // Real Layer 1 engine run inside the sandbox. Findings are Zod-validated by the
  // engine before they are returned (see runner.ts).
  const report = await runLayer1Probes(new EchoSelftestTarget());

  return {
    op: 'selftest',
    engine: {
      layer1Outcome: report.outcome,
      probesExecuted: report.stats.executed,
      findingsCount: report.findings.length,
      findings: report.findings,
    },
    chromium: await probeChromium(),
    runtime: {
      node: process.version,
      user: runtimeUser(),
    },
    // T-FIX.9: schema snapshot baked into the IMAGE so the worker can fail
    // loudly at boot when the image was built against a different scan-engine
    // commit (the "2-element scanTypeSchema" incident).
    contract: {
      scanTypes: [...scanTypeSchema.options],
    },
  };
}

/**
 * Resolve and exercise the Chromium bundled in the image. Proves the image is
 * self-contained for the web scan (T2.6/T3.3) and that Chromium actually launches
 * under the sandbox hardening (cap-drop, non-root, read-only rootfs). Uses the same
 * launch args the web scan uses (`--no-sandbox` relies on Docker isolation — T2.6).
 */
async function probeChromium(): Promise<ChromiumStatus> {
  let executablePath: string;
  try {
    executablePath = chromium.executablePath();
  } catch (cause) {
    return {
      executablePath: '',
      present: false,
      launched: false,
      error: cause instanceof Error ? cause.message : String(cause),
    };
  }
  const present = existsSync(executablePath);

  if (!present) {
    return { executablePath, present, launched: false, error: 'Chromium executable not found in image.' };
  }

  try {
    const browser = await chromium.launch({ args: [...DEFAULT_LAUNCH_ARGS] });
    try {
      const version = browser.version();
      return { executablePath, present, launched: true, version };
    } finally {
      await browser.close();
    }
  } catch (cause) {
    // Surface the failure honestly (do not swallow) — it would block the T3.3 web scan.
    return {
      executablePath,
      present,
      launched: false,
      error: cause instanceof Error ? cause.message : String(cause),
    };
  }
}

function runtimeUser(): string {
  // `process.getuid` is undefined on non-POSIX; the sandbox is always Linux.
  const uid = typeof process.getuid === 'function' ? process.getuid() : -1;
  return `uid=${uid}`;
}

async function runSleep(durationMs: number): Promise<SandboxResult> {
  await new Promise<void>((resolve) => {
    setTimeout(resolve, durationMs);
  });
  return { op: 'sleep', sleptMs: durationMs };
}

async function runAlloc(megabytes: number, holdMs: number): Promise<SandboxResult> {
  // Allocate and TOUCH the memory so the kernel actually backs the pages (otherwise
  // the limit is never hit). Hold the references so they cannot be GC'd, then wait —
  // a container under a tight memory limit is OOM-killed before this returns.
  const chunks: Buffer[] = [];
  for (let i = 0; i < megabytes; i += 1) {
    chunks.push(Buffer.alloc(1024 * 1024, 1));
  }
  await new Promise<void>((resolve) => {
    setTimeout(resolve, holdMs);
  });
  return { op: 'alloc', allocatedMegabytes: chunks.length };
}

async function runNetcheck(targets: readonly NetcheckTarget[]): Promise<SandboxResult> {
  const gateway = readDefaultGateway();
  const results = await Promise.all(
    targets.map(async (target) => {
      const host = target.host === 'gateway' ? gateway : target.host;
      const reachable = host === undefined ? false : await tcpReachable(host, target.port, target.timeoutMs);
      return { label: target.label, host: host ?? 'gateway-unresolved', port: target.port, reachable };
    }),
  );
  return { op: 'netcheck', results };
}

/** True iff a TCP connection to host:port completes within `timeoutMs`. */
function tcpReachable(host: string, port: number, timeoutMs: number): Promise<boolean> {
  return new Promise<boolean>((resolve) => {
    const socket = connect({ host, port });
    let settled = false;
    const done = (reachable: boolean): void => {
      if (settled) {
        return;
      }
      settled = true;
      socket.destroy();
      resolve(reachable);
    };
    socket.setTimeout(timeoutMs);
    socket.once('connect', () => done(true));
    socket.once('timeout', () => done(false));
    socket.once('error', () => done(false));
  });
}

/**
 * Read the container's default-gateway IPv4 from `/proc/net/route`. The gateway is
 * the host, so this is the address the network-isolation test points at to prove
 * the host's published service ports are unreachable from inside the sandbox.
 */
function readDefaultGateway(): string | undefined {
  let table: string;
  try {
    table = readFileSync('/proc/net/route', 'utf8');
  } catch {
    return undefined;
  }
  for (const line of table.split('\n').slice(1)) {
    const cols = line.trim().split(/\s+/);
    const destination = cols[1];
    const gatewayHex = cols[2];
    if (destination === '00000000' && gatewayHex !== undefined && gatewayHex.length === 8) {
      // Little-endian hex → dotted quad.
      const b0 = parseInt(gatewayHex.slice(6, 8), 16);
      const b1 = parseInt(gatewayHex.slice(4, 6), 16);
      const b2 = parseInt(gatewayHex.slice(2, 4), 16);
      const b3 = parseInt(gatewayHex.slice(0, 2), 16);
      return `${b0}.${b1}.${b2}.${b3}`;
    }
  }
  return undefined;
}
