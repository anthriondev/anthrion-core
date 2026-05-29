import { scanConfigSchema, type ScanConfig } from '@anthrion/scan-engine';
import {
  sandboxLlmConfigSchema,
  type SandboxJob,
  type SandboxLlmConfig,
  type SandboxWeb3Config,
} from '@anthrion/sandbox-runtime';
import { env, type ScanJobPayload } from '@anthrion/shared';

/**
 * Payload → `ScanConfig` mapping (T3.3, Part A).
 *
 * The job payload in `shared` carries primitive WIRE data (scan type + target params)
 * — NOT a `ScanConfig`, because `shared` may not import `scan-engine` (ARCHITECTURE.md
 * §2). T3.1 marked this explicitly: the worker (which MAY import `scan-engine`) builds
 * the `ScanConfig` and fills the engine's OPERATIONAL knobs (token budget, model tiers)
 * from validated env (ARCHITECTURE.md §4.2 — the per-scan token budget cap is required).
 *
 * The payload's AI target shapes intentionally mirror scan-engine's `AiTargetSpec`, so
 * the mapping passes the target through and lets `scanConfigSchema` apply engine
 * defaults (e.g. the apiKey header name, the web-scan timeouts). The mapping is total
 * for any Zod-valid payload; a structural mismatch surfaces as a thrown `ZodError`
 * (caught by the runner → a `mapping-error` scan failure, not a crash).
 */

/** Engine operational knobs (from env), filled into the `ScanConfig` by the worker. */
export interface ScanEngineKnobs {
  /** Per-scan token budget cap (input+output). ARCHITECTURE.md §4.2 — required. */
  tokenBudget: number;
}

/** LLM client knobs (from env) for AI scans — the secret key + model tier slugs. */
export interface ScanLlmKnobs {
  apiKey: string;
  lightModel: string;
  heavyModel: string;
}

/** Web3 L3 provider knobs (from env) for web3-dapp scans. Both fields are
 * optional — when either is absent the sandbox installs a stub provider that
 * yields honest "unavailable" coverage gaps on every address (T-A3.7). */
export interface ScanWeb3Knobs {
  alchemyApiKey?: string;
  etherscanApiKey?: string;
}

/** Deps for building a scan job — defaulted from env, overridable in tests. */
export interface BuildScanJobDeps {
  engine: ScanEngineKnobs;
  llm: ScanLlmKnobs;
  web3: ScanWeb3Knobs;
}

/** Read engine knobs from validated env (T2.4). */
export function engineKnobsFromEnv(): ScanEngineKnobs {
  return { tokenBudget: env.LLM_TOKEN_BUDGET_PER_SCAN };
}

/** Read LLM client knobs from validated env (T2.4 — model slugs are env, never hardcoded). */
export function llmKnobsFromEnv(): ScanLlmKnobs {
  return {
    apiKey: env.OPENROUTER_API_KEY,
    lightModel: env.LLM_MODEL_LIGHT,
    heavyModel: env.LLM_MODEL_HEAVY,
  };
}

/** Read Web3 L3 provider knobs from validated env. Both optional — the sandbox
 * runs L1/L2 normally and skips L3 honestly when either key is missing. */
export function web3KnobsFromEnv(): ScanWeb3Knobs {
  const out: ScanWeb3Knobs = {};
  if (env.WEB3_ALCHEMY_API_KEY !== undefined) out.alchemyApiKey = env.WEB3_ALCHEMY_API_KEY;
  if (env.WEB3_ETHERSCAN_API_KEY !== undefined) out.etherscanApiKey = env.WEB3_ETHERSCAN_API_KEY;
  return out;
}

/** Default deps, all from env. */
export function defaultBuildScanJobDeps(): BuildScanJobDeps {
  return { engine: engineKnobsFromEnv(), llm: llmKnobsFromEnv(), web3: web3KnobsFromEnv() };
}

/**
 * Map a validated job payload + engine knobs to a `ScanConfig`. The discriminated
 * `ScanConfig` (T2.1) distinguishes the scan kind — no ad-hoc branching beyond it.
 * Returns a parsed (defaults-applied) config; throws `ZodError` on a structural
 * mismatch.
 */
export function mapPayloadToScanConfig(payload: ScanJobPayload, knobs: ScanEngineKnobs): ScanConfig {
  if (payload.scanType === 'web-app-vuln') {
    // Web scan: URL from payload; per-operation timeouts come from engine defaults
    // (T2.6) applied by the schema — loose guards, configurable later if needed.
    // Sprint A2: forward the optional crawl budget. Omitting the field preserves
    // the Phase 1 single-page behavior; passing it switches to crawl mode and the
    // engine schema applies defaults for any unset sub-field (maxDepth/maxPages/…).
    return scanConfigSchema.parse({
      type: 'web-app-vuln',
      target: { url: payload.target.url },
      ...(payload.crawl !== undefined ? { crawl: payload.crawl } : {}),
    });
  }
  if (payload.scanType === 'api-scan') {
    // API scan (Phase 1.5 T-A1.3): the wire-layer target shape mirrors the engine's
    // `ApiTargetSpec` discriminated union (raw vs spec), so the mapping passes the
    // target through and lets `scanConfigSchema` apply engine defaults for
    // `timeoutMs` and `bodyCaptureMaxChars`. No token budget — API scan has no LLM.
    return scanConfigSchema.parse({
      type: 'api-scan',
      target: payload.target,
    });
  }
  if (payload.scanType === 'web3-dapp') {
    // Web3 dApp scan (Sprint A3, T-A3.7 → T-A3.8): URL + chain from payload;
    // per-operation timeouts + L1 observation window + connect-click-settle
    // come from engine defaults (T-A3.2) via the schema. walletInteractionDepth
    // is forwarded when present; the engine schema applies
    // DEFAULT_WEB3_WALLET_INTERACTION_DEPTH otherwise. No token budget —
    // web3-dapp has no LLM.
    return scanConfigSchema.parse({
      type: 'web3-dapp',
      target: {
        url: payload.target.url,
        chain: payload.target.chain,
        ...(payload.target.walletInteractionDepth !== undefined
          ? { walletInteractionDepth: payload.target.walletInteractionDepth }
          : {}),
      },
    });
  }
  // AI/LLM attack scan: target mirrors AiTargetSpec; token budget from env (T2.4).
  return scanConfigSchema.parse({
    type: 'ai-llm-attack',
    target: payload.target,
    tokenBudget: knobs.tokenBudget,
  });
}

/** Build the LLM runtime config (secret key + model tiers) for an AI scan. */
export function buildLlmConfig(knobs: ScanLlmKnobs): SandboxLlmConfig {
  // `apiKey` min(1) → an AI scan with no configured OpenRouter key fails here, which
  // the runner reports honestly as a mapping error (never a silent unauthenticated run).
  return sandboxLlmConfigSchema.parse({
    apiKey: knobs.apiKey,
    models: { light: knobs.lightModel, heavy: knobs.heavyModel },
  });
}

/**
 * Build the `scan` {@link SandboxJob} the worker sends into the container: the mapped
 * `ScanConfig` plus, for AI scans, the LLM runtime config, and for web3-dapp scans
 * the optional L3 provider config. Web and API scans need neither, so a missing
 * OpenRouter / Alchemy / Etherscan key never blocks them.
 */
export function buildScanSandboxJob(payload: ScanJobPayload, deps: BuildScanJobDeps): SandboxJob {
  const config = mapPayloadToScanConfig(payload, deps.engine);
  if (config.type === 'ai-llm-attack') {
    return { op: 'scan', config, llm: buildLlmConfig(deps.llm) };
  }
  if (config.type === 'web3-dapp') {
    const web3: SandboxWeb3Config = {};
    if (deps.web3.alchemyApiKey !== undefined) web3.alchemyApiKey = deps.web3.alchemyApiKey;
    if (deps.web3.etherscanApiKey !== undefined) web3.etherscanApiKey = deps.web3.etherscanApiKey;
    return { op: 'scan', config, web3 };
  }
  // Web and API scans run with no LLM / no L3 keys.
  return { op: 'scan', config };
}
