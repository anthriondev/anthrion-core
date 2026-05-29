import type { Finding } from './finding';
import {
  runLayer2Attack,
  type Layer2Options,
  type Layer2Report,
} from './layer2';
import type { LlmCaller } from './llm';
import { emitProgress, type ScanProgressCallback } from './progress';
import { runLayer1Probes, type Layer1Report, type Layer1RunnerOptions } from './runner';
import type { ScanTarget } from './target';
import type { TokenBudget } from './token-budget';
import type { CoveredCategory } from './coverage';

/**
 * Full hybrid AI/LLM scan runner (ARCHITECTURE.md §4.2): Layer 1 (static probes,
 * T2.3) then Layer 2 (adaptive LLM attacker, T2.5) ONLY if the target passes
 * Layer 1. Merges findings from both layers into a single `Finding[]`.
 *
 * Pure: only communicates via `ScanTarget.send()` and the `LlmCaller`/`TokenBudget` abstractions.
 */

export interface HybridAiScanOptions {
  /** Heavy-tier LLM attacker for Layer 2. */
  attackerLlm: LlmCaller;
  /** Heavy-tier LLM evaluator for Layer 2 (default: `attackerLlm`). */
  evaluatorLlm?: LlmCaller;
  /** Budget per scan (T2.4) — shared across all LLM calls. */
  budget: TokenBudget;
  /** Layer 1 runner options (e.g. custom probes). */
  layer1?: Layer1RunnerOptions;
  /** Layer 2 options (beyond attacker/evaluator/budget/gate already populated). */
  layer2?: {
    categories?: readonly CoveredCategory[];
    maxIterationsPerCategory?: number;
    useLlmEvaluator?: boolean;
    canaryFactory?: () => string;
  };
  /** Optional stage-level progress sink (T4.2). Best-effort; never affects the scan. */
  onProgress?: ScanProgressCallback;
}

export interface HybridAiScanReport {
  /** Combined Layer 1 + Layer 2 findings — one collection for consumers. */
  findings: Finding[];
  passedLayer1: boolean;
  layer1: Layer1Report;
  /** Layer 2 report (`ran: false` if skipped because Layer 1 was not passed). */
  layer2: Layer2Report;
}

export async function runHybridAiScan(
  target: ScanTarget,
  options: HybridAiScanOptions,
): Promise<HybridAiScanReport> {
  // Thread the progress sink into Layer 1 so it emits its own stage events.
  const layer1 = await runLayer1Probes(target, {
    ...(options.layer1 ?? {}),
    ...(options.onProgress !== undefined ? { onProgress: options.onProgress } : {}),
  });

  // Layer 2 runs only for targets that passed Layer 1 (gate, ARCHITECTURE §4.2). Emit
  // the Layer 2 boundary events only when it will actually run.
  if (layer1.passedLayer1) {
    emitProgress(options.onProgress, {
      phase: 'layer-2',
      status: 'started',
      message: 'Layer 1 passed — running Layer 2 adaptive attacker',
    });
  }

  const layer2Options: Layer2Options = {
    attackerLlm: options.attackerLlm,
    budget: options.budget,
    layer1Passed: layer1.passedLayer1,
    ...(options.evaluatorLlm !== undefined ? { evaluatorLlm: options.evaluatorLlm } : {}),
    ...(options.layer2?.categories !== undefined ? { categories: options.layer2.categories } : {}),
    ...(options.layer2?.maxIterationsPerCategory !== undefined
      ? { maxIterationsPerCategory: options.layer2.maxIterationsPerCategory }
      : {}),
    ...(options.layer2?.useLlmEvaluator !== undefined
      ? { useLlmEvaluator: options.layer2.useLlmEvaluator }
      : {}),
    ...(options.layer2?.canaryFactory !== undefined
      ? { canaryFactory: options.layer2.canaryFactory }
      : {}),
    ...(options.onProgress !== undefined ? { onProgress: options.onProgress } : {}),
  };

  // Layer 2 enforces the passedLayer1 gate itself; if not passed → ran:false.
  const layer2 = await runLayer2Attack(target, layer2Options);

  if (layer2.ran) {
    emitProgress(options.onProgress, {
      phase: 'layer-2',
      status: 'completed',
      message: `Layer 2 complete: ${layer2.stats.breached} categor(ies) breached`,
      detail: { breached: layer2.stats.breached, findings: layer2.findings.length },
    });
  }

  return {
    findings: [...layer1.findings, ...layer2.findings],
    passedLayer1: layer1.passedLayer1,
    layer1,
    layer2,
  };
}
