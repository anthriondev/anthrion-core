import assert from 'node:assert/strict';
import { test } from 'node:test';

import { runLayer2Attack } from './layer2';
import { OpenRouterLlmClient } from './llm-client';
import type { ScanTarget } from './target';
import { TokenBudget } from './token-budget';

/**
 * Layer 2 LIVE PATH test (T2.5 Section D): proves the adaptive loop runs
 * end-to-end with a REAL LLM attacker (OpenRouter) against a simple mock target.
 * Economical: 1 category, small budget, LLM evaluator disabled (canary is sufficient),
 * echo target so a breach is proven in 1 iteration.
 *
 * Gated on `OPENROUTER_API_KEY` → routine `pnpm test` skips it (no cost).
 * To run for real:
 *   node --env-file=../../.env --import tsx --test src/layer2.live.test.ts
 * (from packages/scan-engine).
 */
const apiKey = process.env['OPENROUTER_API_KEY'];
const heavyModelEnv = process.env['LLM_MODEL_HEAVY'];

test(
  'Layer 2: attacker→target→evaluator loop runs with a real LLM (heavy tier)',
  {
    skip:
      apiKey === undefined || apiKey === ''
        ? 'OPENROUTER_API_KEY not set — live calls skipped'
        : heavyModelEnv === undefined || heavyModelEnv === ''
          ? 'LLM_MODEL_HEAVY not set — live calls skipped'
          : false,
  },
  async () => {
    const key = apiKey ?? '';
    const heavyModel = heavyModelEnv ?? '';

    const client = new OpenRouterLlmClient({
      apiKey: key,
      models: { light: heavyModel, heavy: heavyModel },
      maxTokensPerCall: 256,
      title: 'ANTHRION Scan Engine (T2.5 live)',
    });
    const budget = new TokenBudget(4_000);
    const attackerLlm = client.caller('heavy', budget);

    // Vulnerable mock target: echoes the payload (injected canary is reflected back).
    const echoTarget: ScanTarget = {
      send: (input) => Promise.resolve({ content: `Understood. ${input.payload}` }),
    };

    const report = await runLayer2Attack(echoTarget, {
      attackerLlm,
      budget,
      layer1Passed: true,
      categories: ['prompt-injection'],
      maxIterationsPerCategory: 3, // allow room for multi-finding exploration
      useLlmEvaluator: false,
    });

    assert.equal(report.ran, true);
    // Echo target breaches via canary; multi-finding exploration may yield
    // >1 vulnerability if the real attacker varies its vectors (non-deterministic).
    assert.ok(report.findings.length >= 1, 'echo target should breach via canary');
    assert.equal(report.findings[0]?.category, 'prompt-injection');
    assert.ok(budget.used > 0, 'real attacker consumes tokens');

    console.log(
      `[live l2] stopped=${report.stoppedReason} findings=${report.findings.length} ` +
        `budgetUsed=${budget.used}/${budget.cap} ` +
        `results=${JSON.stringify(report.results.map((r) => ({ c: r.category, s: r.status, it: r.iterations })))}`,
    );
  },
);
