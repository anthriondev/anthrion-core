import assert from 'node:assert/strict';
import { test } from 'node:test';

import { OpenRouterLlmClient } from './llm-client';
import { TokenBudget } from './token-budget';

/**
 * Tests the REAL path to OpenRouter (T2.4 DoD: "LLM client works"). Uses the
 * operator's balance → kept cheap: a single small call to the `light` model.
 *
 * Gated on `OPENROUTER_API_KEY` and `LLM_MODEL_LIGHT` (LLM_MODEL_HEAVY falls back
 * to LLM_MODEL_LIGHT if unset). A plain `pnpm test` (without env) SKIPS this test
 * to keep the suite green and cost-free. To verify the integration, run with the
 * env loaded:
 *   node --env-file=../../.env --import tsx --test src/llm-client.live.test.ts
 * (from packages/scan-engine). Check the report for real call results.
 */
const apiKey = process.env['OPENROUTER_API_KEY'];
const lightModelEnv = process.env['LLM_MODEL_LIGHT'];

test(
  'real call to OpenRouter replies and parses correctly (tier: light)',
  {
    skip:
      apiKey === undefined || apiKey === ''
        ? 'OPENROUTER_API_KEY is not set — live call skipped'
        : lightModelEnv === undefined || lightModelEnv === ''
          ? 'LLM_MODEL_LIGHT is not set — live call skipped'
          : false,
  },
  async () => {
    // apiKey + lightModelEnv guaranteed by the skip gate above.
    const key = apiKey ?? '';
    const lightModel = lightModelEnv ?? '';
    const heavyModel = process.env['LLM_MODEL_HEAVY'] ?? lightModel;

    const client = new OpenRouterLlmClient({
      apiKey: key,
      models: { light: lightModel, heavy: heavyModel },
      title: 'ANTHRION Scan Engine (T2.4 smoke test)',
      maxTokensPerCall: 32,
    });
    const budget = new TokenBudget(2_000);

    const result = await client.complete({
      system: 'You are a terse assistant. Reply with a single word.',
      user: 'Reply with exactly the word: PONG',
      tier: 'light',
      budget,
    });

    assert.ok(result.content.length > 0, 'model must reply with content');
    assert.ok(result.usage.totalTokens > 0, 'token usage must be > 0');
    assert.equal(budget.used, result.usage.totalTokens, 'budget records real tokens');

    // Evidence for the report (not secret).
    console.log(
      `[live] model=${result.model} content=${JSON.stringify(result.content)} ` +
        `usage=prompt:${result.usage.promptTokens} completion:${result.usage.completionTokens} ` +
        `total:${result.usage.totalTokens} cached:${result.usage.cachedTokens ?? 0}`,
    );
  },
);
