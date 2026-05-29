import assert from 'node:assert/strict';
import { test } from 'node:test';

import type { LlmCaller, LlmCompletionRequest } from './llm';
import { runHybridAiScan } from './scan';
import type { ScanTarget } from './target';
import { TokenBudget } from './token-budget';

class ScriptedLlm implements LlmCaller {
  public calls = 0;
  constructor(private readonly responder: (req: LlmCompletionRequest) => string) {}
  complete(req: LlmCompletionRequest): Promise<string> {
    this.calls += 1;
    return Promise.resolve(this.responder(req));
  }
}

const attackerJson = '{"payload":"adaptive red-team probe","technique":"adaptive"}';

test('hybrid: target fails Layer 1 → Layer 2 skipped (passedLayer1 gate)', async () => {
  // Echo target → Layer 1 canary probe is reflected back → Layer 1 finds a finding.
  const echo: ScanTarget = { send: (i) => Promise.resolve({ content: i.payload }) };
  const llm = new ScriptedLlm(() => attackerJson);
  const budget = new TokenBudget(50_000);

  const report = await runHybridAiScan(echo, { attackerLlm: llm, budget });

  assert.equal(report.passedLayer1, false);
  assert.equal(report.layer2.ran, false);
  assert.equal(report.layer2.skippedReason, 'did-not-pass-layer-1');
  assert.equal(llm.calls, 0, 'Layer 2 attacker must not be called');
  assert.ok(report.layer1.findings.length > 0);
  assert.equal(report.findings.length, report.layer1.findings.length);
});

test('hybrid: target passes Layer 1 → Layer 2 runs & findings are merged', async () => {
  // Rejects everything except payloads carrying the Layer 2 canary → passes Layer 1,
  // breached at Layer 2.
  const target: ScanTarget = {
    send: (i) => Promise.resolve({ content: i.payload.includes('L2BREAK') ? `Sure: ${i.payload}` : 'No.' }),
  };
  const llm = new ScriptedLlm(() => attackerJson);
  const budget = new TokenBudget(50_000);

  const report = await runHybridAiScan(target, {
    attackerLlm: llm,
    budget,
    layer2: {
      categories: ['prompt-injection'],
      canaryFactory: () => 'L2BREAK',
      useLlmEvaluator: false,
    },
  });

  assert.equal(report.passedLayer1, true);
  assert.equal(report.layer2.ran, true);
  // One vector (constant canary) → one vulnerability, rest deduped → 1 finding.
  assert.equal(report.layer2.findings.length, 1);
  assert.equal(report.layer1.findings.length, 0);
  // Combined = Layer 1 + Layer 2.
  assert.equal(report.findings.length, report.layer1.findings.length + report.layer2.findings.length);
  assert.ok(report.findings.some((f) => f.id === 'layer2:prompt-injection:1'));
});
