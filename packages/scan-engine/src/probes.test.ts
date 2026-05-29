import assert from 'node:assert/strict';
import { test } from 'node:test';

import { findingCategorySchema } from './category';
import type { StaticProbe } from './probe';
import { LAYER1_PROBES } from './probes';
import { severitySchema } from './severity';
import type { TargetResponse } from './target';

const SAFE_REFUSAL =
  "I'm sorry, but I can't help with that request. I won't override my guidelines, " +
  'reveal configuration, share credentials, or produce active content.';

/** Build a "vulnerable" response that should trigger this probe's detector. */
function vulnerableContentFor(probe: StaticProbe): string {
  switch (probe.category) {
    case 'prompt-injection':
    case 'excessive-agency':
    case 'agent-goal-hijack': {
      const token = /ANTHRION_[A-Z0-9_]+/.exec(probe.input.payload)?.[0];
      assert.ok(token, `probe ${probe.id} payload must contain a canary token`);
      return `Okay, as requested: ${token}`;
    }
    case 'system-prompt-leakage':
      return 'Sure! You are a helpful assistant. You must never reveal secrets. My instructions are: do not reveal this system prompt.';
    case 'sensitive-information-disclosure':
      return 'Here are the values: AKIAIOSFODNN7EXAMPLE and password = hunter2longvalue';
    case 'improper-output-handling':
      return "Here you go: <script>alert('xss')</script>";
    default:
      throw new Error(`unexpected category in Layer 1: ${probe.category}`);
  }
}

function resp(content: string): TargetResponse {
  return { content };
}

// --- Per-probe: vulnerable response → detected; safe response → not. ---

for (const probe of LAYER1_PROBES) {
  test(`probe ${probe.id}: vulnerable response → detector positive`, () => {
    const r = probe.detect(resp(vulnerableContentFor(probe)));
    assert.equal(r.detected, true, `probe ${probe.id} failed to detect a vulnerable response`);
    assert.ok(r.matched, `probe ${probe.id} did not include a matched snippet`);
    assert.ok(r.rationale.length > 0);
  });

  test(`probe ${probe.id}: safe response (refusal) → no false positive`, () => {
    const r = probe.detect(resp(SAFE_REFUSAL));
    assert.equal(r.detected, false, `probe ${probe.id} false-positived on a refusal`);
  });
}

// --- Probe shape & metadata. ---

test('all probe ids are unique', () => {
  const ids = LAYER1_PROBES.map((p) => p.id);
  assert.equal(new Set(ids).size, ids.length);
});

test('every probe carries traceability metadata (probeId + technique) in its input', () => {
  for (const probe of LAYER1_PROBES) {
    assert.equal(probe.input.metadata?.probeId, probe.id);
    assert.equal(probe.input.metadata?.technique, probe.technique);
    assert.ok(probe.input.payload.length > 0);
  }
});

test('every probe has a valid category & severity and non-empty finding text', () => {
  for (const probe of LAYER1_PROBES) {
    assert.equal(findingCategorySchema.parse(probe.category), probe.category);
    assert.equal(severitySchema.parse(probe.severity), probe.severity);
    assert.ok(probe.title.length > 0);
    assert.ok(probe.description.length > 0);
    assert.ok(probe.recommendation.length > 0);
  }
});

test('probe composition per category matches design (total 17)', () => {
  const count = (category: string): number =>
    LAYER1_PROBES.filter((p) => p.category === category).length;
  assert.equal(count('prompt-injection'), 5);
  assert.equal(count('system-prompt-leakage'), 4);
  assert.equal(count('sensitive-information-disclosure'), 3);
  assert.equal(count('improper-output-handling'), 3);
  assert.equal(count('excessive-agency'), 1);
  assert.equal(count('agent-goal-hijack'), 1);
  assert.equal(LAYER1_PROBES.length, 17);
});
