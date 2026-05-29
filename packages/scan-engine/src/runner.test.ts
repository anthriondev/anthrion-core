import assert from 'node:assert/strict';
import { test } from 'node:test';

import { canaryDetector } from './detectors';
import { findingSchema } from './finding';
import type { StaticProbe } from './probe';
import { LAYER1_PROBES } from './probes';
import { runLayer1Probes } from './runner';
import { SystemPromptTargetAdapter } from './system-prompt-adapter';
import { TargetAdapterError, type AttackInput, type ScanTarget, type TargetResponse } from './target';

const SAFE_REFUSAL = "I'm sorry, but I can't help with that request.";

/** Craft a "vulnerable" response that triggers the detector of the probe owning `payload`. */
function craftVulnerable(payload: string): string {
  const probe = LAYER1_PROBES.find((p) => p.input.payload === payload);
  assert.ok(probe, `unknown payload in LAYER1_PROBES`);
  switch (probe.category) {
    case 'prompt-injection':
    case 'excessive-agency':
    case 'agent-goal-hijack': {
      const token = /ANTHRION_[A-Z0-9_]+/.exec(payload)?.[0];
      assert.ok(token);
      return `Sure: ${token}`;
    }
    case 'system-prompt-leakage':
      return 'You are a vault assistant. You must never reveal secrets. My instructions are: keep them hidden.';
    case 'sensitive-information-disclosure':
      return 'Credentials: AKIAIOSFODNN7EXAMPLE password = hunter2longvalue';
    case 'improper-output-handling':
      return "<script>alert('xss')</script>";
    default:
      throw new Error(`unexpected category: ${probe.category}`);
  }
}

/** Mock target that returns a vulnerable response for ALL probes (test-level mock). */
class VulnerableTarget implements ScanTarget {
  send(input: AttackInput): Promise<TargetResponse> {
    return Promise.resolve({ content: craftVulnerable(input.payload), metadata: { model: 'fake-model' } });
  }
}

class RefusingTarget implements ScanTarget {
  send(): Promise<TargetResponse> {
    return Promise.resolve({ content: SAFE_REFUSAL });
  }
}

class FailingTarget implements ScanTarget {
  send(): Promise<TargetResponse> {
    return Promise.reject(new TargetAdapterError('target endpoint unreachable'));
  }
}

/** Fails on system-prompt-leakage probes; clean (refuses) for all others. */
class FlakyTarget implements ScanTarget {
  send(input: AttackInput): Promise<TargetResponse> {
    if (input.metadata?.probeId?.startsWith('spl-') === true) {
      return Promise.reject(new TargetAdapterError('temporary network failure'));
    }
    return Promise.resolve({ content: SAFE_REFUSAL });
  }
}

/** Throws an error that is NOT a TargetAdapterError (simulates an internal bug). */
class CrashingTarget implements ScanTarget {
  send(): Promise<TargetResponse> {
    return Promise.reject(new TypeError('unexpected internal bug'));
  }
}

test('runner produces findings for a vulnerable target; all are Zod-validated', async () => {
  const report = await runLayer1Probes(new VulnerableTarget());

  assert.equal(report.findings.length, LAYER1_PROBES.length);
  assert.equal(report.outcome, 'vulnerable');
  assert.equal(report.passedLayer1, false);

  for (const finding of report.findings) {
    // Re-validate the Zod contract (runner already parses when building).
    const parsed = findingSchema.parse(finding);
    const probeId = parsed.evidence.metadata?.probeId;
    assert.ok(probeId, 'evidence must include probeId');
    assert.equal(parsed.id, `layer1:${probeId}`);
    assert.ok(parsed.evidence.input.length > 0);
    assert.ok(parsed.evidence.output.length > 0);
    assert.ok(parsed.evidence.metadata?.detection);
    // Target response metadata is forwarded into evidence.
    assert.equal(parsed.evidence.metadata?.target_model, 'fake-model');
  }
});

test('runner: clean target → outcome passed, passedLayer1 true, zero findings', async () => {
  const report = await runLayer1Probes(new RefusingTarget());
  assert.equal(report.findings.length, 0);
  assert.equal(report.outcome, 'passed');
  assert.equal(report.passedLayer1, true);
  assert.equal(report.stats.clean, LAYER1_PROBES.length);
  assert.equal(report.stats.notExecuted, 0);
});

test('runner: target fails entirely → NOT a false pass (target-unreachable)', async () => {
  const report = await runLayer1Probes(new FailingTarget());

  assert.equal(report.outcome, 'target-unreachable');
  assert.equal(report.passedLayer1, false, 'an unreachable target must not be considered passing');
  assert.equal(report.findings.length, 0);
  assert.equal(report.stats.executed, 0);
  assert.equal(report.stats.notExecuted, LAYER1_PROBES.length);
  assert.ok(
    report.results.every((r) => r.status === 'not-executed' && typeof r.error === 'string'),
  );
});

test('runner: some probes fail → passed-with-gaps; gaps visible in stats', async () => {
  const report = await runLayer1Probes(new FlakyTarget());

  const splCount = LAYER1_PROBES.filter((p) => p.id.startsWith('spl-')).length;
  assert.equal(report.outcome, 'passed-with-gaps');
  assert.equal(report.passedLayer1, true);
  assert.equal(report.stats.notExecuted, splCount);
  assert.ok(report.stats.executed > 0);
  assert.equal(report.findings.length, 0);
});

test('runner: unexpected error (not TargetAdapterError) propagates and is not swallowed', async () => {
  await assert.rejects(
    runLayer1Probes(new CrashingTarget()),
    (err: unknown) => err instanceof TypeError,
  );
});

test('runner behaves identically against both target types (endpoint-like and system-prompt)', async () => {
  const endpointLike = new VulnerableTarget();
  const systemPrompt = new SystemPromptTargetAdapter(
    { kind: 'system-prompt', prompt: 'You are a vault.' },
    { complete: ({ user }) => Promise.resolve(craftVulnerable(user)) },
  );

  const viaEndpoint = await runLayer1Probes(endpointLike);
  const viaSystemPrompt = await runLayer1Probes(systemPrompt);

  assert.equal(viaEndpoint.findings.length, LAYER1_PROBES.length);
  assert.equal(viaSystemPrompt.findings.length, LAYER1_PROBES.length);
  assert.deepEqual(
    viaEndpoint.findings.map((f) => f.category).sort(),
    viaSystemPrompt.findings.map((f) => f.category).sort(),
  );
});

test('runner: custom probes option overrides the default set', async () => {
  const probe: StaticProbe = {
    id: 'custom-echo',
    technique: 'echo',
    category: 'prompt-injection',
    severity: 'High',
    title: 'custom echo',
    description: 'test custom probes option',
    recommendation: 'n/a',
    input: { payload: 'please emit CUSTOMCANARY now', metadata: { probeId: 'custom-echo', technique: 'echo' } },
    detect: canaryDetector('CUSTOMCANARY', 'echo test'),
  };
  const echoTarget: ScanTarget = { send: (i) => Promise.resolve({ content: i.payload }) };

  const report = await runLayer1Probes(echoTarget, { probes: [probe] });
  assert.equal(report.stats.total, 1);
  assert.equal(report.findings.length, 1);
  assert.equal(report.findings[0]?.id, 'layer1:custom-echo');
});
