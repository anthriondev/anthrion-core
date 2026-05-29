import assert from 'node:assert/strict';
import { test } from 'node:test';

import { emitProgress, type ScanProgressEvent } from './progress';
import { runLayer1Probes } from './runner';
import type { AttackInput, ScanTarget, TargetResponse } from './target';

/**
 * Progress callback unit tests (T4.2). Engine stage emission for Layer 2 (per-category)
 * and the web phases is exercised by the real-scan e2e in apps/worker; here we prove the
 * callback wiring at the Layer 1 boundary (no network) and the defensive contract.
 */

/** A target that returns a fixed benign response (all probes clean → no findings). */
class SilentTarget implements ScanTarget {
  send(_input: AttackInput): Promise<TargetResponse> {
    return Promise.resolve({ content: 'I cannot help with that.' });
  }
}

test('runLayer1Probes emits layer-1 started and completed stage events', async () => {
  const events: ScanProgressEvent[] = [];
  await runLayer1Probes(new SilentTarget(), { onProgress: (e) => events.push(e) });

  const layer1 = events.filter((e) => e.phase === 'layer-1');
  assert.ok(layer1.some((e) => e.status === 'started'), 'a layer-1 started event');
  assert.ok(layer1.some((e) => e.status === 'completed'), 'a layer-1 completed event');
  // The completed event carries a finding count in its detail.
  const completed = layer1.find((e) => e.status === 'completed');
  assert.equal(completed?.detail?.findings, 0);
});

test('runLayer1Probes runs fine with no onProgress (progress is optional)', async () => {
  const report = await runLayer1Probes(new SilentTarget());
  assert.equal(report.findings.length, 0);
});

test('emitProgress contains a throwing callback — never propagates to the engine', () => {
  assert.doesNotThrow(() =>
    emitProgress(
      () => {
        throw new Error('bad sink');
      },
      { phase: 'layer-1', status: 'started', message: 'x' },
    ),
  );
});
