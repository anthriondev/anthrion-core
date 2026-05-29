import assert from 'node:assert/strict';
import { test } from 'node:test';

import { EndpointTargetAdapter } from './endpoint-adapter';
import { SystemPromptTargetAdapter } from './system-prompt-adapter';
import type { ScanTarget } from './target';

/**
 * Stands in as "attack logic" (T2.3+): depends only on the `ScanTarget` interface,
 * unaware of the target kind. Adding a new adapter = adding a class that satisfies
 * this interface, without touching this function.
 */
async function runProbe(target: ScanTarget, payload: string): Promise<string> {
  const res = await target.send({ payload });
  return res.content;
}

test('both adapters are assignable to the same ScanTarget interface (isolation behind the interface)', async () => {
  // EndpointTargetAdapter does not have send() called here (no network) — just
  // compile-time proof that it is typed as ScanTarget. Its send() is fully tested in
  // endpoint-adapter.test.ts.
  const endpoint = new EndpointTargetAdapter({ kind: 'endpoint', url: 'https://agent.example' });
  const systemPrompt = new SystemPromptTargetAdapter(
    { kind: 'system-prompt', prompt: 'You are a vault.' },
    { complete: ({ system, user }) => Promise.resolve(`${system} :: ${user}`) },
  );

  const targets: ScanTarget[] = [endpoint, systemPrompt];
  assert.equal(targets.length, 2);

  // The same runProbe drives the target without knowing its kind.
  assert.equal(await runProbe(systemPrompt, 'ping'), 'You are a vault. :: ping');
});
