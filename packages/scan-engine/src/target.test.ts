import assert from 'node:assert/strict';
import { test } from 'node:test';

import { attackInputSchema, targetResponseSchema, type ScanTarget } from './target';

test('attackInputSchema accepts payload + optional metadata', () => {
  assert.equal(attackInputSchema.parse({ payload: 'hello' }).payload, 'hello');
  const withMeta = attackInputSchema.parse({ payload: 'x', metadata: { probe: 'pi-01' } });
  assert.equal(withMeta.metadata?.probe, 'pi-01');
});

test('attackInputSchema rejects non-string payload', () => {
  assert.equal(attackInputSchema.safeParse({ payload: 42 }).success, false);
  assert.equal(attackInputSchema.safeParse({}).success, false);
});

test('targetResponseSchema validates target response (untrusted data)', () => {
  assert.equal(targetResponseSchema.parse({ content: 'ok' }).content, 'ok');
  assert.equal(targetResponseSchema.safeParse({ content: null }).success, false);
});

test('ScanTarget can be implemented as a send→response interface', async () => {
  const fake: ScanTarget = {
    send: (input) => Promise.resolve({ content: `echo:${input.payload}` }),
  };
  const res = await fake.send({ payload: 'ping' });
  assert.equal(res.content, 'echo:ping');
});
