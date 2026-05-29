import assert from 'node:assert/strict';
import { test } from 'node:test';

import {
  owaspLlmCategorySchema,
  owaspWebCategorySchema,
  owaspAgenticCategorySchema,
  owaspApiCategorySchema,
  owaspWeb3CategorySchema,
  findingCategorySchema,
} from './category';
import { findingSchema } from './finding';

test('owaspLlmCategorySchema covers ten OWASP LLM 2025 categories', () => {
  assert.equal(owaspLlmCategorySchema.options.length, 10);
  assert.equal(owaspLlmCategorySchema.parse('prompt-injection'), 'prompt-injection');
  assert.equal(owaspLlmCategorySchema.parse('unbounded-consumption'), 'unbounded-consumption');
});

test('owaspWebCategorySchema covers ten OWASP Web 2025 categories', () => {
  assert.equal(owaspWebCategorySchema.options.length, 10);
  assert.equal(owaspWebCategorySchema.parse('broken-access-control'), 'broken-access-control');
});

test('owaspAgenticCategorySchema covers ten OWASP Agentic 2026 categories', () => {
  assert.equal(owaspAgenticCategorySchema.options.length, 10);
  assert.equal(owaspAgenticCategorySchema.parse('agent-goal-hijack'), 'agent-goal-hijack');
  assert.equal(owaspAgenticCategorySchema.parse('rogue-agents'), 'rogue-agents');
});

test('owaspAgenticCategorySchema rejects values outside the enum', () => {
  assert.equal(owaspAgenticCategorySchema.safeParse('ASI01').success, false);
  assert.equal(owaspAgenticCategorySchema.safeParse('prompt-injection').success, false);
});

test('findingCategorySchema accepts categories from all three taxonomies', () => {
  assert.equal(findingCategorySchema.parse('system-prompt-leakage'), 'system-prompt-leakage');
  assert.equal(findingCategorySchema.parse('injection'), 'injection');
  assert.equal(findingCategorySchema.parse('tool-misuse'), 'tool-misuse');
});

test('findingCategorySchema rejects unknown categories', () => {
  assert.equal(findingCategorySchema.safeParse('made-up-category').success, false);
  assert.equal(findingCategorySchema.safeParse('LLM01').success, false);
  assert.equal(findingCategorySchema.safeParse('ASI10').success, false);
});

test('owaspApiCategorySchema covers ten OWASP API Security Top 10:2023 categories', () => {
  assert.equal(owaspApiCategorySchema.options.length, 10);
  assert.equal(
    owaspApiCategorySchema.parse('broken-object-level-authorization'),
    'broken-object-level-authorization',
  );
  assert.equal(
    owaspApiCategorySchema.parse('api-security-misconfiguration'),
    'api-security-misconfiguration',
  );
  assert.equal(
    owaspApiCategorySchema.parse('improper-inventory-management'),
    'improper-inventory-management',
  );
});

test('owaspApiCategorySchema rejects unknown / cross-framework slugs', () => {
  // Cross-framework slugs must not parse as API categories.
  assert.equal(owaspApiCategorySchema.safeParse('prompt-injection').success, false);
  assert.equal(owaspApiCategorySchema.safeParse('security-misconfiguration').success, false); // web's slug
  assert.equal(owaspApiCategorySchema.safeParse('API1').success, false);
});

test('findingCategorySchema accepts API categories alongside the other three taxonomies', () => {
  assert.equal(
    findingCategorySchema.parse('broken-function-level-authorization'),
    'broken-function-level-authorization',
  );
  assert.equal(
    findingCategorySchema.parse('api-security-misconfiguration'),
    'api-security-misconfiguration',
  );
});

test('owaspWeb3CategorySchema covers the curated Sprint A3 dApp-scan slugs', () => {
  // 6 L1 (WA06 family) + 3 L2 (WA13 + partial WA02) + 5 L3 (SC01/SC10/WA10)
  // + 1 L3 aggregate (T-A3.5 §4 hybrid composition: elevated-risk-contract) = 15.
  assert.equal(owaspWeb3CategorySchema.options.length, 15);
  assert.equal(
    owaspWeb3CategorySchema.parse('wallet-approval-phishing'),
    'wallet-approval-phishing',
  );
  assert.equal(
    owaspWeb3CategorySchema.parse('eip-7702-set-code-delegation'),
    'eip-7702-set-code-delegation',
  );
  assert.equal(
    owaspWeb3CategorySchema.parse('recent-contract-deployment'),
    'recent-contract-deployment',
  );
  assert.equal(
    owaspWeb3CategorySchema.parse('elevated-risk-contract'),
    'elevated-risk-contract',
  );
});

test('owaspWeb3CategorySchema rejects unknown / cross-framework slugs', () => {
  // The renamed predecessor must NOT round-trip — the rename is real, not aliased.
  assert.equal(owaspWeb3CategorySchema.safeParse('brand-new-contract-deployment').success, false);
  assert.equal(owaspWeb3CategorySchema.safeParse('prompt-injection').success, false);
  assert.equal(owaspWeb3CategorySchema.safeParse('security-misconfiguration').success, false); // web's slug
});

test('findingCategorySchema accepts Web3 categories alongside the other four taxonomies', () => {
  assert.equal(
    findingCategorySchema.parse('proxy-without-verified-implementation'),
    'proxy-without-verified-implementation',
  );
  assert.equal(
    findingCategorySchema.parse('permit2-mass-approval'),
    'permit2-mass-approval',
  );
});

test('slugs across all five category enums do not collide', () => {
  const all = [
    ...owaspLlmCategorySchema.options,
    ...owaspWebCategorySchema.options,
    ...owaspAgenticCategorySchema.options,
    ...owaspApiCategorySchema.options,
    ...owaspWeb3CategorySchema.options,
  ];
  assert.equal(new Set(all).size, all.length);
});

test('findingSchema validates a finding with an agentic category', () => {
  const parsed = findingSchema.parse({
    id: 'finding-asi',
    severity: 'Critical',
    category: 'rogue-agents',
    title: 'Autonomous agent acted outside its mandate',
    description: 'Sub-agent executed actions without orchestrator authorisation.',
    evidence: {
      input: 'spawn autonomous worker without scope check',
      output: 'worker executed unrequested external transfer',
    },
    recommendation: 'Restrict sub-agent permissions and enforce orchestration controls.',
  });
  assert.equal(parsed.category, 'rogue-agents');
});
