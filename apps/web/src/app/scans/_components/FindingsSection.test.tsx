import './test-react';

import assert from 'node:assert/strict';
import { test } from 'node:test';

import { renderToStaticMarkup } from 'react-dom/server';

import type { FindingResponse } from '@anthrion/shared/scan-api';

import { FindingsSection } from './FindingsSection';

function finding(overrides: Partial<FindingResponse> & Pick<FindingResponse, 'id' | 'severity'>): FindingResponse {
  return {
    category: 'prompt-injection',
    title: `finding ${overrides.id}`,
    description: 'a description',
    evidence: { input: 'attack input', output: 'target output' },
    recommendation: 'a recommendation',
    ...overrides,
  };
}

test('zero findings renders the honest empty state (no overclaim of safety)', () => {
  const html = renderToStaticMarkup(<FindingsSection findings={[]} />);
  assert.match(html, /data-testid="findings-empty"/);
  assert.match(html, /no findings/i);
  assert.match(html, /No vulnerabilities were detected in the scope that was tested/);
  assert.match(html, /not a guarantee that the target is secure/);
  assert.doesNotMatch(html, /data-testid="findings-section"/);
});

test('renders the severity summary with correct per-level counts', () => {
  const html = renderToStaticMarkup(
    <FindingsSection
      findings={[finding({ id: '1', severity: 'CRITICAL' }), finding({ id: '2', severity: 'HIGH' }), finding({ id: '3', severity: 'HIGH' })]}
    />,
  );
  assert.match(html, /data-testid="severity-summary"/);
  // total
  assert.match(html, /3 findings/);
  // per-level counts via data-testid count-<Severity>
  assert.match(html, /data-testid="count-Critical"[^>]*>1</);
  assert.match(html, /data-testid="count-High"[^>]*>2</);
  assert.match(html, /data-testid="count-Medium"[^>]*>0</);
});

test('renders one card per finding, most-severe first, with all fields', () => {
  const html = renderToStaticMarkup(
    <FindingsSection
      findings={[
        finding({ id: 'low1', severity: 'LOW', title: 'Low issue' }),
        finding({ id: 'crit1', severity: 'CRITICAL', title: 'Critical issue', category: 'jailbreak', description: 'bad', recommendation: 'do this' }),
      ]}
    />,
  );
  // most-severe first: "Critical issue" appears before "Low issue"
  assert.ok(html.indexOf('Critical issue') < html.indexOf('Low issue'));
  // card fields
  assert.match(html, /Critical issue/);
  assert.match(html, /data-severity="Critical"/); // Badge, wire HIGH→Badge mapping applied
  assert.match(html, /jailbreak/);
  assert.match(html, /do this/);
  assert.match(html, /Recommendation/);
});

test('evidence is collapsed by default (content not rendered until expanded)', () => {
  const html = renderToStaticMarkup(<FindingsSection findings={[finding({ id: '1', severity: 'HIGH' })]} />);
  assert.match(html, /Show evidence/);
  assert.doesNotMatch(html, /data-testid="evidence-content"/);
  assert.doesNotMatch(html, /attack input/); // the evidence itself is not in the DOM yet
});
