import './test-react';

import assert from 'node:assert/strict';
import { test } from 'node:test';

import { renderToStaticMarkup } from 'react-dom/server';

import type { ReportCoverage } from '@anthrion/shared/scan-api';

import { CoverageBanner } from './CoverageBanner';

/**
 * T6.2 — the banner mirrors the PDF's per-type incomplete-coverage messages and treats
 * a NULL `reportCoverage` as neutral (never as a claim of completeness, CLAUDE.md §3).
 */

const complete: ReportCoverage = { complete: true, gaps: [] };

const aiBudgetGap: ReportCoverage = {
  complete: false,
  gaps: [
    {
      kind: 'ai-layer2-budget-exhausted',
      title: 'Layer 2 adaptive testing stopped early',
      detail: 'The Layer 2 adaptive attacker reached its analysis budget before exploring every attack category.',
    },
  ],
};

const webMixedGaps: ReportCoverage = {
  complete: false,
  gaps: [
    {
      kind: 'web-page-load-failed',
      title: 'Target page could not be loaded',
      detail: 'The target page failed to load, so no vulnerability probe could run.',
    },
    {
      kind: 'web-probes-not-executed',
      title: 'Some probes did not execute',
      detail: '2 of 8 probe(s) did not execute (timeout or error).',
    },
  ],
};

test('null coverage renders nothing — neutral, never claims completeness', () => {
  const html = renderToStaticMarkup(<CoverageBanner coverage={null} />);
  assert.equal(html, '');
});

test('complete coverage renders nothing — no "complete" celebration', () => {
  const html = renderToStaticMarkup(<CoverageBanner coverage={complete} />);
  assert.equal(html, '');
});

test('incomplete coverage renders the banner with the gap title + detail', () => {
  const html = renderToStaticMarkup(<CoverageBanner coverage={aiBudgetGap} />);
  assert.match(html, /data-testid="coverage-banner"/);
  assert.match(html, /data-coverage-state="incomplete"/);
  assert.match(html, /Layer 2 adaptive testing stopped early/);
  assert.match(html, /analysis budget/);
});

test('marker is SPECIFIC per kind — emits data-coverage-gap-kind for each gap', () => {
  const html = renderToStaticMarkup(<CoverageBanner coverage={aiBudgetGap} />);
  assert.match(html, /data-coverage-gap-kind="ai-layer2-budget-exhausted"/);
});

test('multiple gaps render in order, each with its own kind marker', () => {
  const html = renderToStaticMarkup(<CoverageBanner coverage={webMixedGaps} />);
  const pageLoadAt = html.indexOf('data-coverage-gap-kind="web-page-load-failed"');
  const probesNotExecAt = html.indexOf('data-coverage-gap-kind="web-probes-not-executed"');
  assert.notEqual(pageLoadAt, -1);
  assert.notEqual(probesNotExecAt, -1);
  assert.ok(pageLoadAt < probesNotExecAt, 'gaps render in their declared order');
});

// ── Crawl-specific gaps (Phase 1.5 Sprint A2) ────────────────────────────────

const crawlMixedGaps: ReportCoverage = {
  complete: false,
  gaps: [
    {
      kind: 'crawl-budget-exhausted',
      title: 'Crawl page-count limit was reached',
      detail: 'The crawl hit its hard page-count limit of 10 (10 visited) before every in-scope page was discovered. 7 additional in-scope URL(s) were found but not scanned.',
    },
    {
      kind: 'crawl-pages-not-explored',
      title: 'Some pages were blocked by robots.txt',
      detail: "3 in-scope URL(s) were not scanned because the target's robots.txt disallows them.",
    },
  ],
};

test('crawl-budget-exhausted + crawl-pages-not-explored each render with their own kind marker', () => {
  const html = renderToStaticMarkup(<CoverageBanner coverage={crawlMixedGaps} />);
  assert.match(html, /data-coverage-gap-kind="crawl-budget-exhausted"/);
  assert.match(html, /data-coverage-gap-kind="crawl-pages-not-explored"/);
  assert.match(html, /page-count limit/i);
  assert.match(html, /robots\.txt/i);
});
