import './test-react';

import assert from 'node:assert/strict';
import { test } from 'node:test';

import { renderToStaticMarkup } from 'react-dom/server';

import type { ScanSummaryResponse } from '@anthrion/shared/scan-api';

import { ScanList } from './ScanList';

const sampleScans: ScanSummaryResponse[] = [
  { id: 's1', status: 'RUNNING', scanType: 'ai-llm-attack', targetUrl: 'https://agent.example', createdAt: '2026-05-25T10:00:00.000Z', finishedAt: null },
  { id: 's2', status: 'DONE', scanType: 'web-app-vuln', targetUrl: 'https://site.example', createdAt: '2026-05-24T09:00:00.000Z', finishedAt: '2026-05-24T09:05:00.000Z' },
];

test('ScanList shows a loading state', () => {
  const html = renderToStaticMarkup(<ScanList state={{ kind: 'loading' }} />);
  assert.match(html, /Loading scans/);
});

test('ScanList shows an error state with the message', () => {
  const html = renderToStaticMarkup(<ScanList state={{ kind: 'error', message: 'network down' }} />);
  assert.match(html, /data-testid="list-error"/);
  assert.match(html, /network down/);
});

test('ScanList shows a friendly empty state with a create CTA', () => {
  const html = renderToStaticMarkup(<ScanList state={{ kind: 'ready', scans: [] }} />);
  assert.match(html, /data-testid="list-empty"/);
  assert.match(html, /No scans yet/);
  assert.match(html, /href="\/scans\/new"/);
});

test('ScanList renders a row per scan, each linking to its detail page', () => {
  const html = renderToStaticMarkup(<ScanList state={{ kind: 'ready', scans: sampleScans }} />);
  assert.match(html, /href="\/scans\/s1"/);
  assert.match(html, /href="\/scans\/s2"/);
  assert.match(html, /AI \/ LLM attack scan/);
  assert.match(html, /Web app vulnerability scan/);
  assert.match(html, /data-status="RUNNING"/);
  assert.match(html, /data-status="DONE"/);
  // status indicator only — no finding severity Badge on the list (that is T4.4)
  assert.doesNotMatch(html, /data-severity=/);
});
