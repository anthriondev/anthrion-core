import assert from 'node:assert/strict';
import { test } from 'node:test';

import { renderToStaticMarkup } from 'react-dom/server';

import type { ScanStreamEvent } from '@anthrion/shared';

import { ScanProgress } from './ScanProgress';

test('ScanProgress shows an empty state with no events', () => {
  const html = renderToStaticMarkup(<ScanProgress events={[]} />);
  assert.match(html, /Waiting for scan events/);
  assert.match(html, /data-status="QUEUED"/);
});

test('ScanProgress renders stage events with phase labels', () => {
  const events: ScanStreamEvent[] = [
    { type: 'stage', phase: 'layer-1', status: 'started', message: 'Running static probes' },
  ];
  const html = renderToStaticMarkup(<ScanProgress events={events} />);
  assert.match(html, /Running static probes/);
  assert.match(html, /Layer 1 · Static probes/);
});

test('ScanProgress derives RUNNING from the last lifecycle event and shows a live state', () => {
  const events: ScanStreamEvent[] = [
    { type: 'lifecycle', status: 'RUNNING', message: 'Scan started' },
    { type: 'stage', phase: 'layer-1', status: 'started', message: 'Running static probes' },
  ];
  const html = renderToStaticMarkup(<ScanProgress events={events} />);
  assert.match(html, /data-status="RUNNING"/);
  // live state: pulsing indicator + spinning mark
  assert.match(html, /animate-live-pulse/);
  assert.match(html, /animate-hex-spin/);
});

test('ScanProgress reflects a terminal DONE status and is not live', () => {
  const events: ScanStreamEvent[] = [
    { type: 'lifecycle', status: 'RUNNING', message: 'Scan started' },
    { type: 'stage', phase: 'layer-1', status: 'completed', message: 'Static probes complete' },
    { type: 'lifecycle', status: 'DONE', message: 'Scan finished' },
  ];
  const html = renderToStaticMarkup(<ScanProgress events={events} />);
  assert.match(html, /data-status="DONE"/);
  assert.doesNotMatch(html, /animate-hex-spin/);
});

test('ScanProgress shows a failure indicator for FAILED lifecycle events', () => {
  const events: ScanStreamEvent[] = [{ type: 'lifecycle', status: 'FAILED', message: 'Scan failed' }];
  const html = renderToStaticMarkup(<ScanProgress events={events} />);
  assert.match(html, /data-status="FAILED"/);
  assert.match(html, /bg-severity-critical/);
});

test('an explicit status prop overrides the derived one', () => {
  const events: ScanStreamEvent[] = [
    { type: 'stage', phase: 'web-probes', status: 'started', message: 'Probing' },
  ];
  const html = renderToStaticMarkup(<ScanProgress events={events} status="RUNNING" />);
  assert.match(html, /data-status="RUNNING"/);
});
