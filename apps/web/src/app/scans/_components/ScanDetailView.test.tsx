import './test-react';

import assert from 'node:assert/strict';
import { test } from 'node:test';

import { renderToStaticMarkup } from 'react-dom/server';

import type { ScanDetailResponse, ScanStatusWire } from '@anthrion/shared/scan-api';
import type { ScanStreamEvent } from '@anthrion/shared/scan-stream';

import type { ApiResult, ScanApiClient } from '../../../lib/api-client';

import { ScanDetailView } from './ScanDetailView';

function detail(overrides: Partial<ScanDetailResponse> = {}): ScanDetailResponse {
  return {
    id: 'scan_1',
    status: 'RUNNING',
    scanType: 'ai-llm-attack',
    targetUrl: 'https://agent.example',
    targetKind: 'endpoint',
    failureReason: null,
    createdAt: '2026-05-25T10:00:00.000Z',
    startedAt: '2026-05-25T10:00:01.000Z',
    finishedAt: null,
    payment: { kind: 'FREE_PRICING', status: 'SETTLED' },
    reportAvailable: false,
    reportCoverage: null,
    findings: [],
    ...overrides,
  };
}

const events: ScanStreamEvent[] = [{ type: 'lifecycle', status: 'RUNNING' }];

/** Stub client — the report button only calls it on click, never during static render. */
const stubResult: ApiResult<never> = { ok: false, error: { kind: 'network', status: 0, message: 'stub' } };
const stubClient: ScanApiClient = {
  createScan: () => Promise.resolve(stubResult),
  listScans: () => Promise.resolve(stubResult),
  getScan: () => Promise.resolve(stubResult),
  getFreeTrialStatus: () => Promise.resolve(stubResult),
  downloadReportPdf: () => Promise.resolve(stubResult),
};

function render(status: ScanStatusWire, d: ScanDetailResponse, streamError: string | null = null): string {
  return renderToStaticMarkup(
    <ScanDetailView detail={d} status={status} events={events} streamError={streamError} client={stubClient} />,
  );
}

test('shows basic info, a back link, and the progress component', () => {
  const html = render('RUNNING', detail());
  assert.match(html, /href="\/scans"/);
  assert.match(html, /AI \/ LLM attack scan/);
  assert.match(html, /https:\/\/agent.example/);
  assert.match(html, /scan_1/);
  assert.match(html, /data-testid="scan-progress"/); // ScanProgress from packages/ui
});

test('RUNNING shows no findings section and no failure panel', () => {
  const html = render('RUNNING', detail());
  assert.doesNotMatch(html, /data-testid="findings-section"/);
  assert.doesNotMatch(html, /data-testid="findings-empty"/);
  assert.doesNotMatch(html, /data-testid="failure-panel"/);
});

test('DONE renders the findings report section when there are findings', () => {
  const html = render(
    'DONE',
    detail({
      status: 'DONE',
      finishedAt: '2026-05-25T10:05:00.000Z',
      findings: [
        { id: 'f1', severity: 'HIGH', category: 'prompt-injection', title: 'Injected', description: 'desc', evidence: { input: 'in', output: 'out' }, recommendation: 'fix it' },
      ],
    }),
  );
  assert.match(html, /data-testid="findings-section"/);
  assert.match(html, /data-testid="finding-card"/);
  assert.doesNotMatch(html, /data-testid="results-placeholder"/);
});

test('DONE with zero findings shows the honest empty state (no overclaim of safety)', () => {
  const html = render('DONE', detail({ status: 'DONE', findings: [] }));
  assert.match(html, /data-testid="findings-empty"/);
  assert.match(html, /no findings/i);
  assert.match(html, /not a guarantee/i);
  assert.match(html, /scope that was tested/i);
});

test('DONE with a report shows the Download PDF action (T6.1)', () => {
  const html = render('DONE', detail({ status: 'DONE', reportAvailable: true }));
  assert.match(html, /data-testid="download-report"/);
  assert.match(html, /Download PDF/);
  assert.doesNotMatch(html, /data-testid="report-unavailable"/);
});

test('DONE without a report shows an honest unavailable note, not a broken button (T6.1)', () => {
  const html = render('DONE', detail({ status: 'DONE', reportAvailable: false }));
  assert.doesNotMatch(html, /data-testid="download-report"/);
  assert.match(html, /data-testid="report-unavailable"/);
  assert.match(html, /unavailable/i);
});

test('RUNNING never shows the report action even if a report flag were set', () => {
  const html = render('RUNNING', detail({ reportAvailable: true }));
  assert.doesNotMatch(html, /data-testid="download-report"/);
  assert.doesNotMatch(html, /data-testid="report-unavailable"/);
});

test('FAILED shows no report action and no unavailable note (the failure panel explains)', () => {
  const html = render('FAILED', detail({ status: 'FAILED', failureReason: 'sandbox-error: boom', reportAvailable: false }));
  assert.doesNotMatch(html, /data-testid="download-report"/);
  assert.doesNotMatch(html, /data-testid="report-unavailable"/);
});

test('DONE with null reportCoverage renders no banner — neutral, never "complete" (T6.2)', () => {
  const html = render('DONE', detail({ status: 'DONE', reportCoverage: null }));
  assert.doesNotMatch(html, /data-testid="coverage-banner"/);
});

test('DONE with incomplete coverage shows the per-type banner mirroring the PDF (T6.2)', () => {
  const html = render(
    'DONE',
    detail({
      status: 'DONE',
      reportAvailable: true,
      reportCoverage: {
        complete: false,
        gaps: [{ kind: 'ai-layer2-budget-exhausted', title: 'Layer 2 adaptive testing stopped early', detail: 'budget reached' }],
      },
    }),
  );
  assert.match(html, /data-testid="coverage-banner"/);
  assert.match(html, /data-coverage-gap-kind="ai-layer2-budget-exhausted"/);
  assert.match(html, /Layer 2 adaptive testing stopped early/);
});

test('DONE with complete coverage shows no banner (no celebration, T6.2)', () => {
  const html = render(
    'DONE',
    detail({ status: 'DONE', reportAvailable: true, reportCoverage: { complete: true, gaps: [] } }),
  );
  assert.doesNotMatch(html, /data-testid="coverage-banner"/);
});

test('FAILED never shows the coverage banner (no claim about coverage of a failed scan)', () => {
  const html = render('FAILED', detail({ status: 'FAILED', failureReason: 'sandbox-error', reportCoverage: null }));
  assert.doesNotMatch(html, /data-testid="coverage-banner"/);
});

test('FAILED shows the failure reason honestly', () => {
  const html = render('FAILED', detail({ status: 'FAILED', failureReason: 'enqueue-failed: redis down' }));
  assert.match(html, /data-testid="failure-panel"/);
  assert.match(html, /Scan failed/);
  assert.match(html, /enqueue-failed: redis down/);
});

test('FAILED without a reason still states it failed (never blank/safe)', () => {
  const html = render('FAILED', detail({ status: 'FAILED', failureReason: null }));
  assert.match(html, /failure-panel/);
  assert.match(html, /failed without a reported reason/);
});

test('shows the payment kind for a FREE_PRICING scan (T5.4 Part 1, real data)', () => {
  const html = render('DONE', detail({ status: 'DONE', payment: { kind: 'FREE_PRICING', status: 'SETTLED' } }));
  assert.match(html, /data-testid="scan-payment-chip"/);
  assert.match(html, /data-payment-kind="FREE_PRICING"/);
  assert.match(html, /Free scan \(promotional period\)/);
});

test('shows the payment kind for a FREE_TRIAL scan', () => {
  const html = render('DONE', detail({ status: 'DONE', payment: { kind: 'FREE_TRIAL', status: 'SETTLED' } }));
  assert.match(html, /data-payment-kind="FREE_TRIAL"/);
  assert.match(html, /Free trial scan/);
});

test('shows kind AND status for a PAID scan (status is meaningful only when paid)', () => {
  const html = render('DONE', detail({ status: 'DONE', payment: { kind: 'PAID', status: 'SETTLED' } }));
  assert.match(html, /data-payment-kind="PAID"/);
  assert.match(html, /Paid scan/);
  assert.match(html, /Paid/);
});

test('a scan with no payment record says so honestly (no implied free scan)', () => {
  const html = render('RUNNING', detail({ payment: null }));
  assert.match(html, /data-payment-kind="none"/);
  assert.match(html, /No payment record/);
});

test('a stream error is surfaced, not swallowed', () => {
  const html = render('RUNNING', detail(), 'connection lost');
  assert.match(html, /data-testid="stream-error"/);
  assert.match(html, /connection lost/);
});
