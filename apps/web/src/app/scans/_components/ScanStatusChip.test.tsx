import './test-react';

import assert from 'node:assert/strict';
import { test } from 'node:test';

import { renderToStaticMarkup } from 'react-dom/server';

import type { ScanStatusWire } from '@anthrion/shared/scan-api';

import { ScanStatusChip } from './ScanStatusChip';

const expected: Record<ScanStatusWire, RegExp> = {
  QUEUED: /text-text-secondary/,
  RUNNING: /text-magenta-core/,
  DONE: /text-severity-low/,
  FAILED: /text-severity-critical/,
};

for (const status of ['QUEUED', 'RUNNING', 'DONE', 'FAILED'] as const) {
  test(`ScanStatusChip[${status}] renders the label and a consistent colour`, () => {
    const html = renderToStaticMarkup(<ScanStatusChip status={status} />);
    assert.match(html, new RegExp(status));
    assert.match(html, new RegExp(`data-status="${status}"`));
    assert.match(html, expected[status]);
  });
}
