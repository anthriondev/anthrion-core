import assert from 'node:assert/strict';
import { test } from 'node:test';

import { renderToStaticMarkup } from 'react-dom/server';

import { Card } from './Card';

test('Card uses surface background, trace border and 8px radius', () => {
  const html = renderToStaticMarkup(<Card>content</Card>);
  assert.match(html, /bg-surface/);
  assert.match(html, /border-trace/);
  assert.match(html, /rounded-card/);
  assert.match(html, /content/);
});

test('Card has no registration marks by default', () => {
  const html = renderToStaticMarkup(<Card>content</Card>);
  assert.doesNotMatch(html, /registration-marks/);
});

test('Card renders registration marks when requested', () => {
  const html = renderToStaticMarkup(<Card withMarks>content</Card>);
  assert.match(html, /registration-marks/);
});
