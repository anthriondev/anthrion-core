import assert from 'node:assert/strict';
import { test } from 'node:test';

import { renderToStaticMarkup } from 'react-dom/server';

import { SEVERITIES } from '../severity';

import { Badge } from './Badge';

const expectedClass: Record<(typeof SEVERITIES)[number], string> = {
  Critical: 'text-severity-critical',
  High: 'text-severity-high',
  Medium: 'text-severity-medium',
  Low: 'text-severity-low',
  Info: 'text-severity-info',
};

for (const severity of SEVERITIES) {
  test(`Badge[${severity}] renders its label and the correct semantic colour`, () => {
    const html = renderToStaticMarkup(<Badge severity={severity} />);
    assert.match(html, new RegExp(severity));
    assert.match(html, new RegExp(`data-severity="${severity}"`));
    assert.match(html, new RegExp(expectedClass[severity]));
  });
}

test('Badge is a mono uppercase chip', () => {
  const html = renderToStaticMarkup(<Badge severity="High" />);
  assert.match(html, /font-mono/);
  assert.match(html, /uppercase/);
});
