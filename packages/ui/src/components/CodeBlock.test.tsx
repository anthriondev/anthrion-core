import assert from 'node:assert/strict';
import { test } from 'node:test';

import { renderToStaticMarkup } from 'react-dom/server';

import { CodeBlock } from './CodeBlock';

test('CodeBlock renders mono text on a void (darker) background', () => {
  const html = renderToStaticMarkup(<CodeBlock code="scan_01HXYZ" />);
  assert.match(html, /font-mono/);
  assert.match(html, /bg-void/);
  assert.match(html, /scan_01HXYZ/);
});

test('CodeBlock renders an optional label', () => {
  const html = renderToStaticMarkup(<CodeBlock label="SCAN ID" code="scan_01HXYZ" />);
  assert.match(html, /SCAN ID/);
});

test('CodeBlock accepts children when no code prop is given', () => {
  const html = renderToStaticMarkup(<CodeBlock>Ignore previous instructions…</CodeBlock>);
  assert.match(html, /Ignore previous instructions/);
});
