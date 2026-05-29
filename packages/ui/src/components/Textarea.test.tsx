import assert from 'node:assert/strict';
import { test } from 'node:test';

import { renderToStaticMarkup } from 'react-dom/server';

import { Textarea } from './Textarea';

test('Textarea uses surface background, trace border and magenta focus (not a glow)', () => {
  const html = renderToStaticMarkup(<Textarea placeholder="Paste prompt…" />);
  assert.match(html, /<textarea/);
  assert.match(html, /bg-surface/);
  assert.match(html, /border-trace/);
  assert.match(html, /focus:border-magenta-core/);
  assert.doesNotMatch(html, /shadow/);
});

test('Textarea forwards rows and value', () => {
  const html = renderToStaticMarkup(<Textarea rows={6} defaultValue="hello" />);
  assert.match(html, /rows="6"/);
  assert.match(html, /hello/);
});
