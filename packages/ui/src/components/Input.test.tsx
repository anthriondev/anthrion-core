import assert from 'node:assert/strict';
import { test } from 'node:test';

import { renderToStaticMarkup } from 'react-dom/server';

import { Field, Input } from './Input';

test('Input uses surface background and trace border', () => {
  const html = renderToStaticMarkup(<Input placeholder="https://agent.example" />);
  assert.match(html, /bg-surface/);
  assert.match(html, /border-trace/);
  assert.match(html, /placeholder="https:\/\/agent.example"/);
});

test('Input focus changes the border to magenta-core (not a glow)', () => {
  const html = renderToStaticMarkup(<Input />);
  assert.match(html, /focus:border-magenta-core/);
  assert.doesNotMatch(html, /shadow/);
});

test('Field renders its label', () => {
  const html = renderToStaticMarkup(
    <Field label="Target URL" htmlFor="url">
      <Input id="url" />
    </Field>,
  );
  assert.match(html, /Target URL/);
  assert.match(html, /<label/);
});

test('Field shows a hint, or an error in magenta when present', () => {
  const withHint = renderToStaticMarkup(
    <Field label="URL" hint="Public endpoint">
      <Input />
    </Field>,
  );
  assert.match(withHint, /Public endpoint/);

  const withError = renderToStaticMarkup(
    <Field label="URL" hint="Public endpoint" error="Required">
      <Input />
    </Field>,
  );
  assert.match(withError, /Required/);
  assert.match(withError, /text-magenta-core/);
  assert.doesNotMatch(withError, /Public endpoint/);
});
