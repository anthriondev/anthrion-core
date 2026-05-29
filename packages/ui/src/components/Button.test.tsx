import assert from 'node:assert/strict';
import { test } from 'node:test';

import { renderToStaticMarkup } from 'react-dom/server';

import { Button, buttonClassName } from './Button';

test('Button renders its label inside a button element', () => {
  const html = renderToStaticMarkup(<Button>Run scan</Button>);
  assert.match(html, /<button/);
  assert.match(html, /Run scan/);
});

test('Button defaults to type=button and 8px (card) radius', () => {
  const html = renderToStaticMarkup(<Button>Go</Button>);
  assert.match(html, /type="button"/);
  assert.match(html, /rounded-card/);
});

test('primary variant fills magenta with dark text', () => {
  const html = renderToStaticMarkup(<Button variant="primary">Go</Button>);
  assert.match(html, /bg-magenta-core/);
  assert.match(html, /text-void/);
});

test('secondary variant is an outline in trace, no magenta fill', () => {
  const html = renderToStaticMarkup(<Button variant="secondary">Go</Button>);
  assert.match(html, /border-trace/);
  assert.doesNotMatch(html, /bg-magenta-core/);
});

test('ghost variant has neither magenta fill nor trace border', () => {
  const html = renderToStaticMarkup(<Button variant="ghost">Go</Button>);
  assert.doesNotMatch(html, /bg-magenta-core/);
  assert.doesNotMatch(html, /border-trace/);
});

test('forwards native button attributes (disabled)', () => {
  const html = renderToStaticMarkup(<Button disabled>Go</Button>);
  assert.match(html, /disabled/);
});

test('buttonClassName exposes the same variant classes (for link-as-button)', () => {
  const primary = buttonClassName({ variant: 'primary' });
  assert.match(primary, /bg-magenta-core/);
  assert.match(primary, /rounded-card/);
  const secondary = buttonClassName({ variant: 'secondary', size: 'sm' });
  assert.match(secondary, /border-trace/);
  assert.doesNotMatch(secondary, /bg-magenta-core/);
});
