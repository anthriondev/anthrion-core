import assert from 'node:assert/strict';
import { test } from 'node:test';

import { renderToStaticMarkup } from 'react-dom/server';

import { Mark } from './Mark';

test('Mark renders an svg with the 48-unit viewBox', () => {
  const html = renderToStaticMarkup(<Mark />);
  assert.match(html, /<svg/);
  assert.match(html, /viewBox="0 0 48 48"/);
});

test('Mark is decorative (aria-hidden) without a title', () => {
  const html = renderToStaticMarkup(<Mark />);
  assert.match(html, /aria-hidden="true"/);
  assert.doesNotMatch(html, /role="img"/);
});

test('Mark becomes an accessible image when given a title', () => {
  const html = renderToStaticMarkup(<Mark title="ANTHRION" />);
  assert.match(html, /role="img"/);
  assert.match(html, /<title>ANTHRION<\/title>/);
  assert.match(html, /aria-label="ANTHRION"/);
});

test('Mark spins the inner hexagon only when spinning, respecting reduced motion', () => {
  const spinning = renderToStaticMarkup(<Mark spinning />);
  assert.match(spinning, /animate-hex-spin/);
  assert.match(spinning, /motion-reduce:animate-none/);

  const still = renderToStaticMarkup(<Mark />);
  assert.doesNotMatch(still, /animate-hex-spin/);
});
