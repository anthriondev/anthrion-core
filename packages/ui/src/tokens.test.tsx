import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { test } from 'node:test';
import { fileURLToPath } from 'node:url';

import anthrionPreset from './tailwind-preset';
import { colors } from './tokens';

test('tokens.css stays in sync with tokens.ts colours (single source)', () => {
  const cssPath = fileURLToPath(new URL('./styles/tokens.css', import.meta.url));
  const css = readFileSync(cssPath, 'utf8');

  // Every token colour is declared with the same hex value.
  for (const [name, hex] of Object.entries(colors)) {
    const match = css.match(new RegExp(`--color-${name}\\s*:\\s*(#[0-9a-fA-F]{3,8})`));
    const value = match?.[1];
    assert.ok(value, `tokens.css is missing --color-${name}`);
    assert.equal(value.toLowerCase(), hex.toLowerCase());
  }

  // No stray --color-* variables beyond the token set.
  const declared = [...css.matchAll(/--color-([a-z-]+)\s*:/g)].map((m) => m[1]);
  assert.deepEqual(declared.sort(), Object.keys(colors).sort());
});

test('Tailwind preset exposes the brand, text and severity colours', () => {
  const extend = anthrionPreset.theme?.extend;
  assert.ok(extend, 'preset defines theme.extend');

  const themeColors = extend.colors;
  assert.ok(themeColors);
  assert.equal(typeof themeColors, 'object');
  assert.ok('magenta-core' in themeColors);
  assert.ok('void' in themeColors);
  assert.ok('text' in themeColors);
  assert.ok('severity' in themeColors);
});

test('Tailwind preset exposes the type scale, radius and motion tokens', () => {
  const extend = anthrionPreset.theme?.extend;
  assert.ok(extend);

  const fontSize = extend.fontSize;
  assert.ok(fontSize);
  assert.equal(typeof fontSize, 'object');
  assert.ok('display' in fontSize);
  assert.ok('caption' in fontSize);

  const borderRadius = extend.borderRadius;
  assert.ok(borderRadius);
  assert.equal(typeof borderRadius, 'object');
  assert.ok('card' in borderRadius);
  assert.ok('panel' in borderRadius);

  const duration = extend.transitionDuration;
  assert.ok(duration);
  assert.equal(typeof duration, 'object');
  assert.ok('fast' in duration);
});
