import assert from 'node:assert/strict';
import { test } from 'node:test';

import type { ReactElement, ReactNode } from 'react';

import { Wordmark } from './_components/Wordmark';

/**
 * Render-contract test for the landing-page brand markup (post mobile-broken-
 * render incident).
 *
 * The mobile-broken-render bug surfaced as: white background, serif font, plain
 * black wordmark, "INITIALIZING" forever. The root cause was operational (pm2
 * serving a stale chunk manifest after a build) — the source markup was correct.
 *
 * This test locks the SOURCE-SIDE brand contract so a future code regression
 * (someone deletes the magenta span, retypes the wordmark, drops the tagline)
 * is caught at unit-test time and is never confused with the operational
 * chunk-drift class again. Chunk-drift is an operational concern; the deploy
 * notes (and the carry-forward list) own that, not this test.
 *
 * Targets `Wordmark` directly — the same component `page.tsx` renders — so this
 * file does not transitively import the Privy SDK and stays a fast pure-React
 * unit test.
 */

function isElement(node: unknown): node is ReactElement<{ children?: ReactNode }> {
  return (
    typeof node === 'object' &&
    node !== null &&
    'type' in node &&
    'props' in node
  );
}

function findFirst(
  root: ReactNode,
  predicate: (el: ReactElement<{ children?: ReactNode }>) => boolean,
): ReactElement<{ children?: ReactNode }> | undefined {
  if (Array.isArray(root)) {
    for (const child of root) {
      const hit = findFirst(child, predicate);
      if (hit !== undefined) return hit;
    }
    return undefined;
  }
  if (!isElement(root)) return undefined;
  if (predicate(root)) return root;
  return findFirst(root.props.children, predicate);
}

function flattenText(root: ReactNode): string {
  if (root === null || root === undefined || root === false || root === true) return '';
  if (typeof root === 'string' || typeof root === 'number') return String(root);
  if (Array.isArray(root)) return root.map(flattenText).join('');
  if (isElement(root)) return flattenText(root.props.children);
  return '';
}

test('Wordmark renders the ANTHRION brand with a magenta "ION" span', () => {
  const tree = Wordmark();
  const h1 = findFirst(tree, (el) => el.type === 'h1');
  assert.ok(h1, 'expected an <h1> in Wordmark');

  // Text content must read ANTHRION (the "ANTHR" literal + the <span>"ION" child).
  assert.equal(flattenText(h1), 'ANTHRION');

  // The "ION" span carries the magenta brand colour — locks the visual identity
  // the chunk-drift incident appeared (incorrectly) to break.
  const span = findFirst(h1, (el) => el.type === 'span');
  assert.ok(span, 'expected a <span> inside the <h1> for the brand split');
  assert.equal(flattenText(span), 'ION');
  const style = (span.props as { style?: { color?: string } }).style;
  assert.ok(
    typeof style?.color === 'string' && /var\(--color-magenta-core\)/.test(style.color),
    `expected magenta-core var on the ION span, got ${JSON.stringify(style)}`,
  );
});

test('Wordmark renders the brand tagline GUIDING SYSTEMS, SAFELY', () => {
  const tree = Wordmark();
  const tagline = findFirst(
    tree,
    (el) => el.type === 'p' && flattenText(el) === 'GUIDING SYSTEMS, SAFELY',
  );
  assert.ok(tagline, 'expected the tagline paragraph in Wordmark');
});
