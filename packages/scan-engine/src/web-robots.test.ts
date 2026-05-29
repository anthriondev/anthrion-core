import assert from 'node:assert/strict';
import { test } from 'node:test';

import { RobotsTxt } from './web-robots';

/**
 * Unit tests for the minimal robots.txt parser (T-A2.2). HTTP fetching is exercised
 * end-to-end by the crawl tests; here we only test the rule logic.
 */

test('empty robots.txt → permissive (everything allowed)', () => {
  const r = RobotsTxt.parse('');
  assert.equal(r.ruleCount, 0);
  assert.equal(r.isAllowed('/'), true);
  assert.equal(r.isAllowed('/anything'), true);
});

test('Disallow: / blocks everything under root', () => {
  const r = RobotsTxt.parse('User-agent: *\nDisallow: /\n');
  assert.equal(r.isAllowed('/'), false);
  assert.equal(r.isAllowed('/foo'), false);
  assert.equal(r.isAllowed('/a/b/c'), false);
});

test('Disallow with empty value is a no-op (spec: "Disallow:" means nothing disallowed)', () => {
  const r = RobotsTxt.parse('User-agent: *\nDisallow:\n');
  assert.equal(r.ruleCount, 0);
  assert.equal(r.isAllowed('/anything'), true);
});

test('Allow overrides Disallow when its pattern is longer (longest match wins)', () => {
  const r = RobotsTxt.parse('User-agent: *\nDisallow: /admin\nAllow: /admin/public\n');
  assert.equal(r.isAllowed('/admin'), false);
  assert.equal(r.isAllowed('/admin/secret'), false);
  // The longer `/admin/public` Allow wins for paths beneath it.
  assert.equal(r.isAllowed('/admin/public'), true);
  assert.equal(r.isAllowed('/admin/public/page'), true);
});

test('Allow wins on equal-length tie with Disallow', () => {
  const r = RobotsTxt.parse('User-agent: *\nDisallow: /x\nAllow: /x\n');
  assert.equal(r.isAllowed('/x'), true);
  assert.equal(r.isAllowed('/x/sub'), true);
});

test('rules for other user-agents do NOT apply to the * group', () => {
  const body = ['User-agent: SomeOtherBot', 'Disallow: /private', '', 'User-agent: *', 'Allow: /public', ''].join('\n');
  const r = RobotsTxt.parse(body);
  // The other bot's Disallow must not be inherited by *.
  assert.equal(r.isAllowed('/private'), true);
  // The * group's lone Allow is a no-op for paths it doesn't match (default allow holds).
  assert.equal(r.isAllowed('/anything'), true);
});

test('grouped User-agent lines (e.g. * + ChatGPT) share the same rules', () => {
  // Per the standard, consecutive User-agent lines share the following block.
  const body = ['User-agent: *', 'User-agent: ChatGPT', 'Disallow: /no', ''].join('\n');
  const r = RobotsTxt.parse(body);
  assert.equal(r.isAllowed('/no'), false);
  assert.equal(r.isAllowed('/yes'), true);
});

test('comments are stripped (# to end-of-line)', () => {
  const body = ['# top-level comment', 'User-agent: * # inline comment', 'Disallow: /no  # another comment', ''].join('\n');
  const r = RobotsTxt.parse(body);
  assert.equal(r.isAllowed('/no'), false);
  assert.equal(r.isAllowed('/yes'), true);
});

test('unknown directives (Crawl-delay, Sitemap, …) are ignored', () => {
  const body = ['User-agent: *', 'Crawl-delay: 10', 'Sitemap: https://example/sitemap.xml', 'Disallow: /private', ''].join('\n');
  const r = RobotsTxt.parse(body);
  assert.equal(r.isAllowed('/'), true);
  assert.equal(r.isAllowed('/private'), false);
});

test('case-insensitive directive names', () => {
  const body = ['user-agent: *', 'DISALLOW: /private', ''].join('\n');
  const r = RobotsTxt.parse(body);
  assert.equal(r.isAllowed('/private'), false);
});

test('paths with query strings match against the same prefix', () => {
  const r = RobotsTxt.parse('User-agent: *\nDisallow: /search\n');
  assert.equal(r.isAllowed('/search?q=foo'), false);
  assert.equal(r.isAllowed('/searchresults'), false, 'prefix match — /search also matches /searchresults');
  assert.equal(r.isAllowed('/other'), true);
});

test('permissive() constructor — no rules, everything allowed', () => {
  const r = RobotsTxt.permissive();
  assert.equal(r.ruleCount, 0);
  assert.equal(r.isAllowed('/'), true);
  assert.equal(r.isAllowed('/admin/secret'), true);
});

test('two consecutive * groups merge their effective rules', () => {
  // Two separate `User-agent: *` blocks — each contributes rules.
  const body = ['User-agent: *', 'Disallow: /a', '', 'User-agent: *', 'Disallow: /b', ''].join('\n');
  const r = RobotsTxt.parse(body);
  assert.equal(r.isAllowed('/a'), false);
  assert.equal(r.isAllowed('/b'), false);
  assert.equal(r.isAllowed('/c'), true);
});
