import assert from 'node:assert/strict';
import { test } from 'node:test';

import { owaspWebCategorySchema } from './category';
import {
  WEB_CATEGORY_SLUGS,
  WEB_COVERAGE_MAP,
  webCategoriesByStatus,
  webCoverageFor,
  type WebCoverageStatus,
} from './web-coverage';
import { WEB_PROBES } from './web-probes';

const VALID_STATUSES: readonly WebCoverageStatus[] = ['covered', 'phase-2'];

// --- GUARD tests: no web category is forgotten (T2.6 Context §2). ---

test('coverage map has an entry for EVERY web category (forget-me-not guard)', () => {
  for (const slug of owaspWebCategorySchema.options) {
    const entry = WEB_COVERAGE_MAP[slug];
    assert.ok(entry, `web category "${slug}" has no entry in the coverage map`);
    assert.equal(entry.category, slug);
  }
});

test('coverage map contains no keys outside the web enum', () => {
  const allowed = new Set<string>(WEB_CATEGORY_SLUGS);
  for (const key of Object.keys(WEB_COVERAGE_MAP)) {
    assert.ok(allowed.has(key), `coverage map contains unknown key: "${key}"`);
  }
  assert.equal(Object.keys(WEB_COVERAGE_MAP).length, WEB_CATEGORY_SLUGS.length);
  assert.equal(WEB_CATEGORY_SLUGS.length, 10);
});

test('every entry has a valid status, an OWASP code, and a written rationale', () => {
  const valid = new Set<string>(VALID_STATUSES);
  for (const slug of WEB_CATEGORY_SLUGS) {
    const entry = WEB_COVERAGE_MAP[slug];
    assert.ok(valid.has(entry.status), `invalid status for "${slug}": ${entry.status}`);
    assert.match(entry.owaspCode, /^A\d{2}:2025$/, `bad OWASP code for "${slug}": ${entry.owaspCode}`);
    assert.ok(entry.rationale.trim().length >= 40, `rationale for "${slug}" is too short/empty`);
  }
});

test('every phase-2 entry explains itself as Phase 2 (honest, not claimed done)', () => {
  for (const entry of webCategoriesByStatus('phase-2')) {
    assert.match(
      entry.rationale,
      /Phase 2/,
      `phase-2 entry "${entry.category}" must justify itself as Phase 2`,
    );
  }
});

// --- Consistency between the coverage map and the actual probe set. ---

test('every WEB_PROBES probe targets a COVERED web category (no probe for phase-2)', () => {
  const coveredSlugs = new Set(webCategoriesByStatus('covered').map((e) => e.category));
  for (const probe of WEB_PROBES) {
    const entry = WEB_COVERAGE_MAP[probe.category];
    assert.ok(entry, `probe ${probe.id} has a category not in the map: ${probe.category}`);
    assert.ok(
      coveredSlugs.has(probe.category),
      `probe ${probe.id} exists for a non-covered category (${probe.category}/${entry.status})`,
    );
  }
});

test('every COVERED category has at least one real probe; phase-2 categories have none', () => {
  const count = (category: string): number =>
    WEB_PROBES.filter((p) => p.category === category).length;
  for (const entry of webCategoriesByStatus('covered')) {
    assert.ok(count(entry.category) >= 1, `covered "${entry.category}" has no probe (fake/empty coverage)`);
  }
  for (const entry of webCategoriesByStatus('phase-2')) {
    assert.equal(count(entry.category), 0, `phase-2 "${entry.category}" must not have a probe`);
  }
});

test('probe ids are unique and stable', () => {
  const ids = WEB_PROBES.map((p) => p.id);
  assert.equal(new Set(ids).size, ids.length, 'duplicate probe ids');
  for (const id of ids) {
    assert.match(id, /^[a-z0-9-]+$/, `probe id is not a stable slug: ${id}`);
  }
});

test('webCoverageFor returns the documented status for each category', () => {
  assert.equal(webCoverageFor('security-misconfiguration').status, 'covered');
  assert.equal(webCoverageFor('cryptographic-failures').status, 'covered');
  assert.equal(webCoverageFor('software-or-data-integrity-failures').status, 'covered');
  assert.equal(webCoverageFor('mishandling-of-exceptional-conditions').status, 'covered');
  assert.equal(webCoverageFor('broken-access-control').status, 'phase-2');
  assert.equal(webCoverageFor('injection').status, 'phase-2');
  assert.equal(webCoverageFor('insecure-design').status, 'phase-2');
  assert.equal(webCoverageFor('authentication-failures').status, 'phase-2');
  assert.equal(webCoverageFor('software-supply-chain-failures').status, 'phase-2');
  assert.equal(webCoverageFor('security-logging-and-alerting-failures').status, 'phase-2');
});

test('coverage distribution: 4 covered, 6 phase-2 (total 10)', () => {
  assert.equal(webCategoriesByStatus('covered').length, 4);
  assert.equal(webCategoriesByStatus('phase-2').length, 6);
});
