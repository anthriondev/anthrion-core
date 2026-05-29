import assert from 'node:assert/strict';
import { test } from 'node:test';

import {
  API_COVERAGE_MAP,
  API_CATEGORY_SLUGS,
  apiCategoriesByStatus,
  apiCoverageFor,
} from './api-coverage';
import { API_PROBES } from './api-probes';
import { owaspApiCategorySchema } from './category';

test('API coverage map has an entry for EVERY API category (forget-me-not guard)', () => {
  for (const slug of API_CATEGORY_SLUGS) {
    const entry = API_COVERAGE_MAP[slug];
    assert.ok(entry, `missing coverage entry for ${slug}`);
    assert.equal(entry.category, slug);
  }
});

test('API coverage map contains no keys outside the enum', () => {
  const mapKeys = Object.keys(API_COVERAGE_MAP);
  const enumSlugs = new Set<string>(owaspApiCategorySchema.options);
  for (const key of mapKeys) {
    assert.ok(enumSlugs.has(key), `coverage map contains unknown slug: ${key}`);
  }
});

test('every coverage entry has a valid status, an OWASP API code, and a non-empty rationale', () => {
  for (const slug of API_CATEGORY_SLUGS) {
    const entry = API_COVERAGE_MAP[slug];
    assert.ok(entry.status === 'covered' || entry.status === 'phase-2', `bad status for ${slug}`);
    assert.match(entry.owaspCode, /^API(?:10|[1-9]):2023$/, `bad OWASP API code for ${slug}: ${entry.owaspCode}`);
    assert.ok(entry.rationale.length > 0, `empty rationale for ${slug}`);
  }
});

test('every phase-2 entry explains itself honestly (mentions Phase 2 OR a missing prerequisite)', () => {
  for (const entry of apiCategoriesByStatus('phase-2')) {
    assert.ok(
      /phase\s*2/i.test(entry.rationale) || /\b(needs|requires)\b/i.test(entry.rationale),
      `phase-2 entry ${entry.category} does not honestly explain why`,
    );
  }
});

test('every API_PROBES probe targets a COVERED API category (no probe for phase-2)', () => {
  for (const probe of API_PROBES) {
    const entry = apiCoverageFor(probe.category);
    assert.equal(
      entry.status,
      'covered',
      `probe ${probe.id} targets ${probe.category} which is marked ${entry.status} — must be covered`,
    );
  }
});

test('every COVERED category has at least one real probe; phase-2 categories have none', () => {
  const probedCategories = new Set(API_PROBES.map((p) => p.category));
  for (const entry of apiCategoriesByStatus('covered')) {
    assert.ok(
      probedCategories.has(entry.category),
      `category ${entry.category} is marked covered but has zero probes (forget-me-not)`,
    );
  }
  for (const entry of apiCategoriesByStatus('phase-2')) {
    assert.ok(
      !probedCategories.has(entry.category),
      `category ${entry.category} is marked phase-2 but has a probe — promote it to covered or remove the probe`,
    );
  }
});

test('API probe ids are unique and stable, all start with "api:"', () => {
  const ids = API_PROBES.map((p) => p.id);
  assert.equal(new Set(ids).size, ids.length, 'duplicate probe ids');
  for (const id of ids) {
    assert.match(id, /^api:[a-z0-9-]+$/, `probe id "${id}" should match /^api:[a-z0-9-]+$/`);
  }
});

test('apiCoverageFor returns the documented status for each category', () => {
  for (const slug of API_CATEGORY_SLUGS) {
    assert.equal(apiCoverageFor(slug).status, API_COVERAGE_MAP[slug].status);
  }
});

test('coverage distribution: 3 covered, 7 phase-2 (total 10)', () => {
  const covered = apiCategoriesByStatus('covered').length;
  const phase2 = apiCategoriesByStatus('phase-2').length;
  assert.equal(covered, 3);
  assert.equal(phase2, 7);
  assert.equal(covered + phase2, API_CATEGORY_SLUGS.length);
});
