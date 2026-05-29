import assert from 'node:assert/strict';
import { test } from 'node:test';

import { owaspAgenticCategorySchema, owaspLlmCategorySchema } from './category';
import {
  COVERED_CATEGORY_SLUGS,
  LAYER1_COVERAGE_MAP,
  LAYER2_ATTACK_CATEGORIES,
  categoriesByTier,
  coverageFor,
  type CoverageTier,
  type CoveredCategory,
} from './coverage';
import { LAYER1_PROBES } from './probes';

const VALID_TIERS: readonly CoverageTier[] = ['tier-1', 'tier-2', 'layer-2-covered', 'phase-2'];

// --- GUARD tests: no enum category is forgotten (T2.3 A.3, updated T2.5). ---

test('coverage map has an entry for EVERY LLM category (forget-me-not guard)', () => {
  for (const slug of owaspLlmCategorySchema.options) {
    const entry = LAYER1_COVERAGE_MAP[slug];
    assert.ok(entry, `LLM category "${slug}" has no entry in the coverage map`);
    assert.equal(entry.taxonomy, 'llm');
  }
});

test('coverage map has an entry for EVERY Agentic category (forget-me-not guard)', () => {
  for (const slug of owaspAgenticCategorySchema.options) {
    const entry = LAYER1_COVERAGE_MAP[slug];
    assert.ok(entry, `Agentic category "${slug}" has no entry in the coverage map`);
    assert.equal(entry.taxonomy, 'agentic');
  }
});

test('coverage map contains no categories outside the LLM+Agentic enums (web is out of scope)', () => {
  const allowed = new Set<string>(COVERED_CATEGORY_SLUGS);
  for (const key of Object.keys(LAYER1_COVERAGE_MAP)) {
    assert.ok(allowed.has(key), `coverage map contains unknown key: "${key}"`);
  }
  assert.equal(Object.keys(LAYER1_COVERAGE_MAP).length, COVERED_CATEGORY_SLUGS.length);
  assert.equal(COVERED_CATEGORY_SLUGS.length, 20);
});

test('every entry key matches its internal category field', () => {
  for (const slug of COVERED_CATEGORY_SLUGS) {
    assert.equal(LAYER1_COVERAGE_MAP[slug].category, slug);
  }
});

test('every entry has a valid status and a non-empty written rationale', () => {
  const valid = new Set<string>(VALID_TIERS);
  for (const slug of COVERED_CATEGORY_SLUGS) {
    const entry = LAYER1_COVERAGE_MAP[slug];
    assert.ok(valid.has(entry.tier), `invalid status for "${slug}": ${entry.tier}`);
    assert.ok(entry.rationale.trim().length >= 20, `rationale for "${slug}" is too short/empty`);
  }
});

test('every phase-2 entry explains the missing prerequisite (honest, not claimed done)', () => {
  for (const entry of categoriesByTier('phase-2')) {
    assert.match(entry.rationale, /Phase 2/, `phase-2 entry "${entry.category}" must be marked Phase 2`);
  }
});

// --- Coverage map consistency with Layer 1 probes. ---

test('Layer 1 probes only target tier-1/tier-2 categories', () => {
  for (const probe of LAYER1_PROBES) {
    const entry = LAYER1_COVERAGE_MAP[probe.category as CoveredCategory];
    assert.ok(entry, `probe ${probe.id} belongs to a category not covered by the map: ${probe.category}`);
    assert.ok(
      entry.tier === 'tier-1' || entry.tier === 'tier-2',
      `probe ${probe.id} exists for a non-Layer-1 category (${probe.category}/${entry.tier})`,
    );
  }
});

test('tier-1 has >=2 probes; tier-2 exactly 1; layer-2-covered & phase-2 have no static probes', () => {
  const count = (category: string): number =>
    LAYER1_PROBES.filter((p) => p.category === category).length;
  for (const entry of categoriesByTier('tier-1')) {
    assert.ok(count(entry.category) >= 2, `tier-1 "${entry.category}" has <2 probes`);
  }
  for (const entry of categoriesByTier('tier-2')) {
    assert.equal(count(entry.category), 1, `tier-2 "${entry.category}" does not have exactly 1 probe`);
  }
  for (const entry of [...categoriesByTier('layer-2-covered'), ...categoriesByTier('phase-2')]) {
    assert.equal(count(entry.category), 0, `${entry.tier} "${entry.category}" must not have static probes`);
  }
});

// --- Coverage map consistency with the Layer 2 attack list (T2.5). ---

test('LAYER2_ATTACK_CATEGORIES contains no phase-2 categories (must not claim false coverage)', () => {
  for (const category of LAYER2_ATTACK_CATEGORIES) {
    const entry = LAYER1_COVERAGE_MAP[category];
    assert.notEqual(entry.tier, 'phase-2', `Layer 2 claims to attack a phase-2 category: ${category}`);
  }
});

test('every layer-2-covered category is actually present in the Layer 2 attack set', () => {
  const attackSet = new Set<string>(LAYER2_ATTACK_CATEGORIES);
  for (const entry of categoriesByTier('layer-2-covered')) {
    assert.ok(
      attackSet.has(entry.category),
      `layer-2-covered "${entry.category}" is missing from LAYER2_ATTACK_CATEGORIES`,
    );
  }
});

test('LAYER2_ATTACK_CATEGORIES is unique and all entries are valid enum categories', () => {
  const ids = [...LAYER2_ATTACK_CATEGORIES];
  assert.equal(new Set(ids).size, ids.length);
  const known = new Set<string>(COVERED_CATEGORY_SLUGS);
  for (const c of ids) {
    assert.ok(known.has(c), `unknown Layer 2 attack category: ${c}`);
  }
});

test('coverageFor returns the correct status (including new T2.5 statuses)', () => {
  assert.equal(coverageFor('prompt-injection').tier, 'tier-1');
  assert.equal(coverageFor('excessive-agency').tier, 'tier-2');
  assert.equal(coverageFor('misinformation').tier, 'layer-2-covered');
  assert.equal(coverageFor('tool-misuse').tier, 'layer-2-covered');
  assert.equal(coverageFor('rogue-agents').tier, 'phase-2');
});

test('tier distribution: 4 tier-1, 2 tier-2, 3 layer-2-covered, 11 phase-2 (total 20)', () => {
  assert.equal(categoriesByTier('tier-1').length, 4);
  assert.equal(categoriesByTier('tier-2').length, 2);
  assert.equal(categoriesByTier('layer-2-covered').length, 3);
  assert.equal(categoriesByTier('phase-2').length, 11);
});
