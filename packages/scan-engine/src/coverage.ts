import {
  owaspAgenticCategorySchema,
  owaspLlmCategorySchema,
  type OwaspAgenticCategory,
  type OwaspLlmCategory,
} from './category';

/**
 * Hybrid engine coverage map — completeness guard (T2.3 Section A, updated
 * T2.5 Section 2).
 *
 * EVERY category in `owaspLlmCategorySchema` and `owaspAgenticCategorySchema`
 * MUST have an entry (web categories are out of scope). The `tier` field is the
 * coverage STATUS for the category — an honest assessment of which layer owns
 * testing it:
 *
 * - `tier-1`          — Layer 1 (T2.3): multiple quality static probes.
 * - `tier-2`          — Layer 1 (T2.3): a single marker static probe.
 * - `layer-2-covered` — Layer 2 (T2.5): handled by the adaptive LLM attacker
 *                       against a SINGLE target (endpoint/system-prompt). Layer 1
 *                       has no meaningful static probes for it.
 * - `phase-2`         — outside Phase 1 scope: requires prerequisites absent
 *                       from the two Phase 1 target modes (multi-agent topology,
 *                       training-pipeline access, RAG backend, inventory/SBOM,
 *                       cross-session behavioral observation, execution-verification
 *                       sandbox). Not missing — Phase 2 work. MUST be justified.
 *
 * NOTE: Layer 2 also DEEPENS `tier-1`/`tier-2` categories adaptively
 * (see `LAYER2_ATTACK_CATEGORIES`) — the status here marks the PRIMARY owner
 * of testing, not the only layer that touches it.
 *
 * The `Record<…>` type enforces completeness at compile time; the guard test
 * (`coverage.test.ts`) enforces it at runtime + consistency with probes &
 * with the Layer 2 attack category list.
 *
 * PRINCIPLE (T2.3 Section B, T2.5 Section 2): taxonomic honesty over cosmetic
 * completeness. No fake probes (Layer 1) and no false coverage claims (Layer 2).
 * Anything outside Phase 1 scope stays recorded as Phase 2 — not claimed as done.
 */

export type CoverageTier = 'tier-1' | 'tier-2' | 'layer-2-covered' | 'phase-2';

export type CoverageTaxonomy = 'llm' | 'agentic';

export interface CoverageEntry {
  /** Category slug — must match the entry's key (enforced by test). */
  category: OwaspLlmCategory | OwaspAgenticCategory;
  /** Taxonomy the category belongs to. */
  taxonomy: CoverageTaxonomy;
  /** Coverage status (see `CoverageTier` type docs). */
  tier: CoverageTier;
  /** Brief written justification for this status. REQUIRED for all entries. */
  rationale: string;
}

/** Category types that must be covered by the map (LLM + Agentic; web is out of scope). */
export type CoveredCategory = OwaspLlmCategory | OwaspAgenticCategory;

export const LAYER1_COVERAGE_MAP: Readonly<Record<CoveredCategory, CoverageEntry>> = {
  // ----- OWASP LLM Top 10 (2025) -----
  'prompt-injection': {
    category: 'prompt-injection',
    taxonomy: 'llm',
    tier: 'tier-1',
    rationale:
      'Layer 1: core category, multiple static probes (verified canary). Jailbreaks map here (OWASP classifies them as LLM01 sub-category). Deepened adaptively by Layer 2.',
  },
  'sensitive-information-disclosure': {
    category: 'sensitive-information-disclosure',
    taxonomy: 'llm',
    tier: 'tier-1',
    rationale:
      'Layer 1: static probes + detection of well-formatted credential patterns. Deepened by Layer 2 (adaptive extraction); the evaluator uses the same credential detectors.',
  },
  'improper-output-handling': {
    category: 'improper-output-handling',
    taxonomy: 'llm',
    tier: 'tier-1',
    rationale:
      'Layer 1: static probes for active content (script/javascript:/event handlers). The primary risk is in downstream consumers, not adaptive target behavior — NOT included in the Layer 2 attack set.',
  },
  'system-prompt-leakage': {
    category: 'system-prompt-leakage',
    taxonomy: 'llm',
    tier: 'tier-1',
    rationale:
      'Layer 1: multiple extraction techniques + heuristic detector for instruction leakage. Deepened by Layer 2 (adaptive extraction; LLM/heuristic evaluator).',
  },
  'excessive-agency': {
    category: 'excessive-agency',
    taxonomy: 'llm',
    tier: 'tier-2',
    rationale:
      'Layer 1: single marker probe (unauthorized destructive action, canary). Deepened adaptively by Layer 2; confirmation of real execution remains Phase 2.',
  },
  'supply-chain': {
    category: 'supply-chain',
    taxonomy: 'llm',
    tier: 'phase-2',
    rationale:
      'Phase 2: provenance/dependency risk (model/dataset/plugin) — not a behavior triggerable by adaptive attacks against a single target. Full coverage requires SBOM/white-box analysis.',
  },
  'data-and-model-poisoning': {
    category: 'data-and-model-poisoning',
    taxonomy: 'llm',
    tier: 'phase-2',
    rationale:
      'Phase 2: requires training-pipeline access or backdoor-trigger discovery beyond black-box access to a single target. Cannot be honestly tested by a Phase 1 adaptive attacker.',
  },
  'vector-and-embedding-weaknesses': {
    category: 'vector-and-embedding-weaknesses',
    taxonomy: 'llm',
    tier: 'phase-2',
    rationale:
      'Phase 2: requires a RAG/retrieval backend to manipulate (vector-store poisoning, embedding inversion, cross-tenant leakage). Absent from both Phase 1 target modes.',
  },
  misinformation: {
    category: 'misinformation',
    taxonomy: 'llm',
    tier: 'layer-2-covered',
    rationale:
      'Layer 2: plants a CONTROLLED false premise and assesses whether the target affirms it without correction (sycophancy/overreliance). Because we define the false premise, the evaluator can verify a breach against a single target.',
  },
  'unbounded-consumption': {
    category: 'unbounded-consumption',
    taxonomy: 'llm',
    tier: 'phase-2',
    rationale:
      'Phase 2: requires resource/cost measurement across many requests + a careful non-DoS methodology. Outside adaptive behavioral attacks; running it now risks becoming a DoS.',
  },

  // ----- OWASP Top 10 for Agentic Applications (2026, ASI01–ASI10) -----
  'agent-goal-hijack': {
    category: 'agent-goal-hijack',
    taxonomy: 'agentic',
    tier: 'tier-2',
    rationale:
      'Layer 1: single marker probe (injected counter-goal, canary). Deepened by Layer 2 (adaptively pursuing the injected goal against a single target).',
  },
  'tool-misuse': {
    category: 'tool-misuse',
    taxonomy: 'agentic',
    tier: 'layer-2-covered',
    rationale:
      'Layer 2: adaptively coerces the agent into agreeing to/attempting tool misuse (e.g. out-of-bounds read, SSRF). Gate = agent agrees/claims it will misuse the tool (canary). Strongest against tool-capable agent endpoints; confirmation of real invocation = Phase 2.',
  },
  'identity-and-privilege-abuse': {
    category: 'identity-and-privilege-abuse',
    taxonomy: 'agentic',
    tier: 'layer-2-covered',
    rationale:
      'Layer 2: adaptive test for role/privilege confusion (e.g. "you are now admin"). Behavioral gate = target assumes unauthorized identity/privilege (canary/eval). Real ACL bypass requires a permission system = Phase 2.',
  },
  'agentic-supply-chain-vulnerabilities': {
    category: 'agentic-supply-chain-vulnerabilities',
    taxonomy: 'agentic',
    tier: 'phase-2',
    rationale:
      'Phase 2: provenance/dependency assessment of tools, plugins, and sub-agents. Requires an inventory/SBOM (beyond black-box access to a single target).',
  },
  'unexpected-code-execution': {
    category: 'unexpected-code-execution',
    taxonomy: 'agentic',
    tier: 'phase-2',
    rationale:
      'Phase 2: confirming REAL code execution (vs. the model role-playing terminal output) requires out-of-band side-effect verification or a sandbox oracle. Without it, results are prone to false-RCE — attacking without verification is dishonest.',
  },
  'memory-and-context-poisoning': {
    category: 'memory-and-context-poisoning',
    taxonomy: 'agentic',
    tier: 'phase-2',
    rationale:
      'Phase 2: requires stateful multi-turn/multi-session interaction (plant in one turn, trigger in another). Phase 1 target calls are stateless per-send.',
  },
  'insecure-inter-agent-communication': {
    category: 'insecure-inter-agent-communication',
    taxonomy: 'agentic',
    tier: 'phase-2',
    rationale:
      'Phase 2: requires a multi-agent communication topology (A2A) to observe or inject into. Absent from a single Phase 1 target.',
  },
  'cascading-failures': {
    category: 'cascading-failures',
    taxonomy: 'agentic',
    tier: 'phase-2',
    rationale:
      'Phase 2: emergent failure propagation across an agent chain; requires a multi-agent system and fault injection. Not observable from a single target.',
  },
  'human-agent-trust-exploitation': {
    category: 'human-agent-trust-exploitation',
    taxonomy: 'agentic',
    tier: 'phase-2',
    rationale:
      'Phase 2: its distinctive risk (agent exploiting trust of its human principal) requires cross-session behavioral observation. A single-shot test collapses into a jailbreak (already covered by prompt-injection in Layer 1/2).',
  },
  'rogue-agents': {
    category: 'rogue-agents',
    taxonomy: 'agentic',
    tier: 'phase-2',
    rationale:
      'Phase 2: detecting an agent acting outside its mandate requires cross-session autonomous behavioral observation. Not a single-shot adaptive attack against a single target.',
  },
};

/** All category slugs that must be covered by the map (LLM + Agentic), derived from enums. */
export const COVERED_CATEGORY_SLUGS: readonly CoveredCategory[] = [
  ...owaspLlmCategorySchema.options,
  ...owaspAgenticCategorySchema.options,
];

/**
 * Categories ATTACKED by the Layer 2 adaptive LLM attacker (T2.5) against a
 * single target. Union of: (a) adaptive deepening of Layer 1 behavioral categories
 * (`tier-1`/`tier-2`), and (b) `layer-2-covered` categories for which Layer 1
 * has no meaningful static probes.
 *
 * NOT included: `improper-output-handling` (risk lives in downstream consumers,
 * not adaptive target behavior) and all `phase-2` categories. Consistency is
 * enforced by tests.
 */
export const LAYER2_ATTACK_CATEGORIES: readonly CoveredCategory[] = [
  'prompt-injection',
  'system-prompt-leakage',
  'sensitive-information-disclosure',
  'excessive-agency',
  'agent-goal-hijack',
  'misinformation',
  'tool-misuse',
  'identity-and-privilege-abuse',
];

/** Retrieve the coverage entry for a category. */
export function coverageFor(category: CoveredCategory): CoverageEntry {
  return LAYER1_COVERAGE_MAP[category];
}

/** List coverage entries with a given status (tier). */
export function categoriesByTier(tier: CoverageTier): CoverageEntry[] {
  return COVERED_CATEGORY_SLUGS.map((slug) => LAYER1_COVERAGE_MAP[slug]).filter(
    (entry) => entry.tier === tier,
  );
}
