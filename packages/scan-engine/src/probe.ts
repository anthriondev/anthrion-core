import type { FindingCategory } from './category';
import type { Severity } from './severity';
import type { AttackInput, TargetResponse } from './target';

/**
 * The result of a single detector run against one `TargetResponse` (T2.3, Layer 1).
 *
 * Detector decisions MUST be explainable (CLAUDE.md §3 — security product):
 * `rationale` always explains why the response was deemed vulnerable or safe, and
 * `matched` holds the response snippet that triggered detection (becoming the
 * Finding's `evidence`). Layer 1 detectors are rule-based — no LLM.
 */
export interface DetectionResult {
  /** True when the detector judges the response as showing a vulnerability. */
  detected: boolean;
  /** Explanation of the decision (positive or negative). Always populated. */
  rationale: string;
  /** Matched response snippet — only present when `detected`. Becomes evidence. */
  matched?: string;
}

/**
 * Rule-based detector: examines a single `TargetResponse` and decides whether
 * the target exhibits a vulnerability. Pure and synchronous — no I/O, no LLM.
 */
export type ProbeDetector = (response: TargetResponse) => DetectionResult;

/**
 * A single static attack probe = (attack payload, detector) pair plus enough
 * metadata to construct a normalised `Finding` when triggered.
 *
 * `id` is stable and unique across probes — used as the base for the `Finding`
 * id and for cross-checking against the coverage map (see `coverage.ts`).
 * `category` MUST reference a category with `tier-1`/`tier-2` status in the
 * coverage map (a probe for a `layer-2` category is a taxonomy contradiction
 * — enforced by tests).
 */
export interface StaticProbe {
  /** Stable, unique identity, e.g. `pi-direct-override`. */
  id: string;
  /** Short technique label for documentation and evidence, e.g. `direct-instruction-override`. */
  technique: string;
  /** OWASP category of the Finding produced by this probe. */
  category: FindingCategory;
  /** Severity of the Finding if the probe triggers. */
  severity: Severity;
  /** Concise Finding title. */
  title: string;
  /** Description of the vulnerability being tested. */
  description: string;
  /** Basic mitigation recommendation. */
  recommendation: string;
  /** Attack payload sent to the target via `ScanTarget.send()`. */
  input: AttackInput;
  /** Rule-based detector that evaluates the target's response. */
  detect: ProbeDetector;
}
