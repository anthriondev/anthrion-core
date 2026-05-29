import { CREDENTIAL_PATTERNS } from './detectors';

/**
 * Layer 2 safety guardrails (T2.5 Context §3). ANTHRION will be released under
 * Apache 2.0 — it must prove vulnerabilities, NOT become a generator of harmful
 * content. Two mechanisms here enforce this in code (not just in prompts):
 *
 *  - `violatesRedLine()` — hard red line (§3c): rejects attack payloads that
 *    attempt to lead a target into PRODUCING severely prohibited material (CSAM,
 *    CBRN weapons). Testing in these areas must not happen at all.
 *  - `sanitizeForEvidence()` — evidence sanitisation (§3d): proof of a breach is
 *    retained, but harmful payloads and secrets are not archived verbatim.
 *
 * These filters intentionally contain DETECTION MARKERS (not instructions).
 * Layer 2 attack categories (`LAYER2_ATTACK_CATEGORIES`) do not target production
 * of prohibited material; these filters are a second-layer safety net in case the
 * LLM attacker goes off-script.
 */

export interface RedLineCheck {
  blocked: boolean;
  /** Hazard category label that triggered the block (not a payload quote). */
  reason?: string;
}

/**
 * Red-line patterns. Each entry: keyword for a severe hazard domain + a
 * "production/instruction" intent signal. Requiring both suppresses false
 * positives (mentioning a topic to test refusal is fine; leading the model to
 * PRODUCE the material is not).
 */
interface RedLinePattern {
  topic: RegExp;
  intent: RegExp;
  reason: string;
}

const PRODUCTION_INTENT =
  /\b(?:how\s+to\s+(?:make|build|create|produce|synthesi[sz]e)|step[-\s]?by[-\s]?step|instructions?\s+(?:to|for)|recipe|synthesi[sz]e|manufactur|produce|provide\s+detailed)\b/i;

const RED_LINE_PATTERNS: readonly RedLinePattern[] = [
  {
    // Child exploitation/abuse — absolute red line, no production-intent condition required.
    topic: /\b(?:csam|child(?:\s+|-)(?:sexual|porn|abuse|exploitation)|minor[s]?\b[^.]{0,40}\bsexual|underage[^.]{0,40}\b(?:sex|nude|porn))\b/i,
    intent: /.*/,
    reason: 'child-sexual-abuse-material',
  },
  {
    // Biological weapons.
    topic: /\b(?:bioweapon|biological\s+weapon|nerve\s+agent|sarin|\bvx\b|anthrax|ricin|pathogen)\b/i,
    intent: PRODUCTION_INTENT,
    reason: 'cbrn-biological-weapon',
  },
  {
    // Chemical weapons.
    topic: /\b(?:chemical\s+weapon|mustard\s+gas|chlorine\s+gas|toxic\s+gas)\b/i,
    intent: PRODUCTION_INTENT,
    reason: 'cbrn-chemical-weapon',
  },
  {
    // Nuclear/radiological weapons and explosives.
    topic: /\b(?:nuclear\s+weapon|dirty\s+bomb|radiological\s+weapon|enrich(?:ed|ment)?\s+uranium|improvised\s+explosive|\bied\b|pipe\s+bomb)\b/i,
    intent: PRODUCTION_INTENT,
    reason: 'cbrn-nuclear-or-explosive',
  },
];

/**
 * Check whether an attack text hits a hard red line. Called on OUTBOUND payloads
 * (those about to be sent to a target) BEFORE sending — blocked payloads are
 * NOT sent. Red lines have no "for testing purposes" exceptions.
 */
export function violatesRedLine(text: string): RedLineCheck {
  for (const { topic, intent, reason } of RED_LINE_PATTERNS) {
    if (topic.test(text) && intent.test(text)) {
      return { blocked: true, reason };
    }
  }
  return { blocked: false };
}

/** Maximum length of an evidence snippet (§3d: enough proof, not a payload archive). */
export const EVIDENCE_SNIPPET_MAX = 600;

const REDACTED_SECRET = '[REDACTED:secret]';
const REDACTED_DISALLOWED = '[REDACTED:disallowed-content]';

/**
 * Sanitise text for `Finding.evidence` (§3d). Proves a breach without archiving
 * harmful payloads or secrets verbatim:
 *  1. Redact well-known secret formats (reusing Layer 1 credential patterns) →
 *     evidence THAT a secret leaked is preserved (its type), but not its value.
 *  2. Redact any content that hits a red line if it makes it this far.
 *  3. Truncate to `EVIDENCE_SNIPPET_MAX` — reports need proof, not a full transcript.
 */
export function sanitizeForEvidence(text: string, maxLength: number = EVIDENCE_SNIPPET_MAX): string {
  let out = text;

  // (1) Redact well-known secret formats.
  for (const { re } of CREDENTIAL_PATTERNS) {
    out = out.replace(new RegExp(re.source, re.flags.includes('g') ? re.flags : `${re.flags}g`), REDACTED_SECRET);
  }

  // (2) Redact red-line content if present (safety net for report readers).
  const redLine = violatesRedLine(out);
  if (redLine.blocked) {
    return `${REDACTED_DISALLOWED} (${redLine.reason ?? 'red-line'})`;
  }

  // (3) Truncate.
  if (out.length > maxLength) {
    out = `${out.slice(0, maxLength)}…[truncated]`;
  }
  return out;
}
