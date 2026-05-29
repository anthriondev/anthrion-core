import { z } from 'zod';

/**
 * Finding categories for the AI/LLM attack scan — based on the OWASP Top 10 for LLM
 * Applications, 2025 edition (genai.owasp.org/llm-top-10).
 *
 * Enum values are stable internal slugs; official OWASP codes are noted in
 * comments so they remain traceable to the standard. This enum is a contract:
 * it covers all ten categories even though concrete probes (T2.3) come later.
 */
export const owaspLlmCategorySchema = z.enum([
  'prompt-injection', // LLM01:2025 Prompt Injection
  'sensitive-information-disclosure', // LLM02:2025 Sensitive Information Disclosure
  'supply-chain', // LLM03:2025 Supply Chain
  'data-and-model-poisoning', // LLM04:2025 Data and Model Poisoning
  'improper-output-handling', // LLM05:2025 Improper Output Handling
  'excessive-agency', // LLM06:2025 Excessive Agency
  'system-prompt-leakage', // LLM07:2025 System Prompt Leakage
  'vector-and-embedding-weaknesses', // LLM08:2025 Vector and Embedding Weaknesses
  'misinformation', // LLM09:2025 Misinformation
  'unbounded-consumption', // LLM10:2025 Unbounded Consumption
]);

export type OwaspLlmCategory = z.infer<typeof owaspLlmCategorySchema>;

/**
 * Finding categories for the web app vulnerability scan (T2.6) — based on the
 * OWASP Top 10:2025 for web applications (owasp.org/Top10/2025).
 *
 * Uses a dedicated enum (rather than a generic category) to match the AI
 * category enum: both are strongly typed and tied to the official OWASP standard.
 */
export const owaspWebCategorySchema = z.enum([
  'broken-access-control', // A01:2025 Broken Access Control
  'security-misconfiguration', // A02:2025 Security Misconfiguration
  'software-supply-chain-failures', // A03:2025 Software Supply Chain Failures
  'cryptographic-failures', // A04:2025 Cryptographic Failures
  'injection', // A05:2025 Injection
  'insecure-design', // A06:2025 Insecure Design
  'authentication-failures', // A07:2025 Authentication Failures
  'software-or-data-integrity-failures', // A08:2025 Software or Data Integrity Failures
  'security-logging-and-alerting-failures', // A09:2025 Security Logging and Alerting Failures
  'mishandling-of-exceptional-conditions', // A10:2025 Mishandling of Exceptional Conditions
]);

export type OwaspWebCategory = z.infer<typeof owaspWebCategorySchema>;

/**
 * Finding categories for agentic systems — based on the OWASP Top 10 for
 * Agentic Applications, 2026 edition (genai.owasp.org/resource/owasp-top-10-for-
 * agentic-applications-for-2026). Released 9 December 2025.
 *
 * This third framework complements (rather than replaces) the OWASP LLM Top 10:
 * it is specific to the risks of agentic systems — tool use, multi-step,
 * multi-agent — which aligns with ANTHRION's focus as an agentic-internet
 * security platform (CLAUDE.md §1). 2026 industry practice uses both lists together.
 *
 * Enum values are stable internal slugs; official OWASP codes (ASI01–ASI10)
 * are noted in comments so they remain traceable to the standard. The "&" in
 * official names is spelled out as "and" in slugs, consistent with the two
 * enums above.
 */
export const owaspAgenticCategorySchema = z.enum([
  'agent-goal-hijack', // ASI01:2026 Agent Goal Hijack
  'tool-misuse', // ASI02:2026 Tool Misuse
  'identity-and-privilege-abuse', // ASI03:2026 Identity & Privilege Abuse
  'agentic-supply-chain-vulnerabilities', // ASI04:2026 Agentic Supply Chain Vulnerabilities
  'unexpected-code-execution', // ASI05:2026 Unexpected Code Execution
  'memory-and-context-poisoning', // ASI06:2026 Memory & Context Poisoning
  'insecure-inter-agent-communication', // ASI07:2026 Insecure Inter-Agent Communication
  'cascading-failures', // ASI08:2026 Cascading Failures
  'human-agent-trust-exploitation', // ASI09:2026 Human-Agent Trust Exploitation
  'rogue-agents', // ASI10:2026 Rogue Agents
]);

export type OwaspAgenticCategory = z.infer<typeof owaspAgenticCategorySchema>;

/**
 * Finding categories for the API security scan (Phase 1.5 Sprint A1, T-A1.2) —
 * based on the OWASP API Security Top 10:2023 edition (owasp.org/API-Security/
 * editions/2023). Released 2023; current as of 2026.
 *
 * Slug rule: the existing three enums (LLM / Web / Agentic) use evocative slugs
 * (`prompt-injection`, `broken-access-control`, `tool-misuse`). API8:2023
 * "Security Misconfiguration" has the same official name as the Web Top 10's
 * A02:2025; to keep `findingCategorySchema` unambiguous (no slug collision
 * across taxonomies — enforced by `category.test.ts`), the API slug is prefixed
 * with `api-`. This is the ONLY slug that needed disambiguation; the other nine
 * API categories have names distinct from the other enums.
 */
export const owaspApiCategorySchema = z.enum([
  'broken-object-level-authorization', // API1:2023 BOLA
  'broken-authentication', // API2:2023 Broken Authentication (note: web's slug is `authentication-failures`, distinct)
  'broken-object-property-level-authorization', // API3:2023 BOPLA (combines old EDE + Mass Assignment)
  'unrestricted-resource-consumption', // API4:2023 Unrestricted Resource Consumption
  'broken-function-level-authorization', // API5:2023 BFLA
  'unrestricted-access-to-sensitive-business-flows', // API6:2023 Unrestricted Access to Sensitive Business Flows
  'server-side-request-forgery', // API7:2023 SSRF
  'api-security-misconfiguration', // API8:2023 Security Misconfiguration (disambiguated; web's is `security-misconfiguration`)
  'improper-inventory-management', // API9:2023 Improper Inventory Management
  'unsafe-consumption-of-apis', // API10:2023 Unsafe Consumption of APIs
]);

export type OwaspApiCategory = z.infer<typeof owaspApiCategorySchema>;

/**
 * Finding categories for the Web3 dApp scan (Phase 1.5 Sprint A3, T-A3.2) —
 * synthesised from three OWASP-track sources that the scan actually exercises:
 *  - OWASP Smart Contract Top 10 (SC01–SC10), for L3 on-chain context findings
 *    (verified source / proxy / admin role surface).
 *  - The OWASP "Top 15 Web3 Application Risks" working list (WA06 wallet
 *    interaction, WA10 token impersonation, WA13 dApp frontend infrastructure),
 *    for L1 wallet-interaction and L2 frontend findings.
 *  - dApp-specific user-protection patterns the public OWASP lists name but do
 *    not pin to a single slug yet (EIP-7702 SetCode delegation, Permit2 mass
 *    approval).
 *
 * Slug rule: stays consistent with the existing four enums above — distinct,
 * evocative kebab-case strings; no collision with any LLM / web / agentic / API
 * slug (enforced by `category.test.ts`). L2 slugs are prefixed `dapp-` where
 * they would otherwise clash with the general web scan (DNS/TLS hygiene and
 * frontend integrity are scan-type-specific judgements, not the same concern
 * as the generic web scan's `cryptographic-failures` or
 * `software-or-data-integrity-failures`).
 *
 * Severity language for L3 slugs MUST stay "indicator-not-verdict" (T-A3.5
 * lesson surfacing the CORS wording correction from T-FIX.6): an unverified
 * contract or an EOA-admin is a real risk signal, not proof of malice.
 */
export const owaspWeb3CategorySchema = z.enum([
  // L1 — wallet interaction / approval phishing (WA06 family, T-A3.3).
  'wallet-approval-phishing',
  'deceptive-typed-data-signature',
  'personal-sign-payload-smell',
  'eip-7702-set-code-delegation',
  'mismatched-chainid-request',
  'permit2-mass-approval',
  // L2 — dApp frontend / infrastructure (WA13 + partial WA02, T-A3.6).
  'dapp-frontend-integrity',
  'known-bad-domain-reference',
  'dapp-dns-or-tls-hygiene',
  // L3 — on-chain context (SC01, SC10, WA10, T-A3.5). Indicators-not-verdicts.
  'contract-source-not-verified',
  'proxy-without-verified-implementation',
  'eoa-admin-single-key',
  'recent-contract-deployment',
  'token-impersonation-indicator',
  // L3 aggregate (T-A3.5 §4 hybrid composition): emitted IN ADDITION to the
  // per-indicator findings above when ≥2 of them hit on the same contract.
  // Severity is the max of the contributing individuals elevated by one tier
  // and capped at High — Critical is reserved for individual probes that
  // warrant it directly, never synthesised. Evidence explicitly lists the
  // contributing indicator slugs so the elevation is auditable, not hidden
  // composite math. Slug follows the existing adjective+noun L3 convention
  // (`recent-contract-deployment`); the "aggregate" framing is operational
  // and lives in the description, not in the taxonomy.
  'elevated-risk-contract',
]);

export type OwaspWeb3Category = z.infer<typeof owaspWeb3CategorySchema>;

/**
 * Category of a `Finding`. Union of the five OWASP-track taxonomies — LLM (AI
 * scan), web (DAST), agentic (autonomous agent systems), API (REST/HTTP API
 * security scan), and Web3 (dApp scan, Sprint A3). The values across all five
 * enums do not collide, so a finding's taxonomy can be read directly from its
 * slug. Notes on naming:
 *  - "supply chain" appears in LLM, web, and agentic frameworks with distinct
 *    slugs (`supply-chain`, `software-supply-chain-failures`,
 *    `agentic-supply-chain-vulnerabilities`).
 *  - "security misconfiguration" appears in web and API with distinct slugs
 *    (`security-misconfiguration`, `api-security-misconfiguration`).
 *  - "broken authentication" (API2:2023) and "authentication failures"
 *    (A07:2025) have different official names — distinct slugs without
 *    explicit prefixing.
 *  - Web3 L2 slugs carry the `dapp-` prefix where the same English phrase
 *    (DNS/TLS, frontend integrity) would otherwise overlap with the generic
 *    web scan — keeping a finding's taxonomy readable from the slug alone.
 */
export const findingCategorySchema = z.union([
  owaspLlmCategorySchema,
  owaspWebCategorySchema,
  owaspAgenticCategorySchema,
  owaspApiCategorySchema,
  owaspWeb3CategorySchema,
]);

export type FindingCategory = z.infer<typeof findingCategorySchema>;
