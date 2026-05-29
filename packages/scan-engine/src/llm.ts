/**
 * LLM caller abstraction required by the system-prompt target adapter (T2.2).
 *
 * Testing a system prompt requires that prompt to be EXECUTED by a model:
 * (system prompt + attack input) → LLM → response. Real LLM integration via
 * OpenRouter is not built until T2.4, so T2.2 only defines this contract and
 * injects it into the adapter (dependency injection). Concrete implementation
 * follows in T2.4; tests use a stub implementation.
 *
 * This is NOT a mock left on the production path — it is an explicit dependency
 * flagged as pending T2.4 (CLAUDE.md §4).
 *
 * SECURITY/TYPE NOTE: LLM output is untrusted data. The concrete implementation
 * (T2.4) is responsible for validating it with Zod at the external boundary
 * (CLAUDE.md §3) before returning the string to the caller.
 */
export interface LlmCompletionRequest {
  /** The system prompt under test (text pasted by the user). */
  system: string;
  /** The user message — i.e. the attack payload from `AttackInput`. */
  user: string;
  /**
   * Optional output token limit for this call. Added in T2.5 so the Layer 2
   * loop can keep attacker/evaluator calls economical. Implementations that
   * do not need it (e.g. `SystemPromptTargetAdapter`) may ignore it.
   */
  maxTokens?: number;
}

export interface LlmCaller {
  complete(request: LlmCompletionRequest): Promise<string>;
}
