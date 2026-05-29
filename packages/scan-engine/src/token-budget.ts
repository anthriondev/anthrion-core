/**
 * Token budget cap per scan (ARCHITECTURE.md §4.2, T2.4).
 *
 * ANTHRION is a pay-per-scan product; LLM costs cut directly into margin and
 * must not run unchecked. One `TokenBudget` is created PER SCAN and passed to
 * the LLM client. The client records tokens used (input + output from the
 * OpenRouter `usage` field) and, once the cap is reached, REJECTS any further
 * calls — not just logging, but actually halting.
 *
 * Note: the cap is enforced BETWEEN calls (actual tokens are only known after
 * the response). To prevent a single call from overshooting the cap by too much,
 * the client also clamps `max_tokens` per call to the remaining budget.
 */

/** Thrown when the per-scan budget is exhausted and another LLM call is attempted. */
export class TokenBudgetExceededError extends Error {
  constructor(
    readonly cap: number,
    readonly used: number,
  ) {
    super(`Per-scan token budget reached: ${used}/${cap} tokens used — LLM usage halted`);
    this.name = 'TokenBudgetExceededError';
  }
}

export class TokenBudget {
  private usedTokens = 0;

  constructor(private readonly capTokens: number) {
    if (!Number.isInteger(capTokens) || capTokens <= 0) {
      throw new Error('Token budget cap must be a positive integer');
    }
  }

  /** Total token cap for this scan. */
  get cap(): number {
    return this.capTokens;
  }

  /** Total tokens used so far. */
  get used(): number {
    return this.usedTokens;
  }

  /** Remaining tokens before the cap is reached (never negative). */
  get remaining(): number {
    return Math.max(0, this.capTokens - this.usedTokens);
  }

  /** True when usage has reached or exceeded the cap. */
  isExhausted(): boolean {
    return this.usedTokens >= this.capTokens;
  }

  /**
   * Called BEFORE each LLM call. Throws `TokenBudgetExceededError` if the
   * budget is exhausted — this is the hard stop (no network call will be made).
   */
  assertAvailable(): void {
    if (this.isExhausted()) {
      throw new TokenBudgetExceededError(this.capTokens, this.usedTokens);
    }
  }

  /** Record tokens used AFTER an LLM call (input + output). */
  record(tokens: number): void {
    if (!Number.isFinite(tokens) || tokens < 0) {
      throw new Error('Token count to record must be a number >= 0');
    }
    this.usedTokens += tokens;
  }
}
