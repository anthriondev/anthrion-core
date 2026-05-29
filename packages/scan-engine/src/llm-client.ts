import { z } from 'zod';

import type { LlmCaller } from './llm';
import type { TokenBudget } from './token-budget';

/**
 * scan-engine LLM client via OpenRouter (T2.4).
 *
 * INTEGRATION (CLAUDE.md §6): uses native `fetch` (Node 24 / undici) directly
 * against the OpenAI-compatible OpenRouter HTTP API — NO SDK. Rationale: (1) the
 * fetch + Zod-validation pattern is already well-established in this package
 * (`endpoint-adapter.ts`); (2) avoids SDK dependency and drift risk; (3) full
 * control + boundary validation. Official docs read before integration:
 *   - POST https://openrouter.ai/api/v1/chat/completions (OpenAI-compatible)
 *   - Header: `Authorization: Bearer <key>`, optional `HTTP-Referer`, `X-Title`
 *   - Response carries `usage` {prompt_tokens, completion_tokens, total_tokens,
 *     prompt_tokens_details.cached_tokens}
 *   - Provider prompt caching (where supported): the model provider may apply
 *     automatic caching server-side; cache-hits are visible in
 *     `usage.prompt_tokens_details.cached_tokens` and are billed at a discount per
 *     the provider's pricing.
 *
 * This package is PURE: the client receives configuration via DI (apiKey, model
 * slug, budget). Env reading is done by the caller (apps/worker) and injected in.
 */

/** OpenRouter chat completions endpoint (OpenAI-compatible). */
export const OPENROUTER_CHAT_COMPLETIONS_URL = 'https://openrouter.ai/api/v1/chat/completions';

/** Default timeout per call (ms). LLMs are slower than typical endpoints. */
export const DEFAULT_LLM_TIMEOUT_MS = 60_000;

/** Default `max_tokens` cap per call when the caller does not specify one. */
export const DEFAULT_MAX_TOKENS_PER_CALL = 1_024;

/** Two model tiers (TECH_STACK.md): lightweight/high-volume vs heavy reasoning (Layer 2). */
export type LlmTier = 'light' | 'heavy';

/**
 * LLM client error (network failure, timeout, non-2xx status, unexpected
 * response shape). Messages NEVER include `OPENROUTER_API_KEY` (CLAUDE.md §7).
 */
export class LlmError extends Error {
  constructor(message: string, options?: { cause?: unknown }) {
    super(message, options);
    this.name = 'LlmError';
  }
}

/**
 * Subset of the OpenRouter chat completions response read by the client. LLM
 * responses are untrusted data (CLAUDE.md §3) → MUST pass this schema before
 * use. `usage` is required: without it the budget cap cannot be enforced.
 */
const completionResponseSchema = z.object({
  id: z.string().optional(),
  model: z.string().optional(),
  choices: z
    .array(
      z.object({
        message: z.object({ content: z.string() }),
        finish_reason: z.string().nullish(),
      }),
    )
    .min(1),
  usage: z.object({
    prompt_tokens: z.number().int().nonnegative(),
    completion_tokens: z.number().int().nonnegative(),
    total_tokens: z.number().int().nonnegative().optional(),
    prompt_tokens_details: z
      .object({ cached_tokens: z.number().int().nonnegative().optional() })
      .optional(),
  }),
});

/** OpenRouter error shape (non-2xx status) — parsed for a clear error message. */
const openRouterErrorSchema = z.object({
  error: z.object({ message: z.string(), code: z.union([z.string(), z.number()]).optional() }),
});

/** Client configuration — injected by the caller (from validated env). */
export const openRouterClientConfigSchema = z.object({
  apiKey: z.string().min(1),
  models: z.object({ light: z.string().min(1), heavy: z.string().min(1) }),
  baseUrl: z.string().url().default(OPENROUTER_CHAT_COMPLETIONS_URL),
  timeoutMs: z.number().int().positive().default(DEFAULT_LLM_TIMEOUT_MS),
  maxTokensPerCall: z.number().int().positive().default(DEFAULT_MAX_TOKENS_PER_CALL),
  /** Optional OpenRouter headers (ranking attribution). Not secret. */
  referer: z.string().optional(),
  title: z.string().optional(),
});

/** Configuration input type (before defaults are applied). */
export type OpenRouterClientConfig = z.input<typeof openRouterClientConfigSchema>;

/** Normalised token usage for a single call. */
export interface LlmUsage {
  promptTokens: number;
  completionTokens: number;
  totalTokens: number;
  /** Cache-hit tokens (prompt caching) if reported by the provider. */
  cachedTokens?: number;
}

/** Result of a single completion call. */
export interface LlmCompletionResult {
  content: string;
  /** Model slug that actually served the request (from the response, if present). */
  model: string;
  usage: LlmUsage;
}

/** Completion request to the OpenRouter client. */
export interface OpenRouterCompletionRequest {
  /** Optional system prompt. */
  system?: string;
  /** User message. */
  user: string;
  /** Model tier — mapped to a slug by the client. */
  tier: LlmTier;
  /** Per-scan budget; enforced before and after the call. */
  budget: TokenBudget;
  /** Override `max_tokens` for this call. */
  maxTokens?: number;
}

interface ChatMessage {
  role: 'system' | 'user';
  content: string;
}

/**
 * OpenRouter LLM client. A single instance may be shared across scans; cost
 * isolation is maintained by the per-scan `TokenBudget` passed on each call.
 */
export class OpenRouterLlmClient {
  private readonly apiKey: string;
  private readonly models: { light: string; heavy: string };
  private readonly baseUrl: string;
  private readonly timeoutMs: number;
  private readonly maxTokensPerCall: number;
  private readonly referer: string | undefined;
  private readonly title: string | undefined;

  constructor(config: OpenRouterClientConfig) {
    const cfg = openRouterClientConfigSchema.parse(config);
    this.apiKey = cfg.apiKey;
    this.models = cfg.models;
    this.baseUrl = cfg.baseUrl;
    this.timeoutMs = cfg.timeoutMs;
    this.maxTokensPerCall = cfg.maxTokensPerCall;
    this.referer = cfg.referer;
    this.title = cfg.title;
  }

  /** Model slug for a given tier. Mapping is code-determined, not a runtime guess. */
  modelFor(tier: LlmTier): string {
    return tier === 'heavy' ? this.models.heavy : this.models.light;
  }

  /**
   * Execute a single completion. Enforces the budget: throws
   * `TokenBudgetExceededError` BEFORE making any network call if the budget is
   * exhausted, and records tokens used after a valid response is received.
   */
  async complete(request: OpenRouterCompletionRequest): Promise<LlmCompletionResult> {
    // Hard stop: if the budget is already exhausted, no network call is made.
    request.budget.assertAvailable();

    const model = this.modelFor(request.tier);
    const messages = this.buildMessages(request);
    // Clamp max_tokens to the remaining budget so a single call cannot far exceed the cap.
    const requested = request.maxTokens ?? this.maxTokensPerCall;
    const maxTokens = Math.max(1, Math.min(requested, request.budget.remaining));

    const body = JSON.stringify({ model, messages, max_tokens: maxTokens });
    const response = await this.post(body);

    if (!response.ok) {
      const detail = await this.safeErrorDetail(response);
      throw new LlmError(
        `OpenRouter returned HTTP ${response.status} ${response.statusText}`.trimEnd() +
          (detail !== undefined ? `: ${detail}` : ''),
      );
    }

    const raw = await this.readJson(response);
    const parsed = completionResponseSchema.safeParse(raw);
    if (!parsed.success) {
      throw new LlmError(
        'OpenRouter response did not match the expected chat completions shape',
        { cause: parsed.error },
      );
    }

    const choice = parsed.data.choices[0];
    if (choice === undefined) {
      // Unreachable (schema enforces min 1) — guard for noUncheckedIndexedAccess.
      throw new LlmError('OpenRouter returned no choices');
    }

    const usage = parsed.data.usage;
    const totalTokens = usage.total_tokens ?? usage.prompt_tokens + usage.completion_tokens;
    // Record usage → closes the budget if the cap is hit (subsequent calls are rejected).
    request.budget.record(totalTokens);

    const cachedTokens = usage.prompt_tokens_details?.cached_tokens;
    return {
      content: choice.message.content,
      model: parsed.data.model ?? model,
      usage: {
        promptTokens: usage.prompt_tokens,
        completionTokens: usage.completion_tokens,
        totalTokens,
        ...(cachedTokens !== undefined ? { cachedTokens } : {}),
      },
    };
  }

  /**
   * Build a concrete `LlmCaller` (T2.2 contract) bound to a specific tier and
   * budget. This is the real implementation consumed by `SystemPromptTargetAdapter`.
   */
  caller(tier: LlmTier, budget: TokenBudget): LlmCaller {
    return {
      complete: ({ system, user, maxTokens }) =>
        this.complete({
          system,
          user,
          tier,
          budget,
          ...(maxTokens !== undefined ? { maxTokens } : {}),
        }).then((result) => result.content),
    };
  }

  private buildMessages(request: OpenRouterCompletionRequest): ChatMessage[] {
    if (request.system !== undefined) {
      return [
        { role: 'system', content: request.system },
        { role: 'user', content: request.user },
      ];
    }
    return [{ role: 'user', content: request.user }];
  }

  private buildHeaders(): Record<string, string> {
    // API key is only in the Authorization header; never logged (CLAUDE.md §7).
    const headers: Record<string, string> = {
      'Content-Type': 'application/json',
      Authorization: `Bearer ${this.apiKey}`,
    };
    if (this.referer !== undefined) {
      headers['HTTP-Referer'] = this.referer;
    }
    if (this.title !== undefined) {
      headers['X-Title'] = this.title;
    }
    return headers;
  }

  private async post(body: string): Promise<Response> {
    const controller = new AbortController();
    let timedOut = false;
    const timer = setTimeout(() => {
      timedOut = true;
      controller.abort();
    }, this.timeoutMs);

    try {
      return await fetch(this.baseUrl, {
        method: 'POST',
        headers: this.buildHeaders(),
        body,
        signal: controller.signal,
      });
    } catch (cause) {
      if (timedOut) {
        throw new LlmError(`OpenRouter request timed out after ${this.timeoutMs}ms`, { cause });
      }
      throw new LlmError('OpenRouter request failed (network error)', { cause });
    } finally {
      clearTimeout(timer);
    }
  }

  private async readJson(response: Response): Promise<unknown> {
    try {
      return await response.json();
    } catch (cause) {
      throw new LlmError('OpenRouter returned a non-JSON response', { cause });
    }
  }

  /** Safely extract the OpenRouter error message. Never throws or leaks the key. */
  private async safeErrorDetail(response: Response): Promise<string | undefined> {
    try {
      const raw: unknown = await response.json();
      const parsed = openRouterErrorSchema.safeParse(raw);
      if (parsed.success) {
        return parsed.data.error.message.slice(0, 300);
      }
    } catch {
      // Body is not JSON or unreadable — ignore it; the status code is sufficient.
      return undefined;
    }
    return undefined;
  }
}
