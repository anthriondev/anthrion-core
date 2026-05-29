import { z } from 'zod';

import type { EndpointAuth, EndpointTargetSpec } from './config';
import {
  TargetAdapterError,
  targetResponseSchema,
  type AttackInput,
  type ScanTarget,
  type TargetResponse,
} from './target';

/** Default endpoint request timeout (ms). Slow agent endpoints are still bounded. */
export const DEFAULT_ENDPOINT_TIMEOUT_MS = 30_000;

/**
 * Subset of the OpenAI-compatible chat completions response that the adapter
 * reads. Only fields that are actually used — the endpoint response is untrusted
 * data (CLAUDE.md §3) and MUST pass this schema before being used. Unexpected
 * shapes (errors, HTML, differently-shaped JSON) are rejected with a clear error.
 */
const chatCompletionResponseSchema = z.object({
  model: z.string().optional(),
  choices: z
    .array(
      z.object({
        message: z.object({ content: z.string() }),
        finish_reason: z.string().nullish(),
      }),
    )
    .min(1),
});

interface EndpointTargetAdapterOptions {
  /** Request timeout in ms (default `DEFAULT_ENDPOINT_TIMEOUT_MS`). */
  timeoutMs?: number;
}

/**
 * Target adapter (a): OpenAI-compatible agent API endpoint (T2.2).
 *
 * Maps a single `AttackInput` → POST chat completions, then response →
 * `TargetResponse`. Satisfies the same `ScanTarget` interface as the system-prompt
 * adapter, so attack logic above it is unaware of the target kind.
 */
export class EndpointTargetAdapter implements ScanTarget {
  private readonly timeoutMs: number;

  constructor(
    private readonly spec: EndpointTargetSpec,
    options: EndpointTargetAdapterOptions = {},
  ) {
    this.timeoutMs = options.timeoutMs ?? DEFAULT_ENDPOINT_TIMEOUT_MS;
  }

  async send(input: AttackInput): Promise<TargetResponse> {
    // AttackInput.payload → a single OpenAI chat-completions user message.
    const body = JSON.stringify({
      ...(this.spec.model !== undefined ? { model: this.spec.model } : {}),
      messages: [{ role: 'user', content: input.payload }],
    });

    const response = await this.fetchWithTimeout(body);

    if (!response.ok) {
      throw new TargetAdapterError(
        `Target endpoint returned HTTP ${response.status} ${response.statusText}`.trimEnd(),
      );
    }

    const raw = await this.readJson(response);
    const parsed = chatCompletionResponseSchema.safeParse(raw);
    if (!parsed.success) {
      throw new TargetAdapterError(
        'Target endpoint response did not match the expected OpenAI-compatible chat completions shape',
        { cause: parsed.error },
      );
    }

    const choice = parsed.data.choices[0];
    if (choice === undefined) {
      // Unreachable (schema enforces min 1) — guard for noUncheckedIndexedAccess.
      throw new TargetAdapterError('Target endpoint returned no choices');
    }

    const metadata: Record<string, string> = {};
    if (parsed.data.model !== undefined) {
      metadata.model = parsed.data.model;
    }
    if (choice.finish_reason !== undefined && choice.finish_reason !== null) {
      metadata.finishReason = choice.finish_reason;
    }

    return targetResponseSchema.parse({
      content: choice.message.content,
      ...(Object.keys(metadata).length > 0 ? { metadata } : {}),
    });
  }

  private async fetchWithTimeout(body: string): Promise<Response> {
    const controller = new AbortController();
    let timedOut = false;
    const timer = setTimeout(() => {
      timedOut = true;
      controller.abort();
    }, this.timeoutMs);

    try {
      return await fetch(this.spec.url, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          ...buildAuthHeaders(this.spec.auth),
        },
        body,
        signal: controller.signal,
      });
    } catch (cause) {
      if (timedOut) {
        throw new TargetAdapterError(
          `Target endpoint request timed out after ${this.timeoutMs}ms`,
          { cause },
        );
      }
      throw new TargetAdapterError('Target endpoint request failed (network error)', { cause });
    } finally {
      clearTimeout(timer);
    }
  }

  private async readJson(response: Response): Promise<unknown> {
    try {
      return await response.json();
    } catch (cause) {
      throw new TargetAdapterError('Target endpoint returned a non-JSON response', { cause });
    }
  }
}

/**
 * Build auth headers from config. Returns an empty object when there is no auth.
 * Credential values are never logged here (CLAUDE.md §3 / security note).
 */
function buildAuthHeaders(auth: EndpointAuth | undefined): Record<string, string> {
  if (auth === undefined) {
    return {};
  }
  if (auth.type === 'bearer') {
    return { Authorization: `Bearer ${auth.value}` };
  }
  return { [auth.headerName]: auth.value };
}
