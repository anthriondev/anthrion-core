import type { SystemPromptTargetSpec } from './config';
import type { LlmCaller } from './llm';
import {
  TargetAdapterError,
  targetResponseSchema,
  type AttackInput,
  type ScanTarget,
  type TargetResponse,
} from './target';

/**
 * Target adapter (b): system prompt pasted by the user (T2.2).
 *
 * Testing a system prompt requires running it through a model:
 * (system prompt + attack input) → LLM → response. The adapter holds the prompt
 * and depends on an injected `LlmCaller` — the real LLM integration (OpenRouter)
 * is built in T2.4. Satisfies the same `ScanTarget` interface as the endpoint
 * adapter, so attack logic is unaware of the target kind.
 */
export class SystemPromptTargetAdapter implements ScanTarget {
  constructor(
    private readonly spec: SystemPromptTargetSpec,
    private readonly llm: LlmCaller,
  ) {}

  async send(input: AttackInput): Promise<TargetResponse> {
    let content: string;
    try {
      content = await this.llm.complete({
        system: this.spec.prompt,
        user: input.payload,
      });
    } catch (cause) {
      throw new TargetAdapterError('System prompt target failed to obtain a model response', {
        cause,
      });
    }

    // Model output is untrusted data — validate before returning
    // (CLAUDE.md §3). The LlmCaller implementation (T2.4) also validates at its boundary.
    return targetResponseSchema.parse({ content });
  }
}
