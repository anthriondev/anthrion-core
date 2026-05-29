import { z } from 'zod';

/**
 * A single attack input sent to a target.
 * `payload` is the attack text (e.g. a prompt injection); `metadata` is optional
 * adapter context (e.g. probe name).
 */
export const attackInputSchema = z.object({
  payload: z.string(),
  metadata: z.record(z.string(), z.string()).optional(),
});

export type AttackInput = z.infer<typeof attackInputSchema>;

/**
 * Raw response from the target for a given `AttackInput`. This data originates
 * outside the trust boundary (agent endpoint / LLM output) — the adapter must
 * validate it against this schema before returning it (CLAUDE.md §3).
 */
export const targetResponseSchema = z.object({
  content: z.string(),
  metadata: z.record(z.string(), z.string()).optional(),
});

export type TargetResponse = z.infer<typeof targetResponseSchema>;

/**
 * Target adapter interface (ARCHITECTURE.md §4.1).
 *
 * The core operation that attack logic requires from a target: send one attack
 * input, receive one response. This interface hides the differences between
 * target types (API endpoint vs system prompt paste) so that the attack logic
 * above it does not need to know which kind of target it is talking to. Concrete
 * implementations for both adapters are T2.2.
 */
export interface ScanTarget {
  send(input: AttackInput): Promise<TargetResponse>;
}

/**
 * Error thrown by a target adapter when it fails to obtain a valid response from
 * the target — network failure, timeout, non-2xx status, or a response that does
 * not match the schema. Gives attack logic (T2.3+) a way to mark an unreachable
 * target instead of crashing. `cause` holds the originating error for diagnosis.
 *
 * Error messages MUST NOT contain credential values (see the security note on
 * `endpointAuthSchema`).
 */
export class TargetAdapterError extends Error {
  constructor(message: string, options?: { cause?: unknown }) {
    super(message, options);
    this.name = 'TargetAdapterError';
  }
}
