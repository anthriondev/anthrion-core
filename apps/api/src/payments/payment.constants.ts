/** DI tokens for the payment layer (T5.1). */

/** The FacilitatorClient implementation (placeholder in T5.1; swapped when chosen). */
export const FACILITATOR_CLIENT = Symbol('FACILITATOR_CLIENT');

/** The active ChainAdapter (Base in Phase 1). A network→adapter registry is added with Solana. */
export const ACTIVE_CHAIN_ADAPTER = Symbol('ACTIVE_CHAIN_ADAPTER');
