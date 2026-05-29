import { z } from 'zod';

/**
 * Sandbox configuration for the per-scan Docker container (T3.2 §3/§4).
 *
 * Worker-local config (kept out of `@anthrion/shared`'s env schema, which is shared
 * with api/web that have no business with sandbox limits). All values come from
 * env — never hardcoded (Context §3) — and are Zod-validated (CLAUDE.md §3).
 *
 * RESOURCE LIMITS — set LOOSE, as a safety net, NOT tight (Context §3, same
 * principle as the T2.6 timeouts). A normal scan — including a web scan that drives
 * Chromium — must NEVER touch these. The limits only catch a genuinely runaway
 * container (malicious target, bug, a page that makes Chromium greedy) so it cannot
 * starve the host or other scans. Tight limits would corrupt scan accuracy;
 * that is deliberately avoided. Proposed Phase-1 defaults are conservative for a
 * modest shared host; operators on larger hosts can raise them via the SANDBOX_* env
 * vars (see .env.example).
 */

/** Defaults are PROPOSALS for Phase 1 review (Context §3) — all overridable via env. */
export const SANDBOX_DEFAULTS = {
  /** Image built from the scan-engine Dockerfile (Part A). Tag is pinned by the build script. */
  image: 'anthrion-scan-runtime:latest',
  /**
   * Dedicated bridge network for scan containers. Isolation comes from Docker's own
   * network model: a container on its OWN bridge cannot reach other bridge networks
   * (Postgres/Redis/MinIO + other projects) — DOCKER-ISOLATION chains + default-DROP
   * FORWARD — while still getting outbound internet via NAT (Part §4).
   */
  network: 'anthrion-scan-net',
  /**
   * Memory cap (MB). A headless-Chromium single-page scan peaks well under 1 GB;
   * 1.5 GB gives generous headroom so a normal scan never hits it, while capping a
   * runaway at <20% of the 8 GB host. Swap is disabled (memory-swap = memory) so an
   * over-limit container is OOM-killed cleanly and detectably instead of thrashing
   * the shared host's swap.
   */
  memoryMb: 1_536,
  /**
   * CPU cap (cores). 1.0 of 4 lets a scan (incl. Chromium) run at good speed while
   * capping it to 25% of host CPU, so it cannot starve other projects. Web/AI scans
   * are navigation/IO-bound, so 1 core is comfortable, not tight.
   */
  cpus: 1,
  /**
   * Process cap — defends against fork bombs. Chromium spawns a few dozen helper
   * processes; 512 is generous headroom while still bounding a runaway.
   */
  pidsLimit: 512,
  /**
   * Overall container wall-clock lifetime (ms) — worker-enforced (Docker has no
   * built-in max lifetime). Set ABOVE the engine's own per-operation timeouts (T2.4
   * token budget; T2.6 navigation 30s + per-probe 10s) so the engine times out and
   * reports HONESTLY first; this ceiling only catches an engine that is wedged solid.
   * 5 min comfortably exceeds a full AI scan (Layer 1 + adaptive Layer 2) or a web
   * scan, so a normal scan never reaches it.
   */
  lifetimeMs: 300_000,
  /** /dev/shm size (MB) for Chromium stability (paired with `--disable-dev-shm-usage`). */
  shmSizeMb: 256,
} as const;

/**
 * Schema for the sandbox env vars. `z.coerce.number()` parses the string env values;
 * bounds reject obviously-wrong settings (e.g. a 0 ms lifetime) loudly at load.
 */
export const sandboxConfigSchema = z.object({
  SANDBOX_IMAGE: z.string().min(1).default(SANDBOX_DEFAULTS.image),
  SANDBOX_NETWORK: z.string().min(1).default(SANDBOX_DEFAULTS.network),
  SANDBOX_MEMORY_MB: z.coerce.number().int().positive().default(SANDBOX_DEFAULTS.memoryMb),
  SANDBOX_CPUS: z.coerce.number().positive().default(SANDBOX_DEFAULTS.cpus),
  SANDBOX_PIDS_LIMIT: z.coerce.number().int().positive().default(SANDBOX_DEFAULTS.pidsLimit),
  SANDBOX_LIFETIME_MS: z.coerce.number().int().positive().default(SANDBOX_DEFAULTS.lifetimeMs),
  SANDBOX_SHM_SIZE_MB: z.coerce.number().int().positive().default(SANDBOX_DEFAULTS.shmSizeMb),
});

/** Resolved, validated sandbox configuration. */
export interface SandboxConfig {
  image: string;
  network: string;
  memoryMb: number;
  cpus: number;
  pidsLimit: number;
  lifetimeMs: number;
  shmSizeMb: number;
}

/**
 * Load and validate sandbox config from an env-like record (defaults to
 * `process.env`). Throws `ZodError` with a clear message if a provided value is
 * invalid — config never silently falls back.
 */
export function loadSandboxConfig(env: NodeJS.ProcessEnv = process.env): SandboxConfig {
  const parsed = sandboxConfigSchema.parse(env);
  return {
    image: parsed.SANDBOX_IMAGE,
    network: parsed.SANDBOX_NETWORK,
    memoryMb: parsed.SANDBOX_MEMORY_MB,
    cpus: parsed.SANDBOX_CPUS,
    pidsLimit: parsed.SANDBOX_PIDS_LIMIT,
    lifetimeMs: parsed.SANDBOX_LIFETIME_MS,
    shmSizeMb: parsed.SANDBOX_SHM_SIZE_MB,
  };
}
