import type { ScanProgressEvent } from '@anthrion/scan-engine';

import {
  DIAGNOSTIC_OPS,
  DIAGNOSTICS_ENV_VAR,
  EVENT_LINE_PREFIX,
  RESULT_LINE_PREFIX,
  sandboxJobSchema,
  sandboxResultSchema,
  type SandboxResult,
} from './contract';
import { runSandboxJob } from './run';

/**
 * Container entrypoint (T3.2) — the process the per-scan sandbox runs as PID 1's
 * child. It is the in-container half of the worker↔container contract (contract.ts):
 *
 *   1. read the JSON {@link import('./contract').SandboxJob} from stdin;
 *   2. validate it (stdin is external input — Zod is the trust boundary, CLAUDE.md §3);
 *   3. run it via {@link runSandboxJob};
 *   4. write exactly ONE result line to stdout (prefixed), diagnostics to stderr;
 *   5. exit 0 on success, non-zero on failure so the worker can classify the run.
 *
 * This file performs process I/O on purpose — it is the boundary glue, kept out of
 * the pure `scan-engine` package (ARCHITECTURE.md §2). It is NOT re-exported from
 * the package index, so importing `@anthrion/sandbox-runtime` has no side effects.
 */

function emitResult(result: SandboxResult): void {
  // The single machine-readable RESULT line the worker greps for at the end.
  process.stdout.write(`${RESULT_LINE_PREFIX}${JSON.stringify(result)}\n`);
}

/**
 * Progress sink (T4.2): write each engine stage event as its own prefixed stdout line.
 * The engine emits these DURING the scan; the worker streams stdout, routes EVENT lines
 * to Redis, and keeps the RESULT line for the final outcome. Events leave the container
 * ONLY via stdout — the sandbox never touches Redis (T3.2 isolation stays intact).
 */
function emitEvent(event: ScanProgressEvent): void {
  process.stdout.write(`${EVENT_LINE_PREFIX}${JSON.stringify(event)}\n`);
}

async function readStdin(): Promise<string> {
  const chunks: Buffer[] = [];
  for await (const chunk of process.stdin) {
    chunks.push(chunk instanceof Buffer ? chunk : Buffer.from(chunk));
  }
  return Buffer.concat(chunks).toString('utf8');
}

async function main(): Promise<void> {
  const raw = await readStdin();
  if (raw.trim() === '') {
    throw new Error('No job received on stdin.');
  }

  const job = sandboxJobSchema.parse(JSON.parse(raw));

  // Diagnostic ops are gated: they prove sandbox limits/isolation and must never be
  // reachable on the production scan path (the worker sets the env only in tests).
  const isDiagnostic = (DIAGNOSTIC_OPS as readonly string[]).includes(job.op);
  if (isDiagnostic && process.env[DIAGNOSTICS_ENV_VAR] !== '1') {
    throw new Error(`Diagnostic op "${job.op}" is disabled (set ${DIAGNOSTICS_ENV_VAR}=1 to enable).`);
  }

  // Pass the progress sink so the engine streams stage events to stdout as it runs.
  const result = await runSandboxJob(job, emitEvent);
  // Validate our OWN output before emitting, so a contract drift fails loudly here
  // rather than producing output the worker will reject.
  emitResult(sandboxResultSchema.parse(result));
}

main().catch((error: unknown) => {
  const message = error instanceof Error ? error.message : String(error);
  // Human-readable detail on stderr...
  process.stderr.write(`[sandbox-runtime] fatal: ${message}\n`);
  // ...and a machine-readable error envelope on stdout so the worker has structure.
  emitResult({ op: 'error', message });
  process.exitCode = 1;
});
