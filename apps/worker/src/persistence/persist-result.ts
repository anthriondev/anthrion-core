import type { ScanRunResult } from '../scan-runner';
import type { ArtifactStore } from '../storage/artifact-store';

import type { ScanResultStore } from './scan-repository';

/**
 * Persist a `ScanRunResult` (T3.4, Part C). The scan status + findings are the
 * authoritative result and are written FIRST; the MinIO transcript artifact is
 * archival and written after.
 */
export interface PersistDeps {
  store: ScanResultStore;
  artifacts: ArtifactStore;
}

export async function persistScanResult(deps: PersistDeps, result: ScanRunResult): Promise<void> {
  // 1) Authoritative result → Postgres.
  if (result.status === 'succeeded') {
    await deps.store.saveSucceeded(result.scanId, result.findings);
  } else {
    await deps.store.saveFailed(result.scanId, result.reason, result.message);
  }

  // 2) Archival transcript → MinIO (both paths: success findings or failure record).
  //
  // Artifact-upload failure handling (Part B): the authoritative result already stands,
  // so a blob-storage hiccup must NOT undo it — but it also must NOT be silent. We log
  // it explicitly (CLAUDE.md §3: no swallowed errors) and leave no dangling Artifact
  // row. The scan stays DONE/FAILED; the missing transcript is visible via this error.
  try {
    const ref = await deps.artifacts.uploadScanLog(result.scanId, JSON.stringify(result));
    await deps.store.addArtifact(result.scanId, 'SCAN_LOG', ref);
  } catch (cause) {
    const message = cause instanceof Error ? cause.message : String(cause);
    console.error(`[worker] artifact upload failed for scan ${result.scanId} — result persisted without it: ${message}`);
  }
}
