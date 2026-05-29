import { z } from 'zod';

import type { ScanType } from '@anthrion/db';
import type { CreateScanRequest } from '@anthrion/shared';

/**
 * Scan API DTOs (T4.1).
 *
 * The wire request/response SCHEMAS now live in `@anthrion/shared` (`scan-api.ts`) so
 * they are the single source of truth shared with `apps/web` (ARCHITECTURE.md §2 — the
 * cross-app contract home; `apps/web` and `apps/api` must not import each other). This
 * module re-exports them so existing call sites keep importing from `./scan.dto`, and
 * keeps the wire↔DB enum mapping here because it depends on `@anthrion/db` (which must
 * not leak into `shared`).
 */

export {
  createScanRequestSchema,
  createScanResponseSchema,
  scanDetailResponseSchema,
  scanListResponseSchema,
} from '@anthrion/shared';
export type {
  CreateScanRequest,
  CreateScanResponse,
  ScanDetailResponse,
  ScanListResponse,
} from '@anthrion/shared';

// ── Scan-type mapping (wire ↔ DB enum) ───────────────────────────────────────

export function toDbScanType(wire: CreateScanRequest['scanType']): ScanType {
  switch (wire) {
    case 'ai-llm-attack':
      return 'AI_LLM_ATTACK';
    case 'web-app-vuln':
      return 'WEB_APP_VULN';
    case 'api-scan':
      return 'API_SCAN';
    case 'web3-dapp':
      return 'WEB3_DAPP';
    default: {
      // Exhaustiveness guard (T-A1.5 hardening): adding a future scan type is a
      // compile error here instead of a silent misroute.
      const _exhaustive: never = wire;
      return _exhaustive;
    }
  }
}

export function toWireScanType(db: ScanType): CreateScanRequest['scanType'] {
  switch (db) {
    case 'AI_LLM_ATTACK':
      return 'ai-llm-attack';
    case 'WEB_APP_VULN':
      return 'web-app-vuln';
    case 'API_SCAN':
      return 'api-scan';
    case 'WEB3_DAPP':
      return 'web3-dapp';
    default: {
      const _exhaustive: never = db;
      return _exhaustive;
    }
  }
}

// ── Path params ──────────────────────────────────────────────────────────────

/** Validates the `:id` path param (T6.1 report download — CLAUDE.md §3: validate path
 * input with Zod). A cuid is a non-empty token; the ownership query rejects unknown ids. */
export const scanIdParamSchema = z.string().min(1, 'scan id is required');

/** MinIO object reference for a scan's report PDF (T6.1), returned to the controller. */
export interface ReportArtifactRef {
  bucket: string;
  objectKey: string;
  contentType: string;
  sizeBytes: number;
}
