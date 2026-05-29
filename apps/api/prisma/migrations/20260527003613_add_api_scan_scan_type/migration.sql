-- AlterEnum
-- Phase 1.5 Sprint A1 (T-A1.3): adds API_SCAN to the ScanType enum.
-- Additive, non-destructive — pre-existing rows retain their scanType
-- (AI_LLM_ATTACK / WEB_APP_VULN). Required before the worker can persist a
-- scan of type api-scan. Mirrors the engine-side `scanTypeSchema` widening
-- shipped in T-A1.1 (commit 4afce2a) and the wire types shipped in this task.
ALTER TYPE "ScanType" ADD VALUE 'API_SCAN';
