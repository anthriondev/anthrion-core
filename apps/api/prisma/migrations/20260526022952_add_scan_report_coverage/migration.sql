-- AlterTable
-- Adds the per-scan report coverage summary (T6.2). Additive nullable JSONB column —
-- non-destructive; pre-existing rows stay NULL (the UI treats null as neutral, never as
-- a claim of completeness). Worker writes it at the same time it records the REPORT_PDF
-- artifact so the UI and the PDF share one source of truth.
ALTER TABLE "Scan" ADD COLUMN "reportCoverage" JSONB;
