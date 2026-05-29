-- AlterEnum
-- Adds the REPORT_PDF artifact kind for the downloadable PDF security report (T6.1).
-- Additive only: extends the existing ArtifactType enum; no data is altered or dropped.
ALTER TYPE "ArtifactType" ADD VALUE 'REPORT_PDF';
