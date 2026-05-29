import { z } from 'zod';

import { findingCategorySchema } from './category';
import { severitySchema } from './severity';

/**
 * Evidence indicating a vulnerability. The shape is intentionally neutral so it
 * works for both AI scans (input = attack prompt, output = target response) and
 * web scans (input = request/payload, output = response). `metadata` is optional
 * for additional context (e.g. URL, status code, probe name).
 */
export const evidenceSchema = z.object({
  input: z.string(),
  output: z.string(),
  metadata: z.record(z.string(), z.string()).optional(),
});

export type Evidence = z.infer<typeof evidenceSchema>;

/**
 * Normalised finding structure (ARCHITECTURE.md §4.4). Consumed uniformly by
 * all consumers: worker → api → web → PDF. Zod-validated before leaving the
 * engine.
 */
export const findingSchema = z.object({
  id: z.string().min(1),
  severity: severitySchema,
  category: findingCategorySchema,
  title: z.string().min(1),
  description: z.string().min(1),
  evidence: evidenceSchema,
  recommendation: z.string().min(1),
});

export type Finding = z.infer<typeof findingSchema>;
