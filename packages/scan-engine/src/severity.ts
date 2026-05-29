import { z } from 'zod';

/**
 * Five-level qualitative severity scale (DESIGN_SYSTEM.md §7).
 * Critical is the most severe, Info is the least severe.
 */
export const severitySchema = z.enum(['Critical', 'High', 'Medium', 'Low', 'Info']);

export type Severity = z.infer<typeof severitySchema>;

/**
 * Severity order from most severe (index 0) to least severe.
 * Single source of truth for sorting findings in reports/UI.
 */
export const SEVERITY_ORDER: readonly Severity[] = [
  'Critical',
  'High',
  'Medium',
  'Low',
  'Info',
] as const;
