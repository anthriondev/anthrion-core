/**
 * @anthrion/ui — the single source of the ANTHRION design system (DESIGN_SYSTEM.md §9):
 * tokens, the shared Tailwind preset, and the core React components (§7).
 *
 * The Tailwind preset is published separately at `@anthrion/ui/tailwind-preset` (used by
 * `apps/web/tailwind.config.ts`) so build-time config stays decoupled from the runtime
 * component surface re-exported here. The token CSS variables are at
 * `@anthrion/ui/styles/tokens.css`.
 */

// --- Tokens (single source) ---
export {
  colors,
  textColors,
  severityColors,
  spacing,
  typography,
  fontFamily,
  radius,
  motion,
} from './tokens';
export type { BrandColor, SeverityColor } from './tokens';

// --- Utilities ---
export { cn } from './cn';
export { SEVERITIES } from './severity';
export type { Severity } from './severity';

// --- Core components (DESIGN_SYSTEM.md §7) ---
export { Button, buttonClassName } from './components/Button';
export type { ButtonProps, ButtonVariant, ButtonSize, ButtonClassOptions } from './components/Button';

export { Card } from './components/Card';
export type { CardProps } from './components/Card';

export { Input, Field } from './components/Input';
export type { InputProps, FieldProps } from './components/Input';

export { Textarea } from './components/Textarea';
export type { TextareaProps } from './components/Textarea';

export { Badge } from './components/Badge';
export type { BadgeProps } from './components/Badge';

export { CodeBlock } from './components/CodeBlock';
export type { CodeBlockProps } from './components/CodeBlock';

export { ScanProgress } from './components/ScanProgress';
export type { ScanProgressProps } from './components/ScanProgress';

// --- Brand + signature details ---
export { Mark } from './components/Mark';
export type { MarkProps } from './components/Mark';

export { RegistrationMarks } from './components/RegistrationMarks';
export type { RegistrationMarksProps } from './components/RegistrationMarks';
