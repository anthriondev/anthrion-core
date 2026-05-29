/**
 * Token-only entry point for `@anthrion/ui` (DESIGN_SYSTEM.md §9).
 *
 * Re-exports the design tokens WITHOUT the React component surface, so non-React
 * consumers (notably `apps/worker`, which renders the PDF report HTML, T6.1) can pull
 * the single source of truth for colours / type / spacing without dragging React in
 * via the package barrel (`./src/index.ts` re-exports components that `import 'react'`).
 *
 * It lives at the package ROOT (not under `src/`) on purpose: `apps/worker` type-checks
 * with classic `node` module resolution (`module: commonjs`, no `exports` support), which
 * resolves `@anthrion/ui/tokens` to `<pkg>/tokens.ts`. The matching `./tokens` entry in
 * `package.json#exports` serves modern resolvers (web/api). Both reach the same tokens.
 */
export {
  colors,
  textColors,
  severityColors,
  spacing,
  typography,
  fontFamily,
  radius,
  motion,
} from './src/tokens';
export type { BrandColor, SeverityColor, TypeScaleName, TypeStep } from './src/tokens';
