/**
 * ANTHRION design tokens — the SINGLE SOURCE of truth (DESIGN_SYSTEM.md §9).
 *
 * Every colour, type step, spacing value, radius and motion value lives here.
 * Two things consume this file:
 *   1. `tailwind-preset.ts` — turns these tokens into Tailwind theme values, so
 *      `apps/web` (and the components below) style with utility classes.
 *   2. `styles/tokens.css` — re-declares the brand colours as CSS variables for
 *      consumers that style outside Tailwind (the Sprint-1 auth pages use
 *      `var(--color-*)`). `tokens.test.ts` asserts that file stays in sync with
 *      the colours here, so there is still exactly one source.
 *
 * No hex/px values should be hardcoded in components — pull from Tailwind utilities
 * (which derive from this file) instead (DESIGN_SYSTEM.md §9).
 */

/** Locked brand palette (DESIGN_SYSTEM.md §2). Do not add colours without sign-off. */
export const colors = {
  /** Accent. Used sparingly — CTAs, a single keyword, active state. */
  'magenta-core': '#E0218A',
  /** Light accent — hover, small highlights. */
  'magenta-light': '#FF6CAE',
  /** Deep accent — pressed state, edge gradient. */
  'magenta-deep': '#B81C7D',
  /** Page background. */
  void: '#040406',
  /** Raised surface — cards, panels. */
  surface: '#0C0810',
  /** Lines, borders, dividers. */
  trace: '#241620',
  /** Primary text on dark. */
  ice: '#F4EEF2',
} as const;

/**
 * Derived text neutrals (DESIGN_SYSTEM.md §2): `ice` at decreasing opacity over
 * `void`. Expressed as rgba so Tailwind exposes them as `text-text-secondary` etc.
 */
export const textColors = {
  /** Primary text — ice 100%. */
  primary: '#F4EEF2',
  /** Secondary text — ice ~60%. */
  secondary: 'rgba(244, 238, 242, 0.6)',
  /** Muted text / captions — ice ~38%. */
  muted: 'rgba(244, 238, 242, 0.38)',
} as const;

/**
 * Semantic severity colours (DESIGN_SYSTEM.md §2 + §7).
 * ONLY for scan-result UI (reports/dashboard) — never the landing page.
 * Keys mirror the `FindingSeverity` enum (scan-engine, T3.4): Critical/High/Medium/Low/Info.
 */
export const severityColors = {
  critical: '#FF5470',
  high: '#FF8A4C',
  medium: '#FFC53D',
  low: '#4ED88A',
  info: '#6AB7FF',
} as const;

/**
 * Spacing scale — 8px base (DESIGN_SYSTEM.md §4). Exported as canonical named values
 * for non-Tailwind use. In Tailwind these map onto the default spacing scale
 * (2=8, 3=12, 4=16, 6=24, 8=32, 12=48, 16=64, 24=96, 32=128), which is already an
 * 8px base — so we don't override Tailwind's scale (see tailwind-preset.ts).
 */
export const spacing = {
  4: '4px',
  8: '8px',
  16: '16px',
  24: '24px',
  32: '32px',
  48: '48px',
  64: '64px',
  96: '96px',
  128: '128px',
} as const;

/** A type-scale step in Tailwind's `[fontSize, { lineHeight, letterSpacing }]` form. */
export type TypeStep = [size: string, config: { lineHeight: string; letterSpacing: string }];

export type TypeScaleName = 'display' | 'h1' | 'h2' | 'h3' | 'body' | 'small' | 'caption';

/**
 * Type scale (DESIGN_SYSTEM.md §3). Tight ratio, few steps, high contrast.
 * Mutable tuples (not `as const`) so they drop straight into the Tailwind preset.
 */
export const typography: Record<TypeScaleName, TypeStep> = {
  display: ['72px', { lineHeight: '1.05', letterSpacing: '-0.02em' }],
  h1: ['44px', { lineHeight: '1.1', letterSpacing: '-0.01em' }],
  h2: ['30px', { lineHeight: '1.15', letterSpacing: '-0.01em' }],
  h3: ['21px', { lineHeight: '1.25', letterSpacing: '0em' }],
  body: ['16px', { lineHeight: '1.6', letterSpacing: '0em' }],
  small: ['14px', { lineHeight: '1.5', letterSpacing: '0em' }],
  caption: ['12px', { lineHeight: '1.4', letterSpacing: '0.12em' }],
};

/**
 * Font families (DESIGN_SYSTEM.md §3). The actual fonts are loaded by `apps/web`
 * via `next/font` (Space Grotesk + JetBrains Mono), exposed as CSS variables; these
 * tokens reference those variables with safe fallbacks.
 */
export const fontFamily = {
  sans: ['var(--font-space-grotesk)', 'ui-sans-serif', 'system-ui', 'sans-serif'],
  mono: ['var(--font-jetbrains-mono)', 'ui-monospace', 'SFMono-Regular', 'monospace'],
} as const;

/** Radius (DESIGN_SYSTEM.md §4): small and consistent — no very-round corners. */
export const radius = {
  xs: '4px',
  /** Cards. */
  card: '8px',
  /** Large panels. */
  panel: '12px',
} as const;

/**
 * Motion (DESIGN_SYSTEM.md §6). Short durations, smooth ease-out, no bounce.
 * Micro-interactions 120–200ms; section/page transitions 200–400ms.
 */
export const motion = {
  duration: {
    fast: '120ms',
    base: '160ms',
    slow: '200ms',
    section: '320ms',
  },
  easing: {
    /** Smooth ease-out for entrances. No bounce, no elastic. */
    out: 'cubic-bezier(0.22, 1, 0.36, 1)',
  },
} as const;

export type BrandColor = keyof typeof colors;
export type SeverityColor = keyof typeof severityColors;
