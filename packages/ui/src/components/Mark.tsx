import type { ReactElement } from 'react';

import { cn } from '../cn';
import { colors } from '../tokens';

export interface MarkProps {
  /** Rendered width/height in px (square). Default 32. */
  size?: number;
  /**
   * Rotate the inner hexagon slowly. Per DESIGN_SYSTEM.md §6 this is only for
   * meaningful states (scan running / loading) — not constant decoration. Honours
   * `prefers-reduced-motion` (rotation is disabled via `motion-reduce:animate-none`).
   */
  spinning?: boolean;
  /** Accessible label. When omitted the mark is decorative (`aria-hidden`). */
  title?: string;
  className?: string;
}

/**
 * ANTHRION brand mark — the "Nested Hex" (DESIGN_SYSTEM.md §1): an upright outer
 * hexagon, an inner hexagon rotated 30°, and a solid circular core with a soft
 * top-left highlight. Thin sharp strokes, no glow.
 *
 * This is a tokenized inline SVG (colours pulled from `tokens.ts`) so it scales, can
 * theme, and can animate for the scan live-state. The canonical brand FILES
 * (`anthrion-mark.svg`, lockup, wordmark, icons) live in `/brand` and are served by
 * `apps/web` from `/public/brand` — those embed the wordmark font and are for
 * favicons / OG / print, not for inlining into the component bundle.
 */
export function Mark({ size = 32, spinning = false, title, className }: MarkProps): ReactElement {
  const decorative = title === undefined;

  return (
    <svg
      width={size}
      height={size}
      viewBox="0 0 48 48"
      fill="none"
      xmlns="http://www.w3.org/2000/svg"
      className={cn('shrink-0', className)}
      role={decorative ? undefined : 'img'}
      aria-hidden={decorative ? true : undefined}
      aria-label={title}
    >
      {title !== undefined ? <title>{title}</title> : null}
      <defs>
        <linearGradient id="anthrion-mark-stroke" x1="24" y1="2" x2="24" y2="46" gradientUnits="userSpaceOnUse">
          <stop stopColor={colors['magenta-light']} />
          <stop offset="1" stopColor={colors['magenta-deep']} />
        </linearGradient>
        <radialGradient
          id="anthrion-mark-core"
          cx="0.4"
          cy="0.35"
          r="0.75"
        >
          <stop stopColor={colors['magenta-light']} />
          <stop offset="0.55" stopColor={colors['magenta-core']} />
          <stop offset="1" stopColor={colors['magenta-deep']} />
        </radialGradient>
      </defs>

      {/* Outer hexagon — pointy-top, upright. */}
      <polygon
        points="24,3 42.19,13.5 42.19,34.5 24,45 5.81,34.5 5.81,13.5"
        stroke="url(#anthrion-mark-stroke)"
        strokeWidth={2}
        strokeLinejoin="round"
      />

      {/* Inner hexagon — flat-top (rotated 30° vs outer). Spins on meaningful state. */}
      <g
        className={
          spinning
            ? 'origin-center animate-hex-spin motion-reduce:animate-none [transform-box:fill-box]'
            : undefined
        }
      >
        <polygon
          points="36,24 30,13.61 18,13.61 12,24 18,34.39 30,34.39"
          stroke="url(#anthrion-mark-stroke)"
          strokeWidth={1.8}
          strokeLinejoin="round"
        />
      </g>

      {/* Solid circular core with soft top-left highlight. */}
      <circle cx="24" cy="24" r="4.6" fill="url(#anthrion-mark-core)" />
      <circle cx="22.4" cy="22.4" r="1.3" fill="#FFFFFF" fillOpacity={0.65} />
    </svg>
  );
}
