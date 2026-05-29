import type { Config } from 'tailwindcss';

import {
  colors,
  fontFamily,
  motion,
  radius,
  severityColors,
  textColors,
  typography,
} from './tokens';

/**
 * Shared Tailwind preset (DESIGN_SYSTEM.md §9) — the single place the design tokens
 * become Tailwind theme values. `apps/web/tailwind.config.ts` lists this in `presets`
 * instead of redefining tokens, and `packages/ui` components style against it.
 *
 * Spacing is intentionally NOT redefined: Tailwind's default scale is already an 8px
 * base that realises the DESIGN_SYSTEM §4 scale (see tokens.ts `spacing`).
 */
export const anthrionPreset: Partial<Config> = {
  theme: {
    extend: {
      colors: {
        ...colors,
        text: textColors,
        severity: severityColors,
      },
      fontFamily: {
        sans: [...fontFamily.sans],
        mono: [...fontFamily.mono],
      },
      fontSize: {
        display: typography.display,
        h1: typography.h1,
        h2: typography.h2,
        h3: typography.h3,
        body: typography.body,
        small: typography.small,
        caption: typography.caption,
      },
      borderRadius: {
        xs: radius.xs,
        card: radius.card,
        panel: radius.panel,
      },
      transitionDuration: {
        fast: motion.duration.fast,
        base: motion.duration.base,
        slow: motion.duration.slow,
        section: motion.duration.section,
      },
      transitionTimingFunction: {
        out: motion.easing.out,
      },
      keyframes: {
        // Inner-hexagon rotation for the Mark — only meaningful states use it
        // (scan running / loading), per DESIGN_SYSTEM.md §6.
        'hex-spin': {
          from: { transform: 'rotate(0deg)' },
          to: { transform: 'rotate(360deg)' },
        },
        // Subtle "alive" pulse for the scan-progress live indicator.
        'live-pulse': {
          '0%, 100%': { opacity: '1' },
          '50%': { opacity: '0.35' },
        },
      },
      animation: {
        'hex-spin': 'hex-spin 8s linear infinite',
        'live-pulse': `live-pulse 1.4s ${motion.easing.out} infinite`,
      },
    },
  },
};

export default anthrionPreset;
