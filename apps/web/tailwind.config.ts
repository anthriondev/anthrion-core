import { anthrionPreset } from '@anthrion/ui/tailwind-preset';
import type { Config } from 'tailwindcss';

/**
 * apps/web pulls ALL design tokens from the shared preset in `@anthrion/ui`
 * (DESIGN_SYSTEM.md §9) — it does not define tokens of its own. The content globs
 * include the UI package source so Tailwind generates the utility classes used by
 * `@anthrion/ui` components.
 */
const config: Config = {
  content: ['./src/**/*.{ts,tsx}', '../../packages/ui/src/**/*.{ts,tsx}'],
  presets: [anthrionPreset],
};

export default config;
