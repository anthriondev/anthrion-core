import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';

/**
 * Brand fonts for the PDF report (DESIGN_SYSTEM.md §3 + §9): Space Grotesk (display/UI)
 * and JetBrains Mono (scan IDs, evidence, registration labels).
 *
 * They are EMBEDDED as base64 `@font-face` blocks rather than relying on system fonts
 * (DESIGN_SYSTEM.md §9 forbids that) or a network fetch at render time: the worker may
 * run without egress, and an embedded font guarantees identical, on-brand output in the
 * PDF. The woff2 files come from the self-hosted `@fontsource/*` packages (worker deps),
 * matching how `apps/web` loads the same families via `next/font`.
 */

interface FontSource {
  pkg: string;
  file: string;
  family: string;
  weight: number;
}

// Weights mirror the design system usage: regular body, medium, bold display for the
// sans; regular + medium for the mono. Latin subset keeps the embedded payload small.
const FONT_SOURCES: readonly FontSource[] = [
  { pkg: '@fontsource/space-grotesk', file: 'space-grotesk-latin-400-normal.woff2', family: 'Space Grotesk', weight: 400 },
  { pkg: '@fontsource/space-grotesk', file: 'space-grotesk-latin-500-normal.woff2', family: 'Space Grotesk', weight: 500 },
  { pkg: '@fontsource/space-grotesk', file: 'space-grotesk-latin-700-normal.woff2', family: 'Space Grotesk', weight: 700 },
  { pkg: '@fontsource/jetbrains-mono', file: 'jetbrains-mono-latin-400-normal.woff2', family: 'JetBrains Mono', weight: 400 },
  { pkg: '@fontsource/jetbrains-mono', file: 'jetbrains-mono-latin-500-normal.woff2', family: 'JetBrains Mono', weight: 500 },
];

/** Resolve a font's `files/` directory by anchoring on its package.json — robust across
 * pnpm layouts and independent of which `exports` subpaths the resolver honours. */
function fontFilesDir(pkg: string): string {
  return join(dirname(require.resolve(`${pkg}/package.json`)), 'files');
}

let cachedCss: string | undefined;

/**
 * Build the `@font-face` CSS with the brand fonts embedded as base64 data URLs.
 * Memoised — the woff2 bytes never change at runtime, so they are read once.
 */
export function embeddedFontFaceCss(): string {
  if (cachedCss !== undefined) {
    return cachedCss;
  }
  const blocks = FONT_SOURCES.map((source) => {
    const bytes = readFileSync(join(fontFilesDir(source.pkg), source.file));
    const base64 = bytes.toString('base64');
    return [
      '@font-face {',
      `  font-family: '${source.family}';`,
      '  font-style: normal;',
      `  font-weight: ${source.weight};`,
      // `block` so glyphs never fall back to a system font mid-render (DESIGN_SYSTEM §9).
      '  font-display: block;',
      `  src: url(data:font/woff2;base64,${base64}) format('woff2');`,
      '}',
    ].join('\n');
  });
  cachedCss = blocks.join('\n');
  return cachedCss;
}
