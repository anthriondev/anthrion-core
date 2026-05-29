/**
 * Brand wordmark + tagline (DESIGN_SYSTEM.md §2).
 *
 * Split out of `page.tsx` so the render contract (ANTHR + magenta ION span,
 * "GUIDING SYSTEMS, SAFELY" tagline) can be locked by a unit test that does
 * NOT transitively import the Privy SDK — see `page.test.tsx`. The mobile-
 * broken-render incident appeared as a visual regression of this component
 * (white bg, serif font, plain black wordmark, no magenta ION), even though
 * the source was correct; chunk-drift was the real cause. Keeping the
 * markup test-locked here means a future SOURCE regression cannot quietly
 * land while operations gets blamed.
 */
export function Wordmark(): React.ReactElement {
  return (
    <>
      <h1 style={{ fontSize: '2rem', fontWeight: 700, letterSpacing: '-0.02em' }}>
        ANTHR<span style={{ color: 'var(--color-magenta-core)' }}>ION</span>
      </h1>
      <p
        style={{
          color: 'var(--color-ice)',
          opacity: 0.6,
          letterSpacing: '0.15em',
          fontSize: '0.75rem',
        }}
      >
        GUIDING SYSTEMS, SAFELY
      </p>
    </>
  );
}
