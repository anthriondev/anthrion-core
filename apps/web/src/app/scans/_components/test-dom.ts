// Test-only setup for jsdom + RTL component tests. Import this FIRST (before
// @testing-library/react) in any test that renders React into the DOM.
import './test-react';
import 'global-jsdom/register';

declare global {
  // Read by React to enable act() semantics in tests.
  var IS_REACT_ACT_ENVIRONMENT: boolean | undefined;
}

globalThis.IS_REACT_ACT_ENVIRONMENT = true;

export {};
