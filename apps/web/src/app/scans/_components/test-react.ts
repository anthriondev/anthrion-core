// Test-only: provide a global `React`. `@anthrion/ui` is consumed as a workspace
// package (node_modules symlink), and tsx transpiles its JSX with the CLASSIC runtime,
// which references a global `React`; in-project files use the automatic runtime. Import
// this FIRST in any web test that renders an imported UI component. (Test-only — the
// real Next build uses the automatic runtime everywhere.)
import * as React from 'react';

(globalThis as typeof globalThis & { React?: unknown }).React = React;

export {};
