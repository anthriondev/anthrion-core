// Public surface of @anthrion/sandbox-runtime.
//
// Only the wire CONTRACT is exported here, so that importing this package on the
// host (the worker, to build job input and validate result output) stays cheap and
// side-effect free. The in-container execution code (`run.ts`, which pulls in
// Playwright) and the entrypoint (`entry.ts`, which reads stdin) are NOT exported —
// they run only inside the sandbox container, invoked as `node dist/entry.js`.

export {
  RESULT_LINE_PREFIX,
  EVENT_LINE_PREFIX,
  DIAGNOSTICS_ENV_VAR,
  DIAGNOSTIC_OPS,
  sandboxJobSchema,
  netcheckTargetSchema,
  sandboxLlmConfigSchema,
  sandboxResultSchema,
  scanReportSchema,
  chromiumStatusSchema,
  parseSandboxResult,
} from './contract';
export type {
  SandboxJob,
  SandboxResult,
  SelftestResult,
  NetcheckResult,
  ScanResult,
  ScanReport,
  AiScanReport,
  WebScanReport,
  ApiScanReport,
  Web3DappScanReport,
  NetcheckTarget,
  SandboxLlmConfig,
  SandboxWeb3Config,
  ChromiumStatus,
} from './contract';
