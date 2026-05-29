// Public contract of scan-engine (T2.1). This package is PURE — no HTTP/DB
// (ARCHITECTURE.md §2). No imports from apps/*.

export { severitySchema, SEVERITY_ORDER } from './severity';
export type { Severity } from './severity';

export {
  owaspLlmCategorySchema,
  owaspWebCategorySchema,
  owaspAgenticCategorySchema,
  owaspApiCategorySchema,
  owaspWeb3CategorySchema,
  findingCategorySchema,
} from './category';
export type {
  OwaspLlmCategory,
  OwaspWebCategory,
  OwaspAgenticCategory,
  OwaspApiCategory,
  OwaspWeb3Category,
  FindingCategory,
} from './category';

export { attackInputSchema, targetResponseSchema, TargetAdapterError } from './target';
export type { AttackInput, TargetResponse, ScanTarget } from './target';

export { evidenceSchema, findingSchema } from './finding';
export type { Evidence, Finding } from './finding';

export {
  scanTypeSchema,
  targetKindSchema,
  endpointAuthSchema,
  endpointTargetSpecSchema,
  systemPromptTargetSpecSchema,
  aiTargetSpecSchema,
  aiLlmAttackScanConfigSchema,
  webScanTimeoutsSchema,
  crawlBudgetSchema,
  webAppVulnScanConfigSchema,
  apiRawTargetSpecSchema,
  apiSpecTargetSpecSchema,
  apiTargetSpecSchema,
  apiScanConfigSchema,
  web3ChainSchema,
  web3WalletInteractionDepthSchema,
  web3ScanTimeoutsSchema,
  web3DappTargetSpecSchema,
  web3DappScanConfigSchema,
  scanConfigSchema,
  DEFAULT_WEB_NAVIGATION_TIMEOUT_MS,
  DEFAULT_WEB_PROBE_TIMEOUT_MS,
  DEFAULT_CRAWL_MAX_DEPTH,
  DEFAULT_CRAWL_MAX_PAGES,
  DEFAULT_CRAWL_RESPECT_ROBOTS,
  DEFAULT_API_REQUEST_TIMEOUT_MS,
  DEFAULT_API_BODY_CAPTURE_MAX_CHARS,
  DEFAULT_WEB3_WALLET_INTERACTION_DEPTH,
  DEFAULT_WEB3_L1_OBSERVATION_MS,
  DEFAULT_WEB3_CONNECT_CLICK_SETTLE_MS,
} from './config';
export type {
  ScanType,
  TargetKind,
  EndpointAuth,
  EndpointTargetSpec,
  SystemPromptTargetSpec,
  AiTargetSpec,
  WebScanTimeouts,
  CrawlBudget,
  WebAppVulnScanConfig,
  ApiRawTargetSpec,
  ApiSpecTargetSpec,
  ApiTargetSpec,
  ApiScanConfig,
  Web3Chain,
  Web3WalletInteractionDepth,
  Web3ScanTimeouts,
  Web3DappTargetSpec,
  Web3DappScanConfig,
  ScanConfig,
} from './config';

// --- API scan target adapter (Phase 1.5 Sprint A1, T-A1.1) ---

export {
  apiHttpMethodSchema,
  apiCoverageModeSchema,
  apiEndpointSchema,
  apiRequestSchema,
  apiResponseSchema,
  ApiTargetAdapterError,
} from './api-target';
export type {
  ApiHttpMethod,
  ApiCoverageMode,
  ApiEndpoint,
  ApiRequest,
  ApiResponse,
  ApiTarget,
} from './api-target';

export { ApiRawTargetAdapter } from './api-raw-adapter';
export { ApiSpecTargetAdapter } from './api-spec-adapter';

// --- API scan: coverage map, probes, runner (Phase 1.5 Sprint A1, T-A1.2) ---

export {
  API_COVERAGE_MAP,
  API_CATEGORY_SLUGS,
  apiCoverageFor,
  apiCategoriesByStatus,
} from './api-coverage';
export type { ApiCoverageStatus, ApiCoverageEntry } from './api-coverage';

export { buildEndpointUrl, tryRequest, NO_DETECTIONS } from './api-probe';
export type { ApiProbe, ApiDetection, RequestOutcome } from './api-probe';

export { API_PROBES } from './api-probes';

export {
  runApiScan,
  DEFAULT_API_PROBE_TIMEOUT_MS,
  DEFAULT_API_MAX_ENDPOINTS_PER_PROBE,
} from './api-scan';
export type {
  ApiProbeStatus,
  ApiProbeResult,
  ApiScanOutcome,
  ApiScanStats,
  ApiScanReport,
  RunApiScanOptions,
} from './api-scan';

export type { LlmCaller, LlmCompletionRequest } from './llm';

// --- Progress events (T4.2) ---

export {
  scanProgressPhaseSchema,
  scanProgressStatusSchema,
  scanProgressEventSchema,
  emitProgress,
} from './progress';
export type {
  ScanProgressPhase,
  ScanProgressStatus,
  ScanProgressEvent,
  ScanProgressCallback,
} from './progress';

export { EndpointTargetAdapter, DEFAULT_ENDPOINT_TIMEOUT_MS } from './endpoint-adapter';
export { SystemPromptTargetAdapter } from './system-prompt-adapter';

// --- Layer 1: static probes (T2.3) ---

export type { DetectionResult, ProbeDetector, StaticProbe } from './probe';

export {
  canaryDetector,
  patternDetector,
  instructionLeakDetector,
  credentialDetector,
  activeContentDetector,
  complianceDetector,
  CREDENTIAL_PATTERNS,
  CREDENTIAL_PLACEHOLDER_IGNORE,
  ACTIVE_CONTENT_PATTERNS,
} from './detectors';
export type { LabeledPattern } from './detectors';

export { LAYER1_PROBES, PROBE_CANARIES } from './probes';

export {
  LAYER1_COVERAGE_MAP,
  COVERED_CATEGORY_SLUGS,
  LAYER2_ATTACK_CATEGORIES,
  coverageFor,
  categoriesByTier,
} from './coverage';
export type {
  CoverageTier,
  CoverageTaxonomy,
  CoverageEntry,
  CoveredCategory,
} from './coverage';

export { runLayer1Probes } from './runner';
export type {
  Layer1Report,
  Layer1ProbeResult,
  Layer1Outcome,
  Layer1Stats,
  Layer1RunnerOptions,
  ProbeStatus,
} from './runner';

// --- LLM client via OpenRouter (T2.4) ---

export { TokenBudget, TokenBudgetExceededError } from './token-budget';

export {
  OpenRouterLlmClient,
  LlmError,
  openRouterClientConfigSchema,
  OPENROUTER_CHAT_COMPLETIONS_URL,
  DEFAULT_LLM_TIMEOUT_MS,
  DEFAULT_MAX_TOKENS_PER_CALL,
} from './llm-client';
export type {
  LlmTier,
  LlmUsage,
  LlmCompletionResult,
  OpenRouterClientConfig,
  OpenRouterCompletionRequest,
} from './llm-client';

// --- Layer 2: adaptive LLM attacker + safety guardrails (T2.5) ---

export { violatesRedLine, sanitizeForEvidence, EVIDENCE_SNIPPET_MAX } from './safety';
export type { RedLineCheck } from './safety';

export { runLayer2Attack, DEFAULT_MAX_ITERATIONS_PER_CATEGORY } from './layer2';
export type {
  Layer2Options,
  Layer2Report,
  Layer2CategoryResult,
  Layer2CategoryStatus,
  Layer2CategoryStopReason,
  Layer2StopReason,
} from './layer2';

export { runHybridAiScan } from './scan';
export type { HybridAiScanOptions, HybridAiScanReport } from './scan';

// --- Web app vulnerability scan: single-page DAST (T2.6) ---

export {
  WEB_COVERAGE_MAP,
  WEB_CATEGORY_SLUGS,
  webCoverageFor,
  webCategoriesByStatus,
} from './web-coverage';
export type { WebCoverageStatus, WebCoverageEntry } from './web-coverage';

export { pageResourceSchema, notDetected } from './web-probe';
export type {
  PageContext,
  PageResource,
  ObservedCookie,
  TlsSecurityDetails,
  WebProbe,
  WebDetection,
} from './web-probe';

export { PlaywrightPageContext, HTML_CAPTURE_MAX } from './web-page-context';

export { WEB_PROBES } from './web-probes';

export {
  scanSinglePage,
  runWebAppScan,
  ProbeTimeoutError,
  DEFAULT_LAUNCH_ARGS,
} from './web-scan';
export type {
  WebProbeStatus,
  WebProbeResult,
  WebScanOutcome,
  WebScanStats,
  WebPageScanResult,
  WaitUntil,
  ScanSinglePageOptions,
  RunWebAppScanOptions,
} from './web-scan';

// --- Multi-page crawl (Phase 1.5 Sprint A2) ---

export { RobotsTxt, fetchRobotsTxt } from './web-robots';

export {
  runWebAppCrawl,
  discoverLinks,
  resolveAndNormalize,
  isSameOrigin,
} from './web-crawl';
export type {
  CrawlStopReason,
  CrawlStats,
  CrawlScanResult,
  RunWebAppCrawlOptions,
} from './web-crawl';

// --- Web3 dApp scan (Phase 1.5 Sprint A3, T-A3.2) -----------------------------

export {
  contractAddressSchema,
  walletRequestMethodSchema,
  walletRequestSchema,
  referencedContractSchema,
  web3CaptureSchema,
  chainIdHex,
  chainIdDecimal,
} from './web3-types';
export type {
  ContractAddress,
  WalletRequest,
  ReferencedContract,
  Web3Capture,
} from './web3-types';

export {
  buildSyntheticProviderScript,
  SYNTHETIC_SCANNER_ADDRESS,
  SYNTHETIC_SIGNATURE,
  SYNTHETIC_TX_HASH,
  CAPTURE_GLOBAL_KEY,
} from './web3-provider-script';

export { harvestReferencedContracts } from './web3-address-harvest';

export {
  PlaywrightWeb3DAppTarget,
  readCapturedWalletRequests,
} from './web3-target';
export type { Web3DAppTarget, Web3CaptureResult } from './web3-target';

export {
  addressKindSchema,
  proxyContextSchema,
  adminRoleContextSchema,
  explorerMetadataSchema,
  contextAvailabilitySchema,
  onChainContextSchema,
} from './web3-onchain-context';
export type {
  AddressKind,
  ProxyContext,
  AdminRoleContext,
  ExplorerMetadata,
  ContextAvailability,
  OnChainContext,
  OnChainContextProvider,
} from './web3-onchain-context';

// --- Web3 L3 read clients + on-chain context loader (Phase 1.5 Sprint A3, T-A3.4) -

export {
  AlchemyRpcClient,
  Web3RpcError,
  decodeAddressFromStorage,
  ALCHEMY_RPC_BASE_URL_ETHEREUM,
  ALCHEMY_RPC_BASE_URL_BASE,
  DEFAULT_WEB3_RPC_TIMEOUT_MS,
  EIP1967_IMPLEMENTATION_SLOT,
  EIP1967_ADMIN_SLOT,
  EIP1967_BEACON_SLOT,
  ZERO_STORAGE_SLOT,
  SELECTOR_OWNER,
  SELECTOR_PENDING_OWNER,
} from './web3-rpc-client';
export type { AlchemyRpcClientConfig } from './web3-rpc-client';

export {
  EtherscanExplorerClient,
  Web3ExplorerError,
  ETHERSCAN_V2_API_BASE_URL,
  DEFAULT_WEB3_EXPLORER_TIMEOUT_MS,
  etherscanChainId,
} from './web3-explorer-client';
export type {
  EtherscanExplorerClientConfig,
  ExplorerSourceCode,
  ExplorerCreationRecord,
} from './web3-explorer-client';

export {
  RemoteOnChainContextProvider,
  sanitizeReason,
} from './web3-onchain-context-loader';
export type { RemoteOnChainContextProviderConfig } from './web3-onchain-context-loader';

// --- Web3 L1 probes + runner (Phase 1.5 Sprint A3, T-A3.3) --------------------

export {
  NO_L1_DETECTIONS,
  PERMIT2_CONTRACT_ADDRESS,
  MAX_UINT256_HEX_LOWER,
  MAX_UINT160_HEX_LOWER,
  SELECTOR_ERC20_APPROVE,
  SELECTOR_SET_APPROVAL_FOR_ALL,
  web3L1DetectionSchema,
} from './web3-l1-probe';
export type { Web3L1Probe, Web3L1Detection } from './web3-l1-probe';

export { WEB3_L1_PROBES } from './web3-l1-probes';

export {
  runWeb3Layer1,
  DEFAULT_WEB3_L1_PROBE_TIMEOUT_MS,
  WEB3_L1_NO_FLOW_COVERAGE_GAP_KIND,
} from './web3-l1';
export type {
  Web3L1ProbeStatus,
  Web3L1ProbeResult,
  Web3L1Outcome,
  Web3L1Stats,
  Web3L1Report,
  RunWeb3L1Options,
} from './web3-l1';

// --- Web3 L3 probes + runner (Phase 1.5 Sprint A3, T-A3.5) --------------------

export {
  NO_L3_DETECTIONS,
  DEFAULT_RECENT_DEPLOYMENT_MAX_AGE_SECONDS,
  STALE_DEPLOYMENT_AGE_SECONDS,
  WELL_KNOWN_TOKEN_REGISTRY,
  EVIDENCE_VALUE_MAX as WEB3_L3_EVIDENCE_VALUE_MAX,
  elevateOneTierCapHigh,
  maxSeverity,
  web3L3DetectionSchema,
} from './web3-l3-probe';
export type { Web3L3Probe, Web3L3Detection, WellKnownToken } from './web3-l3-probe';

export { WEB3_L3_PROBES } from './web3-l3-probes';

export {
  runWeb3Layer3,
  DEFAULT_WEB3_L3_PROBE_TIMEOUT_MS,
  WEB3_L3_NO_CONTEXT_COVERAGE_GAP_KIND,
  WEB3_L3_ELEVATED_RISK_CATEGORY,
  WEB3_L3_ELEVATED_RISK_ID_PREFIX,
} from './web3-l3';
export type {
  Web3L3ProbeStatus,
  Web3L3ProbeResult,
  Web3L3Outcome,
  Web3L3Stats,
  Web3L3AddressCoverageGap,
  Web3L3Report,
  RunWeb3L3Options,
} from './web3-l3';

// --- Web3 L2 probes + runner (Phase 1.5 Sprint A3, T-A3.6) --------------------

export {
  NO_L2_RESULT,
  KNOWN_BAD_DOMAIN_LIST,
  BUNDLE_DRIFT_KNOWN_CDN_HOSTS,
  EVIDENCE_VALUE_MAX as WEB3_L2_EVIDENCE_VALUE_MAX,
  l2SriEligible,
  safeParseUrl as web3L2SafeParseUrl,
  isCrossOriginResource as web3L2IsCrossOriginResource,
  sha256Hex as web3L2Sha256Hex,
  clipForEvidence as web3L2ClipForEvidence,
  web3L2DetectionSchema,
} from './web3-l2-probe';
export type {
  Web3L2Probe,
  Web3L2Detection,
  Web3L2CoverageNote,
  Web3L2EvaluationResult,
} from './web3-l2-probe';

export { WEB3_L2_PROBES } from './web3-l2-probes';

export {
  runWeb3Layer2,
  DEFAULT_WEB3_L2_PROBE_TIMEOUT_MS,
} from './web3-l2';
export type {
  Web3L2ProbeStatus,
  Web3L2ProbeResult,
  Web3L2Outcome,
  Web3L2Stats,
  Web3L2Report,
  RunWeb3L2Options,
} from './web3-l2';
