export { env } from './env';
export type { Env } from './env';

// --- BullMQ scan queue contract + producer (T3.1) ---

export {
  SCAN_QUEUE_NAME,
  SCAN_JOB_NAME,
  scanJobTypeSchema,
  scanJobEndpointAuthSchema,
  scanJobEndpointTargetSchema,
  scanJobSystemPromptTargetSchema,
  scanJobAiTargetSchema,
  scanJobApiRawTargetSchema,
  scanJobApiSpecTargetSchema,
  scanJobApiTargetSchema,
  scanJobCrawlBudgetSchema,
  scanJobPayloadSchema,
  parseScanJobPayload,
  DEFAULT_SCAN_JOB_OPTIONS,
} from './scan-job';
export type {
  ScanJobType,
  ScanJobEndpointAuth,
  ScanJobEndpointTarget,
  ScanJobSystemPromptTarget,
  ScanJobAiTarget,
  ScanJobApiRawTarget,
  ScanJobApiSpecTarget,
  ScanJobApiTarget,
  ScanJobCrawlBudget,
  ScanJobPayload,
} from './scan-job';

export { ScanQueueProducer } from './scan-queue-producer';

// --- Scan progress stream contract (T4.2) ---

export { scanProgressChannel, scanStreamEventSchema, parseScanStreamEvent } from './scan-stream';
export type { ScanStreamEvent, ScanStreamStageEvent, ScanStreamLifecycleEvent } from './scan-stream';

// --- Scan REST API wire contract (T4.1) ---

export {
  scanTypeWireSchema,
  scanStatusWireSchema,
  findingSeverityWireSchema,
  coverageGapKindSchema,
  coverageGapSchema,
  reportCoverageSchema,
  createScanRequestSchema,
  createScanResponseSchema,
  findingResponseSchema,
  scanDetailResponseSchema,
  scanSummaryResponseSchema,
  scanListResponseSchema,
} from './scan-api';
export type {
  ScanTypeWire,
  ScanStatusWire,
  FindingSeverityWire,
  CoverageGapKind,
  CoverageGap,
  ReportCoverage,
  CreateScanRequest,
  CreateScanResponse,
  FindingResponse,
  ScanDetailResponse,
  ScanSummaryResponse,
  ScanListResponse,
} from './scan-api';

// --- Payment-status wire contract (T5.4) ---

export {
  paymentKindWireSchema,
  paymentStatusWireSchema,
  scanPaymentInfoSchema,
  freeTrialStatusSchema,
  freeTrialStatusResponseSchema,
} from './payment-api';
export type {
  PaymentKindWire,
  PaymentStatusWire,
  ScanPaymentInfo,
  FreeTrialStatus,
  FreeTrialStatusResponse,
} from './payment-api';

// --- x402 payment wire contract (T5.1) ---

export {
  X402_VERSION,
  x402SchemeSchema,
  x402NetworkSchema,
  exactEvmAuthorizationSchema,
  exactEvmPayloadSchema,
  paymentPayloadSchema,
  paymentRequirementsSchema,
  paymentRequiredResponseSchema,
  verifyResponseSchema,
  settleResponseSchema,
  parsePaymentHeader,
} from './x402';
export type {
  X402Scheme,
  X402Network,
  ExactEvmAuthorization,
  ExactEvmPayload,
  PaymentPayload,
  PaymentRequirements,
  PaymentRequiredResponse,
  VerifyResponse,
  SettleResponse,
} from './x402';
