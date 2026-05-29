import { z } from 'zod';

import {
  freeTrialStatusResponseSchema,
  type FreeTrialStatusResponse,
} from '@anthrion/shared/payment-api';
import {
  createScanResponseSchema,
  scanDetailResponseSchema,
  scanListResponseSchema,
  type CreateScanRequest,
  type CreateScanResponse,
  type ScanDetailResponse,
  type ScanListResponse,
} from '@anthrion/shared/scan-api';
import {
  paymentRequiredResponseSchema,
  type PaymentRequiredResponse,
} from '@anthrion/shared/x402';

/**
 * Centralized scan API client for `apps/web` (T4.3b). Wraps every scan endpoint from
 * T4.1 (`POST /scans`, `GET /scans`, `GET /scans/:id`) so the screens built in T4.3c
 * call methods instead of hand-rolling `fetch` per component.
 *
 * Token & base URL flow FROM the caller (no Privy hook here — this works outside
 * React): the component passes `getToken` (Privy's `getAccessToken`) and `baseUrl`
 * (`clientEnv.NEXT_PUBLIC_API_URL`). Every response is validated with Zod — an API
 * response is external data (CLAUDE.md §3) — and every failure is returned as a typed
 * `ApiError`, never swallowed.
 */

export type ApiErrorKind =
  /** Server answered with a non-2xx status. */
  | 'http'
  /**
   * x402 HTTP 402: the server advertises `PaymentRequirements` (T5.2/T5.4). NOT a failure in
   * the protocol sense — the caller reads `paymentRequired` and (once paid scans are live) pays
   * + retries with `X-PAYMENT`. Surfaced as a distinct kind so the UI can show the requirements
   * honestly rather than as a generic error.
   */
  | 'payment-required'
  /**
   * HTTP 429: the server's rate limiter said the caller is over budget (T-FIX.8). Distinct
   * kind so the UI can render a styled, on-brand notice instead of leaking the NestJS
   * `ThrottlerException: Too Many Requests` class name.
   */
  | 'rate-limited'
  /** The request never produced a response (network failure, token provider threw). */
  | 'network'
  /** Server answered 2xx but the body was not valid JSON / failed schema validation. */
  | 'invalid-response';

export interface ApiError {
  kind: ApiErrorKind;
  /** HTTP status, or 0 for failures that never produced a response. */
  status: number;
  /** Human-readable message, safe to surface in the UI. */
  message: string;
  /**
   * Present ONLY when `kind === 'payment-required'`: the parsed x402 402 body the server sent
   * (the `accepts` payment options). The UI renders this to show what a paid scan would cost.
   */
  paymentRequired?: PaymentRequiredResponse;
  /**
   * Present ONLY when `kind === 'rate-limited'` and the server sent a parseable `Retry-After`
   * header (either `delta-seconds` or an HTTP date in the future). Surfaced so the UI can hint
   * "try again in N minutes". Absent for 429 responses without the header.
   */
  retryAfterSeconds?: number;
}

/** Discriminated result so callers MUST handle the failure branch (no thrown surprises). */
export type ApiResult<T> = { ok: true; data: T } | { ok: false; error: ApiError };

export interface ScanApiClientConfig {
  /** API base URL (caller supplies it, from `clientEnv.NEXT_PUBLIC_API_URL`). */
  baseUrl: string;
  /**
   * Access-token provider (caller injects Privy's `getAccessToken`). Returning
   * null/empty sends the request unauthenticated → the api answers 401, surfaced as a
   * normal `ApiError`.
   */
  getToken: () => Promise<string | null>;
}

export interface ScanApiClient {
  createScan(payload: CreateScanRequest): Promise<ApiResult<CreateScanResponse>>;
  listScans(): Promise<ApiResult<ScanListResponse>>;
  getScan(id: string): Promise<ApiResult<ScanDetailResponse>>;
  /** Free-trial availability for the current user's primary wallet (T5.4 Part 2). */
  getFreeTrialStatus(): Promise<ApiResult<FreeTrialStatusResponse>>;
  /** Download a scan's PDF security report as a blob (T6.1). 404 → not available. */
  downloadReportPdf(id: string): Promise<ApiResult<Blob>>;
}

/** NestJS error response shape (`{ statusCode, message, error }`) — parsed leniently. */
const errorBodySchema = z.object({
  statusCode: z.number().optional(),
  error: z.string().optional(),
  message: z.union([z.string(), z.array(z.string())]).optional(),
});

function describeError(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}

/**
 * Parse a 402 body into a validated `PaymentRequiredResponse`, or `undefined` if the body is
 * not a valid x402 402 (caller then falls back to a generic http error). Reads a CLONE so the
 * original response body stays available for that fallback. Never throws.
 */
async function readPaymentRequired(response: Response): Promise<PaymentRequiredResponse | undefined> {
  let body: unknown;
  try {
    body = await response.clone().json();
  } catch {
    return undefined;
  }
  const parsed = paymentRequiredResponseSchema.safeParse(body);
  return parsed.success ? parsed.data : undefined;
}

/**
 * Parse an HTTP `Retry-After` header into seconds-from-now (T-FIX.8). The header is
 * either a non-negative delta-seconds integer or an HTTP-date; both are valid per
 * RFC 9110 §10.2.3. Returns `undefined` for missing, malformed, or past-date values
 * so the UI can simply omit the "try again in N" hint when we have nothing reliable.
 */
function parseRetryAfter(value: string | null): number | undefined {
  if (value === null) return undefined;
  const trimmed = value.trim();
  if (trimmed === '') return undefined;
  if (/^\d+$/.test(trimmed)) {
    const seconds = Number.parseInt(trimmed, 10);
    return Number.isFinite(seconds) && seconds >= 0 ? seconds : undefined;
  }
  const dateMs = Date.parse(trimmed);
  if (Number.isNaN(dateMs)) return undefined;
  const deltaSeconds = Math.ceil((dateMs - Date.now()) / 1000);
  return deltaSeconds > 0 ? deltaSeconds : undefined;
}

async function readErrorMessage(response: Response): Promise<string> {
  const fallback = `Request failed with status ${response.status}`;
  let body: unknown;
  try {
    body = await response.json();
  } catch {
    return fallback;
  }
  const parsed = errorBodySchema.safeParse(body);
  if (!parsed.success) {
    return fallback;
  }
  const { message, error } = parsed.data;
  if (Array.isArray(message)) {
    return message.length > 0 ? message.join('; ') : fallback;
  }
  if (typeof message === 'string' && message.length > 0) {
    return message;
  }
  return error ?? fallback;
}

export function createScanApiClient(config: ScanApiClientConfig): ScanApiClient {
  async function request<T>(
    path: string,
    schema: z.ZodType<T>,
    init?: RequestInit,
  ): Promise<ApiResult<T>> {
    let token: string | null;
    try {
      token = await config.getToken();
    } catch (error) {
      return { ok: false, error: { kind: 'network', status: 0, message: `Failed to obtain access token: ${describeError(error)}` } };
    }

    const headers = new Headers(init?.headers);
    if (token !== null && token !== '') {
      headers.set('Authorization', `Bearer ${token}`);
    }

    let response: Response;
    try {
      response = await fetch(`${config.baseUrl}${path}`, { ...init, headers });
    } catch (error) {
      return { ok: false, error: { kind: 'network', status: 0, message: describeError(error) } };
    }

    if (!response.ok) {
      // x402: a 402 carries PaymentRequirements (the `accepts` options). Parse + surface them
      // honestly so the UI can show what a paid scan costs (T5.4 Part 3). `.clone()` so the body
      // can still be read as a plain error message if it is not a valid x402 402.
      if (response.status === 402) {
        const paymentRequired = await readPaymentRequired(response);
        if (paymentRequired !== undefined) {
          return {
            ok: false,
            error: {
              kind: 'payment-required',
              status: 402,
              message: paymentRequired.error ?? 'Payment is required to run this scan',
              paymentRequired,
            },
          };
        }
      }
      // T-FIX.8: 429 from the API throttler is a distinct kind so the UI can render an on-brand
      // notice. The server's JSON body otherwise carries `ThrottlerException: Too Many Requests`
      // — exposing that class name was the original B1 leak.
      if (response.status === 429) {
        const retryAfterSeconds = parseRetryAfter(response.headers.get('retry-after'));
        return {
          ok: false,
          error: {
            kind: 'rate-limited',
            status: 429,
            message: 'Scan rate limit reached. You can run up to 10 scans per hour. Please try again later.',
            ...(retryAfterSeconds !== undefined ? { retryAfterSeconds } : {}),
          },
        };
      }
      return { ok: false, error: { kind: 'http', status: response.status, message: await readErrorMessage(response) } };
    }

    let json: unknown;
    try {
      json = await response.json();
    } catch {
      return { ok: false, error: { kind: 'invalid-response', status: response.status, message: 'Response body was not valid JSON' } };
    }

    const parsed = schema.safeParse(json);
    if (!parsed.success) {
      // A 2xx with the wrong shape is a contract breach — surface it loudly (CLAUDE.md §3).
      console.error('API response failed schema validation', parsed.error.flatten());
      return { ok: false, error: { kind: 'invalid-response', status: response.status, message: 'Unexpected response shape from API' } };
    }
    return { ok: true, data: parsed.data };
  }

  /**
   * Fetch a binary artifact as a Blob (T6.1 report download). Separate from `request`,
   * which validates JSON bodies with Zod — a PDF is not JSON. Auth + error handling mirror
   * `request`: the bearer token is attached, non-2xx becomes a typed `ApiError` (404 →
   * `http` 404, surfaced by the UI as "report unavailable"), and nothing is swallowed.
   */
  async function downloadBlob(path: string): Promise<ApiResult<Blob>> {
    let token: string | null;
    try {
      token = await config.getToken();
    } catch (error) {
      return { ok: false, error: { kind: 'network', status: 0, message: `Failed to obtain access token: ${describeError(error)}` } };
    }

    const headers = new Headers();
    if (token !== null && token !== '') {
      headers.set('Authorization', `Bearer ${token}`);
    }

    let response: Response;
    try {
      response = await fetch(`${config.baseUrl}${path}`, { headers });
    } catch (error) {
      return { ok: false, error: { kind: 'network', status: 0, message: describeError(error) } };
    }

    if (!response.ok) {
      return { ok: false, error: { kind: 'http', status: response.status, message: await readErrorMessage(response) } };
    }

    let blob: Blob;
    try {
      blob = await response.blob();
    } catch {
      return { ok: false, error: { kind: 'invalid-response', status: response.status, message: 'Report body was not a readable file' } };
    }
    return { ok: true, data: blob };
  }

  return {
    createScan: (payload) =>
      request('/scans', createScanResponseSchema, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload),
      }),
    listScans: () => request('/scans', scanListResponseSchema),
    getScan: (id) => request(`/scans/${encodeURIComponent(id)}`, scanDetailResponseSchema),
    getFreeTrialStatus: () => request('/payments/free-trial', freeTrialStatusResponseSchema),
    downloadReportPdf: (id) => downloadBlob(`/scans/${encodeURIComponent(id)}/report`),
  };
}
