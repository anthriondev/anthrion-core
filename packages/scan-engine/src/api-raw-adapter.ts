import {
  DEFAULT_API_BODY_CAPTURE_MAX_CHARS,
  DEFAULT_API_REQUEST_TIMEOUT_MS,
  type ApiRawTargetSpec,
  type EndpointAuth,
} from './config';
import { performApiHttpRequest } from './api-fetch';
import type {
  ApiEndpoint,
  ApiRequest,
  ApiResponse,
  ApiTarget,
} from './api-target';

/**
 * API target adapter (mode: `raw`) — single endpoint, no spec.
 *
 * The user provides one URL (and optionally HTTP method + auth). The adapter
 * extracts the origin as `baseUrl` and exposes that one endpoint via
 * `endpoints()`. Probes operate within this origin (`performApiHttpRequest`
 * rejects requests to a different host) so a probe cannot accidentally drive
 * traffic off-target.
 *
 * `coverage === 'raw'` is the honest signal that endpoint enumeration is
 * shallow — the probe / report layer marks results accordingly (Phase 1.5 plan,
 * Phase 1 honesty rule). The shared HTTP mechanics (origin lock, no-redirect,
 * timeout-with-body-read, body cap, credential safety) live in `api-fetch.ts`
 * so the raw and spec adapters cannot drift apart.
 */
export class ApiRawTargetAdapter implements ApiTarget {
  readonly baseUrl: string;
  readonly coverage = 'raw' as const;

  private readonly singleEndpoint: ApiEndpoint;
  private readonly auth: EndpointAuth | undefined;
  private readonly timeoutMs: number;
  private readonly bodyCaptureMaxChars: number;

  constructor(
    spec: ApiRawTargetSpec,
    options: { timeoutMs?: number; bodyCaptureMaxChars?: number } = {},
  ) {
    const parsed = new URL(spec.url);
    this.baseUrl = parsed.origin;
    this.singleEndpoint = {
      method: spec.method,
      pathTemplate: parsed.pathname === '' ? '/' : parsed.pathname,
      operationId: null,
    };
    this.auth = spec.auth;
    this.timeoutMs = options.timeoutMs ?? DEFAULT_API_REQUEST_TIMEOUT_MS;
    this.bodyCaptureMaxChars = options.bodyCaptureMaxChars ?? DEFAULT_API_BODY_CAPTURE_MAX_CHARS;
  }

  endpoints(): readonly ApiEndpoint[] {
    return [this.singleEndpoint];
  }

  request(req: ApiRequest): Promise<ApiResponse> {
    return performApiHttpRequest(
      {
        baseUrl: this.baseUrl,
        auth: this.auth,
        timeoutMs: this.timeoutMs,
        bodyCaptureMaxChars: this.bodyCaptureMaxChars,
      },
      req,
    );
  }
}
