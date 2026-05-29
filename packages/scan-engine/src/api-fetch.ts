import type { EndpointAuth } from './config';
import {
  apiResponseSchema,
  ApiTargetAdapterError,
  type ApiRequest,
  type ApiResponse,
} from './api-target';

/**
 * Shared HTTP request mechanics for API target adapters (raw + spec).
 *
 * Both adapter modes need the same security-shaped fetch: origin-locked,
 * timeout covering connect + headers + body read, no auto-follow of redirects,
 * body length-capped, decoded into validated `ApiResponse`. Extracting this
 * here keeps adapter implementations thin and ensures the two modes cannot
 * drift apart on these properties.
 */

export interface PerformApiHttpRequestConfig {
  /** Origin the request URL MUST stay within. */
  readonly baseUrl: string;
  /** Optional adapter-level auth. Probe-provided headers take precedence. */
  readonly auth: EndpointAuth | undefined;
  /** Per-request timeout in ms (covers connect + headers + body read). */
  readonly timeoutMs: number;
  /** Captured response body cap, measured in characters of the decoded string. */
  readonly bodyCaptureMaxChars: number;
}

export async function performApiHttpRequest(
  config: PerformApiHttpRequestConfig,
  req: ApiRequest,
): Promise<ApiResponse> {
  let requestUrl: URL;
  try {
    requestUrl = new URL(req.url);
  } catch (cause) {
    throw new ApiTargetAdapterError(`Invalid request URL: ${req.url}`, { cause });
  }
  if (requestUrl.origin !== config.baseUrl) {
    throw new ApiTargetAdapterError(
      `Request URL origin "${requestUrl.origin}" does not match target baseUrl "${config.baseUrl}"`,
    );
  }

  const headers: Record<string, string> = {
    ...(req.headers ?? {}),
    ...buildAuthHeaders(config.auth, req.headers ?? {}),
  };

  const controller = new AbortController();
  let timedOut = false;
  const timer = setTimeout(() => {
    timedOut = true;
    controller.abort();
  }, config.timeoutMs);

  try {
    const init: RequestInit = {
      method: req.method,
      headers,
      signal: controller.signal,
      redirect: 'manual',
    };
    if (req.body !== undefined && methodAllowsBody(req.method)) {
      init.body = req.body;
    }

    let response: Response;
    try {
      response = await fetch(requestUrl, init);
    } catch (cause) {
      if (timedOut) {
        throw new ApiTargetAdapterError(
          `API request timed out after ${config.timeoutMs}ms`,
          { cause },
        );
      }
      throw new ApiTargetAdapterError('API request failed (network error)', { cause });
    }

    const responseHeaders: Record<string, string> = {};
    response.headers.forEach((value, key) => {
      responseHeaders[key.toLowerCase()] = value;
    });

    let text: string;
    try {
      text = await response.text();
    } catch (cause) {
      if (timedOut) {
        throw new ApiTargetAdapterError(
          `API response body read timed out after ${config.timeoutMs}ms`,
          { cause },
        );
      }
      throw new ApiTargetAdapterError('Failed to read API response body', { cause });
    }

    const bodyTruncated = text.length > config.bodyCaptureMaxChars;
    const body = bodyTruncated ? text.slice(0, config.bodyCaptureMaxChars) : text;

    return apiResponseSchema.parse({
      status: response.status,
      headers: responseHeaders,
      body,
      bodyTruncated,
    });
  } finally {
    clearTimeout(timer);
  }
}

/**
 * Build auth headers from the adapter's auth spec. If the probe already set
 * the relevant header, the probe's header wins — auth-tamper / BFLA probes
 * deliberately omit, override, or mutate the credential.
 *
 * Credential values never appear in error messages (CLAUDE.md §3).
 */
function buildAuthHeaders(
  auth: EndpointAuth | undefined,
  existingHeaders: Record<string, string>,
): Record<string, string> {
  if (auth === undefined) {
    return {};
  }
  const lowerCasedExisting = new Set(Object.keys(existingHeaders).map((k) => k.toLowerCase()));
  if (auth.type === 'bearer') {
    if (lowerCasedExisting.has('authorization')) {
      return {};
    }
    return { Authorization: `Bearer ${auth.value}` };
  }
  if (lowerCasedExisting.has(auth.headerName.toLowerCase())) {
    return {};
  }
  return { [auth.headerName]: auth.value };
}

/**
 * Whether the method conventionally allows a request body. GET / HEAD / OPTIONS
 * MUST NOT carry one per HTTP semantics, and `fetch` enforces that at the
 * platform level. We silently DROP a probe-supplied body for those methods
 * rather than throwing — preserves the "request goes through" contract; a probe
 * that needs GET-with-body for a non-conformant server should use POST/PUT/PATCH.
 */
function methodAllowsBody(method: ApiRequest['method']): boolean {
  return method !== 'GET' && method !== 'HEAD' && method !== 'OPTIONS';
}
