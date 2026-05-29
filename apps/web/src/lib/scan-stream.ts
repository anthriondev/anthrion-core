import { scanStreamEventSchema, type ScanStreamEvent } from '@anthrion/shared/scan-stream';

/**
 * SSE consumer for scan progress (T4.3b). Connects to `GET /scans/:id/stream` (T4.2)
 * and yields validated `ScanStreamEvent`s.
 *
 * Why fetch + ReadableStream instead of `EventSource`: the SSE endpoint is behind
 * `AuthGuard`, so it needs an `Authorization: Bearer <token>` header. Native
 * `EventSource` cannot set custom headers, so we open the stream with `fetch()` (which
 * can), read the `ReadableStream` body, and parse `text/event-stream` by hand. (This is
 * a deliberate decision — the api is NOT changed to accept a query-param/cookie token.)
 *
 * Token & base URL flow FROM the caller (no Privy hook here). Each event is validated
 * with Zod — a network event is external data (CLAUDE.md §3); invalid events are
 * reported via `onError` and skipped, never forwarded raw.
 *
 * T4.3c BOUNDARY: this module is the utility only. Wiring it into the React
 * `ScanProgress` component on a real screen — opening it in a `useEffect`, pushing
 * `onEvent` into state, and calling `controller.abort()` on unmount — is T4.3c.
 */

/**
 * Minimal WHATWG `text/event-stream` parser. Feed it decoded text chunks; it buffers
 * across chunk boundaries (so an event split mid-stream is handled) and invokes
 * `onData` once per complete event with that event's `data` payload (multiple `data:`
 * lines joined by `\n`, per spec). Comments (`:`…) and non-`data` fields (`event`/`id`/
 * `retry`) are ignored — the api emits one JSON object per event as `data:` lines.
 */
export class EventStreamParser {
  private buffer = '';
  private dataLines: string[] = [];

  constructor(private readonly onData: (data: string) => void) {}

  feed(chunk: string): void {
    this.buffer += chunk;
    let newlineIndex = this.buffer.indexOf('\n');
    while (newlineIndex !== -1) {
      let line = this.buffer.slice(0, newlineIndex);
      this.buffer = this.buffer.slice(newlineIndex + 1);
      if (line.endsWith('\r')) {
        line = line.slice(0, -1); // tolerate CRLF line endings
      }
      this.handleLine(line);
      newlineIndex = this.buffer.indexOf('\n');
    }
  }

  private handleLine(line: string): void {
    if (line === '') {
      this.dispatch(); // blank line terminates an event
      return;
    }
    if (line.startsWith(':')) {
      return; // comment line
    }
    const colon = line.indexOf(':');
    const field = colon === -1 ? line : line.slice(0, colon);
    let value = colon === -1 ? '' : line.slice(colon + 1);
    if (value.startsWith(' ')) {
      value = value.slice(1); // strip one leading space after the colon (spec)
    }
    if (field === 'data') {
      this.dataLines.push(value);
    }
  }

  private dispatch(): void {
    if (this.dataLines.length === 0) {
      return; // blank line without any data → nothing to dispatch
    }
    const data = this.dataLines.join('\n');
    this.dataLines = [];
    this.onData(data);
  }
}

export type ScanStreamErrorKind =
  /** The stream request answered with a non-2xx status. */
  | 'http'
  /** Network failure / token provider threw / no response body. */
  | 'network'
  /** A received event was not valid JSON or failed `ScanStreamEvent` validation. */
  | 'invalid-event';

export interface ScanStreamError {
  kind: ScanStreamErrorKind;
  /** HTTP status, or 0 when no response was produced. */
  status: number;
  message: string;
}

export interface ConsumeScanStreamOptions {
  /** API base URL (caller supplies it, from `clientEnv.NEXT_PUBLIC_API_URL`). */
  baseUrl: string;
  scanId: string;
  /** Access-token provider (caller injects Privy's `getAccessToken`). */
  getToken: () => Promise<string | null>;
  /** Called once per valid event, in order. */
  onEvent: (event: ScanStreamEvent) => void;
  /** Called for a non-2xx status, a network failure, or an invalid event (then skipped). */
  onError?: (error: ScanStreamError) => void;
  /** Called once when the stream ends — server-closed (terminal DONE/FAILED) or aborted. */
  onClose?: () => void;
  /** Abort to cancel the stream (e.g. on React unmount). */
  signal?: AbortSignal;
}

function describeError(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}

function isAbortError(error: unknown): boolean {
  if (typeof error === 'object' && error !== null && 'name' in error) {
    return error.name === 'AbortError';
  }
  return false;
}

/**
 * Open the SSE stream and pump validated events to the callbacks. Resolves when the
 * stream ends (server close or abort). The api completes the stream on a terminal
 * lifecycle event (DONE/FAILED) by closing the connection, which ends the read loop and
 * fires `onClose`; the terminal event itself arrives via `onEvent` just before.
 */
export async function consumeScanStream(options: ConsumeScanStreamOptions): Promise<void> {
  const { baseUrl, scanId, getToken, onEvent, onError, onClose, signal } = options;

  let token: string | null;
  try {
    token = await getToken();
  } catch (error) {
    onError?.({ kind: 'network', status: 0, message: `Failed to obtain access token: ${describeError(error)}` });
    return;
  }

  const headers = new Headers({ Accept: 'text/event-stream' });
  if (token !== null && token !== '') {
    headers.set('Authorization', `Bearer ${token}`);
  }

  // Build init conditionally: with exactOptionalPropertyTypes, `signal` must be omitted
  // when undefined (RequestInit.signal is AbortSignal | null, not undefined).
  const requestInit: RequestInit = { method: 'GET', headers };
  if (signal !== undefined) {
    requestInit.signal = signal;
  }

  let response: Response;
  try {
    response = await fetch(`${baseUrl}/scans/${encodeURIComponent(scanId)}/stream`, requestInit);
  } catch (error) {
    if (isAbortError(error)) {
      onClose?.();
      return;
    }
    onError?.({ kind: 'network', status: 0, message: describeError(error) });
    return;
  }

  if (!response.ok) {
    onError?.({ kind: 'http', status: response.status, message: `Stream request failed with status ${response.status}` });
    return;
  }
  if (response.body === null) {
    onError?.({ kind: 'network', status: response.status, message: 'Stream response had no body' });
    return;
  }

  const parser = new EventStreamParser((data) => {
    let json: unknown;
    try {
      json = JSON.parse(data);
    } catch {
      onError?.({ kind: 'invalid-event', status: response.status, message: 'SSE event was not valid JSON' });
      return;
    }
    const parsed = scanStreamEventSchema.safeParse(json);
    if (!parsed.success) {
      onError?.({ kind: 'invalid-event', status: response.status, message: 'SSE event failed schema validation' });
      return;
    }
    onEvent(parsed.data);
  });

  const decoder = new TextDecoder();
  const reader = response.body.getReader();
  try {
    for (;;) {
      const { done, value } = await reader.read();
      if (done) {
        break;
      }
      parser.feed(decoder.decode(value, { stream: true }));
    }
    parser.feed(decoder.decode()); // flush any buffered bytes
    onClose?.();
  } catch (error) {
    if (isAbortError(error)) {
      onClose?.();
      return;
    }
    onError?.({ kind: 'network', status: response.status, message: describeError(error) });
  } finally {
    reader.releaseLock();
  }
}
