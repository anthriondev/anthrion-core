import SwaggerParser from '@apidevtools/swagger-parser';
import { z } from 'zod';

import { performApiHttpRequest } from './api-fetch';
import {
  ApiTargetAdapterError,
  apiHttpMethodSchema,
  type ApiEndpoint,
  type ApiHttpMethod,
  type ApiRequest,
  type ApiResponse,
  type ApiTarget,
} from './api-target';
import {
  DEFAULT_API_BODY_CAPTURE_MAX_CHARS,
  DEFAULT_API_REQUEST_TIMEOUT_MS,
  type ApiSpecTargetSpec,
  type EndpointAuth,
} from './config';

/**
 * API target adapter (mode: `spec`) — built from a parsed OpenAPI / Swagger
 * document.
 *
 * Dereferences internal `$ref`s with `@apidevtools/swagger-parser` and
 * enumerates every operation under `paths` × {method} as an `ApiEndpoint`.
 * `coverage === 'spec'` so the report layer can mark this scan as having had
 * the full operation list available (vs raw mode's single endpoint).
 *
 * Security properties:
 *  - `resolve.external = false` is set on the parser — `$ref`s pointing to
 *    `http://...` or `file://...` are NOT followed. The parser only resolves
 *    internal `#/components/...` references. This prevents SSRF / arbitrary
 *    file read via a malicious user-uploaded spec.
 *  - The adapter accepts the spec as a pre-parsed object only. `SwaggerParser`
 *    treats a plain `string` as a path-or-URL; never let untrusted text reach
 *    that overload (the config schema enforces object form via
 *    `apiSpecTargetSpecSchema`).
 *  - Per-request mechanics (origin lock, timeout, body cap, redirect handling)
 *    are shared with raw mode via `performApiHttpRequest` so the two modes
 *    cannot drift apart on these properties.
 *
 * Construction is async because dereferencing is async — use the static
 * `create()` factory. The constructor is private to enforce that.
 */
export class ApiSpecTargetAdapter implements ApiTarget {
  readonly baseUrl: string;
  readonly coverage = 'spec' as const;

  private readonly endpointList: readonly ApiEndpoint[];
  private readonly auth: EndpointAuth | undefined;
  private readonly timeoutMs: number;
  private readonly bodyCaptureMaxChars: number;

  private constructor(
    baseUrl: string,
    endpointList: readonly ApiEndpoint[],
    auth: EndpointAuth | undefined,
    timeoutMs: number,
    bodyCaptureMaxChars: number,
  ) {
    this.baseUrl = baseUrl;
    this.endpointList = endpointList;
    this.auth = auth;
    this.timeoutMs = timeoutMs;
    this.bodyCaptureMaxChars = bodyCaptureMaxChars;
  }

  static async create(
    spec: ApiSpecTargetSpec,
    options: { timeoutMs?: number; bodyCaptureMaxChars?: number } = {},
  ): Promise<ApiSpecTargetAdapter> {
    // Clone before handing to SwaggerParser — dereference mutates the object
    // graph (replaces $ref nodes in place) and we must not mutate the caller's
    // input. `z.record(z.string(), z.unknown())` admits user-constructed
    // circular structures; `JSON.stringify` throws on those — translate to an
    // explicit adapter error instead of a generic unhandled rejection.
    let cloned: unknown;
    try {
      cloned = JSON.parse(JSON.stringify(spec.document));
    } catch (cause) {
      throw new ApiTargetAdapterError(
        'Spec document is not serialisable (likely contains a circular reference)',
        { cause },
      );
    }

    let dereferenced: unknown;
    try {
      // SSRF prevention: `resolve.external = false` blocks both `http` and
      // `file` resolvers. Only internal `#/...` refs are followed.
      dereferenced = await SwaggerParser.dereference(cloned as never, {
        resolve: { external: false },
      });
    } catch (cause) {
      const message =
        cause instanceof Error ? cause.message : 'unknown error';
      throw new ApiTargetAdapterError(
        `Failed to parse OpenAPI/Swagger spec: ${message}`,
        { cause },
      );
    }

    // The server URL declared in the spec may include a basePath (e.g.
    // `https://api.example.com/v1`). We split it into `origin` (used for the
    // origin lock + adapter.baseUrl) and `basePath` (prepended to every
    // operation's `pathTemplate` so probes get the FULL path from origin and
    // don't need to know about basePath separately).
    const { origin, basePath } = resolveServer(dereferenced, spec.baseUrl);
    const endpointList = extractEndpoints(dereferenced, basePath);
    if (endpointList.length === 0) {
      throw new ApiTargetAdapterError(
        'OpenAPI/Swagger spec contains no usable endpoints (no paths × methods)',
      );
    }

    return new ApiSpecTargetAdapter(
      origin,
      endpointList,
      spec.auth,
      options.timeoutMs ?? DEFAULT_API_REQUEST_TIMEOUT_MS,
      options.bodyCaptureMaxChars ?? DEFAULT_API_BODY_CAPTURE_MAX_CHARS,
    );
  }

  endpoints(): readonly ApiEndpoint[] {
    return this.endpointList;
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

// ── Internal helpers ────────────────────────────────────────────────────────

/** OpenAPI 3.x: derive origin + basePath from `servers[0].url`. */
const openApiV3ServersSchema = z.object({
  servers: z.array(z.object({ url: z.string() })).min(1),
});

/** Swagger 2.0: derive origin from `${schemes[0] ?? 'https'}://${host}`, basePath from `basePath`. */
const swaggerV2HostSchema = z.object({
  host: z.string().min(1),
  schemes: z.array(z.string().min(1)).min(1).optional(),
  basePath: z.string().optional(),
});

interface ResolvedServer {
  /** Origin only — used as the adapter's `baseUrl` and the origin lock. */
  origin: string;
  /** Path prefix (may be empty). Prepended to every operation's `pathTemplate`. */
  basePath: string;
}

function resolveServer(doc: unknown, override: string | undefined): ResolvedServer {
  if (override !== undefined) {
    const parsed = new URL(override);
    return { origin: parsed.origin, basePath: trimTrailingSlash(parsed.pathname) };
  }

  const v3 = openApiV3ServersSchema.safeParse(doc);
  if (v3.success) {
    const first = v3.data.servers[0];
    if (first !== undefined) {
      // Reject templated server URLs (e.g. `{scheme}://api/v{ver}`) — the spec
      // allows variables, but resolving them needs values we don't have here.
      // Honest failure with a clear pointer beats silently mis-targeting.
      if (first.url.includes('{')) {
        throw new ApiTargetAdapterError(
          `OpenAPI servers[0].url contains template variables ("${first.url}") — provide an explicit \`baseUrl\` instead`,
        );
      }
      // OpenAPI 3.0 explicitly allows `servers[0].url` to be a RELATIVE path
      // resolved against the spec's document location (e.g. Petstore uses
      // `"/api/v3"`). Without a Base URL we have no document location to resolve
      // against, so emit a friendly, actionable error instead of the cryptic
      // "not a valid absolute URL". The with-override branch above already
      // accepts a relative server URL by using the override as the resolution
      // origin — this branch is only reached when no override was provided.
      let parsed: URL;
      try {
        parsed = new URL(first.url);
      } catch {
        throw new ApiTargetAdapterError(
          `This spec uses a relative server URL ("${first.url}"). Provide a Base URL (e.g. "https://api.example.com") so the endpoints can be resolved.`,
        );
      }
      return { origin: parsed.origin, basePath: trimTrailingSlash(parsed.pathname) };
    }
  }

  const v2 = swaggerV2HostSchema.safeParse(doc);
  if (v2.success) {
    const scheme = v2.data.schemes?.[0] ?? 'https';
    return {
      origin: `${scheme}://${v2.data.host}`,
      basePath: trimTrailingSlash(v2.data.basePath ?? ''),
    };
  }

  throw new ApiTargetAdapterError(
    'Could not determine baseUrl from spec; provide `baseUrl` explicitly or add a `servers[0].url` (OpenAPI 3.x) or `host` (Swagger 2.0)',
  );
}

function trimTrailingSlash(path: string): string {
  if (path === '' || path === '/') return '';
  return path.endsWith('/') ? path.slice(0, -1) : path;
}

const pathsRecordSchema = z.record(
  z.string(),
  z.record(z.string(), z.unknown()),
);

const operationSchema = z
  .object({ operationId: z.string().optional() })
  .passthrough();

const docWithPathsSchema = z.object({ paths: pathsRecordSchema });

const HTTP_METHOD_LOOKUP: ReadonlyMap<string, ApiHttpMethod> = new Map(
  apiHttpMethodSchema.options.map((m) => [m.toLowerCase(), m]),
);

function extractEndpoints(doc: unknown, basePath: string): readonly ApiEndpoint[] {
  const parsed = docWithPathsSchema.safeParse(doc);
  if (!parsed.success) {
    return [];
  }

  const endpoints: ApiEndpoint[] = [];
  for (const [path, pathItem] of Object.entries(parsed.data.paths)) {
    for (const [key, opUnknown] of Object.entries(pathItem)) {
      const method = HTTP_METHOD_LOOKUP.get(key.toLowerCase());
      if (method === undefined) {
        continue;
      }
      const op = operationSchema.safeParse(opUnknown);
      if (!op.success) {
        continue;
      }
      endpoints.push({
        method,
        // Full path from origin: probes just use `baseUrl + pathTemplate` and
        // don't need to know about basePath separately. Empty basePath is the
        // common case (servers[0].url = bare origin / no v2 basePath).
        pathTemplate: `${basePath}${path}`,
        operationId: op.data.operationId ?? null,
      });
    }
  }
  return endpoints;
}
