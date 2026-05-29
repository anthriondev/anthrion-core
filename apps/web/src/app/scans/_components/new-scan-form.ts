import { z } from 'zod';

import type { CreateScanRequest } from '@anthrion/shared/scan-api';

/**
 * Strict shape for the parsed spec document — used to validate at the client→server
 * trust boundary (`CLAUDE.md` §3 forbids `JSON.parse(x) as SomeType`). The server's
 * `scanJobApiSpecTargetSchema.document` is the same shape; this duplicates it locally
 * to avoid pulling the full shared schema into the browser bundle for a one-line
 * parse.
 */
const specDocumentSchema = z.record(z.string(), z.unknown());

/**
 * Pure form model + helpers for the create-scan screen. Kept separate from the React
 * component so the validation and payload-building logic is unit-testable without a DOM.
 * Mirrors `CreateScanRequest` (T4.3b): web-app-vuln (URL) | ai-llm-attack (endpoint or
 * pasted system prompt) | api-scan (raw single endpoint or pasted OpenAPI/Swagger spec).
 *
 * Note on api-scan spec mode (Phase 1.5 T-A1.4): the form accepts ONLY a JSON-shape
 * OpenAPI/Swagger document at v1. YAML support is deferred to a later sprint to avoid
 * pulling in a YAML parser; users with YAML specs can convert via `yq -o=json` or an
 * online tool. The server requires the document as a pre-parsed object (scan-job.ts
 * SSRF guard — SwaggerParser would interpret a raw string as a path/URL).
 */

export type ScanKind = 'web-app-vuln' | 'ai-llm-attack' | 'api-scan' | 'web3-dapp';
export type AiMode = 'endpoint' | 'system-prompt';
export type ApiMode = 'raw' | 'spec';
export type AuthMode = 'none' | 'bearer' | 'apiKey';

/** Web3 dApp scan inputs (Sprint A3, T-A3.8). NO private-key / mnemonic /
 * wallet-connect field by construction — the synthetic EIP-1193 provider
 * returns plausible fakes, the L3 channel is read-only RPC (sub-agent
 * rubric §10). The form has no place for a key, full stop. */
export type Web3Chain = 'ethereum' | 'base';
export type Web3WalletDepth = 'landing-page-only' | 'try-connect-button';

/**
 * Web scan mode (Phase 1.5 Sprint A2): single-page (the Phase 1 behavior) or crawl
 * (multi-page BFS from the seed). Crawl is purely additive: existing single-page
 * payloads continue to work, and the server applies engine defaults to any unset
 * crawl sub-field.
 */
export type WebScanMode = 'single' | 'crawl';

/**
 * Fixed crawl-budget defaults used by the UI (Phase 1.5 Sprint A2). Identical to
 * the engine defaults (`crawlBudgetSchema` in scan-engine/config.ts): max 10 pages,
 * depth 2, robots.txt respected. Kept fixed in v1 — exposing knobs widens the cost
 * surface and is deferred to Part B per the plan. Adjusting these values here would
 * widen scope, not the engine; the engine remains the source of truth for bounds.
 */
export const WEB_CRAWL_DEFAULT_MAX_PAGES = 10;
export const WEB_CRAWL_DEFAULT_MAX_DEPTH = 2;
export const WEB_CRAWL_DEFAULT_RESPECT_ROBOTS = true;

export interface NewScanFormState {
  scanKind: ScanKind;
  webUrl: string;
  /** Phase 1.5 Sprint A2: single-page (Phase 1) vs multi-page crawl. */
  webMode: WebScanMode;
  aiMode: AiMode;
  endpointUrl: string;
  endpointModel: string;
  authMode: AuthMode;
  authValue: string;
  authHeaderName: string;
  systemPrompt: string;
  // ── API scan (Phase 1.5 T-A1.4) ────────────────────────────────────────────
  apiMode: ApiMode;
  apiRawUrl: string;
  apiSpecDocument: string;
  apiSpecBaseUrl: string;
  // ── Web3 dApp scan (Phase 1.5 T-A3.8) ──────────────────────────────────────
  web3Url: string;
  web3Chain: Web3Chain;
  web3WalletDepth: Web3WalletDepth;
}

export const initialNewScanFormState: NewScanFormState = {
  scanKind: 'ai-llm-attack',
  webUrl: '',
  webMode: 'single',
  aiMode: 'endpoint',
  endpointUrl: '',
  endpointModel: '',
  authMode: 'none',
  authValue: '',
  authHeaderName: '',
  systemPrompt: '',
  apiMode: 'raw',
  apiRawUrl: '',
  apiSpecDocument: '',
  apiSpecBaseUrl: '',
  web3Url: '',
  web3Chain: 'ethereum',
  web3WalletDepth: 'try-connect-button',
};

export interface NewScanFormErrors {
  webUrl?: string;
  endpointUrl?: string;
  authValue?: string;
  systemPrompt?: string;
  apiRawUrl?: string;
  apiSpecDocument?: string;
  apiSpecBaseUrl?: string;
  web3Url?: string;
}

function isValidHttpUrl(value: string): boolean {
  let url: URL;
  try {
    url = new URL(value);
  } catch {
    return false;
  }
  return url.protocol === 'http:' || url.protocol === 'https:';
}

/** True iff `text` parses as a non-null JSON OBJECT (not an array or primitive). */
function isJsonObject(text: string): boolean {
  let parsed: unknown;
  try {
    parsed = JSON.parse(text);
  } catch {
    return false;
  }
  return parsed !== null && typeof parsed === 'object' && !Array.isArray(parsed);
}

/**
 * T-FIX.3: detect when the user pasted a URL (e.g. `https://petstore3.swagger.io/api/v3/openapi.json`)
 * into the spec textarea instead of the JSON content. A single-line `http(s)://…` value with no
 * `{` character is unmistakably a URL — auto-fetching by URL is a feature, not a defect fix
 * (deferred), so we surface a clear actionable message and block submit.
 */
function looksLikeBareUrl(text: string): boolean {
  const trimmed = text.trim();
  if (trimmed === '') return false;
  if (trimmed.includes('\n') || trimmed.includes('{')) return false;
  return /^https?:\/\/\S+$/i.test(trimmed);
}

/**
 * T-FIX.4: reject URLs that point at a spec FILE when the user means the API ROOT.
 * Concatenating a real endpoint path onto `.../openapi.json` yields absurd paths like
 * `/api/v3/openapi.json/pet`, so we block it with an inline message. The check is path-
 * suffix-based (the URL otherwise looks valid); non-suffix `.json`/`.yaml` segments
 * inside a path (e.g. a `/data.json/items` API) are extremely rare and would still
 * pass — the goal is catching the common copy-paste mistake, not every edge case.
 */
function looksLikeSpecFileUrl(url: string): boolean {
  let parsed: URL;
  try {
    parsed = new URL(url);
  } catch {
    return false;
  }
  return /\.(json|ya?ml)$/i.test(parsed.pathname);
}

/**
 * Client-side validation for fast feedback. The server remains the source of truth —
 * this only catches obvious mistakes before submit (CLAUDE.md §3: server re-validates).
 */
export function validateNewScanForm(state: NewScanFormState): NewScanFormErrors {
  const errors: NewScanFormErrors = {};

  if (state.scanKind === 'web-app-vuln') {
    if (state.webUrl.trim() === '') {
      errors.webUrl = 'Target URL is required';
    } else if (!isValidHttpUrl(state.webUrl.trim())) {
      errors.webUrl = 'Enter a valid http(s) URL';
    }
    return errors;
  }

  if (state.scanKind === 'web3-dapp') {
    if (state.web3Url.trim() === '') {
      errors.web3Url = 'dApp URL is required';
    } else if (!isValidHttpUrl(state.web3Url.trim())) {
      errors.web3Url = 'Enter a valid http(s) URL';
    }
    return errors;
  }

  if (state.scanKind === 'api-scan') {
    if (state.apiMode === 'raw') {
      if (state.apiRawUrl.trim() === '') {
        errors.apiRawUrl = 'Endpoint URL is required';
      } else if (!isValidHttpUrl(state.apiRawUrl.trim())) {
        errors.apiRawUrl = 'Enter a valid http(s) URL';
      }
    } else {
      if (state.apiSpecDocument.trim() === '') {
        errors.apiSpecDocument = 'OpenAPI/Swagger spec is required (JSON)';
      } else if (looksLikeBareUrl(state.apiSpecDocument)) {
        // T-FIX.3: a pasted URL was previously accepted as if it were spec
        // content, then the scan ran against meaningless input.
        errors.apiSpecDocument =
          'This looks like a URL, not a JSON document. Open the URL in your browser, copy the JSON content, and paste it here. (Fetching specs by URL is not supported in this release.)';
      } else if (!isJsonObject(state.apiSpecDocument)) {
        errors.apiSpecDocument =
          'Spec must be a valid JSON object. YAML is not supported in this release — convert with `yq -o=json` or an online tool.';
      }
      const baseUrl = state.apiSpecBaseUrl.trim();
      if (baseUrl !== '') {
        if (!isValidHttpUrl(baseUrl)) {
          errors.apiSpecBaseUrl = 'Enter a valid http(s) URL (or leave blank to use the spec)';
        } else if (looksLikeSpecFileUrl(baseUrl)) {
          // T-FIX.4: the spec-file URL pasted here produces nonsense request paths
          // (`/openapi.json/pet`); guide the user to the API root instead.
          errors.apiSpecBaseUrl =
            'Base URL should be the API root (e.g. `https://petstore3.swagger.io/api/v3`), not the URL of a spec file.';
        }
      }
    }
    if (state.authMode !== 'none' && state.authValue.trim() === '') {
      errors.authValue = 'Auth value is required for the selected auth mode';
    }
    return errors;
  }

  if (state.aiMode === 'endpoint') {
    if (state.endpointUrl.trim() === '') {
      errors.endpointUrl = 'Endpoint URL is required';
    } else if (!isValidHttpUrl(state.endpointUrl.trim())) {
      errors.endpointUrl = 'Enter a valid http(s) URL';
    }
    if (state.authMode !== 'none' && state.authValue.trim() === '') {
      errors.authValue = 'Auth value is required for the selected auth mode';
    }
    return errors;
  }

  if (state.systemPrompt.trim() === '') {
    errors.systemPrompt = 'System prompt is required';
  }
  return errors;
}

export function hasErrors(errors: NewScanFormErrors): boolean {
  return Object.keys(errors).length > 0;
}

/** Build the AI endpoint auth field (omitted entirely when authMode is 'none'). */
function buildAuthFields(
  state: NewScanFormState,
): { auth?: { type: 'bearer'; value: string } | { type: 'apiKey'; value: string; headerName?: string } } {
  if (state.authMode === 'bearer') {
    return { auth: { type: 'bearer', value: state.authValue.trim() } };
  }
  if (state.authMode === 'apiKey') {
    const headerName = state.authHeaderName.trim();
    return {
      auth: { type: 'apiKey', value: state.authValue.trim(), ...(headerName !== '' ? { headerName } : {}) },
    };
  }
  return {};
}

/**
 * Map the validated form into the `CreateScanRequest` wire shape (T4.3b, T-A1.4).
 * Caller MUST run `validateNewScanForm` first — for api-scan spec mode this function
 * trusts that `apiSpecDocument` is valid JSON-object text.
 */
export function buildCreateScanPayload(state: NewScanFormState): CreateScanRequest {
  if (state.scanKind === 'web-app-vuln') {
    // Phase 1.5 Sprint A2: crawl is purely additive — `crawl` is OMITTED for single-page
    // scans (preserves the Phase 1 payload exactly) and SET to the explicit defaults for
    // crawl scans so the server applies engine defaults without us hardcoding them inline.
    if (state.webMode === 'crawl') {
      return {
        scanType: 'web-app-vuln',
        target: { url: state.webUrl.trim() },
        crawl: {
          maxPages: WEB_CRAWL_DEFAULT_MAX_PAGES,
          maxDepth: WEB_CRAWL_DEFAULT_MAX_DEPTH,
          respectRobots: WEB_CRAWL_DEFAULT_RESPECT_ROBOTS,
        },
      };
    }
    return { scanType: 'web-app-vuln', target: { url: state.webUrl.trim() } };
  }
  if (state.scanKind === 'web3-dapp') {
    // Sprint A3 T-A3.8: URL + chain + optional walletInteractionDepth. NEVER
    // forward private-key / mnemonic / wallet-connect fields (the form has no
    // input for them — by construction, sub-agent rubric §10).
    return {
      scanType: 'web3-dapp',
      target: {
        url: state.web3Url.trim(),
        chain: state.web3Chain,
        walletInteractionDepth: state.web3WalletDepth,
      },
    };
  }
  if (state.scanKind === 'api-scan') {
    const auth = buildAuthFields(state);
    if (state.apiMode === 'raw') {
      return {
        scanType: 'api-scan',
        target: {
          kind: 'raw',
          url: state.apiRawUrl.trim(),
          ...auth,
        },
      };
    }
    // Spec mode: parse the pasted JSON document and Zod-validate the result before
    // putting it on the wire (`CLAUDE.md` §3 — never `JSON.parse(x) as SomeType`).
    // `validateNewScanForm` has already confirmed the text parses to an object, so
    // this throws only on a race / programmer error, not normal user input. The
    // server re-validates at its own trust boundary, and never feeds a raw string
    // to SwaggerParser (T-A1.1 SSRF guard).
    const document = specDocumentSchema.parse(JSON.parse(state.apiSpecDocument));
    const baseUrl = state.apiSpecBaseUrl.trim();
    return {
      scanType: 'api-scan',
      target: {
        kind: 'spec',
        document,
        ...(baseUrl !== '' ? { baseUrl } : {}),
        ...auth,
      },
    };
  }
  if (state.aiMode === 'system-prompt') {
    return { scanType: 'ai-llm-attack', target: { kind: 'system-prompt', prompt: state.systemPrompt } };
  }
  return {
    scanType: 'ai-llm-attack',
    target: {
      kind: 'endpoint',
      url: state.endpointUrl.trim(),
      ...(state.endpointModel.trim() !== '' ? { model: state.endpointModel.trim() } : {}),
      ...buildAuthFields(state),
    },
  };
}
