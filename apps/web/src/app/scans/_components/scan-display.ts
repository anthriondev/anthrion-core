import type { ScanTypeWire } from '@anthrion/shared/scan-api';

/** Human label for a scan type (wire casing → display). */
export function scanTypeLabel(scanType: ScanTypeWire): string {
  if (scanType === 'ai-llm-attack') return 'AI / LLM attack scan';
  if (scanType === 'web-app-vuln') return 'Web app vulnerability scan';
  if (scanType === 'api-scan') return 'API security scan';
  return 'Web3 dApp scan';
}

/** Format an ISO timestamp for display, or em dash when absent/invalid. */
export function formatTimestamp(iso: string | null): string {
  if (iso === null) {
    return '—';
  }
  const date = new Date(iso);
  if (Number.isNaN(date.getTime())) {
    return '—';
  }
  return date.toLocaleString('en-GB', { dateStyle: 'medium', timeStyle: 'short' });
}

/**
 * Short description of a scan target. `targetKind` is only present on the detail
 * response (list summaries pass null); pasted system-prompt scans and api-scan
 * spec-mode scans without an explicit baseUrl carry no URL.
 */
export function targetSummary(targetUrl: string | null, targetKind: string | null): string {
  if (targetUrl !== null && targetUrl !== '') {
    // For api-spec we still annotate the mode alongside the URL so users see at a glance
    // the scan ran against a parsed OpenAPI document rather than a single raw endpoint.
    if (targetKind === 'api-spec') return `API (spec) · ${targetUrl}`;
    if (targetKind === 'api-raw') return `API · ${targetUrl}`;
    // Web3: targetKind carries chain as `web3-ethereum` / `web3-base` (set by api).
    if (targetKind === 'web3-ethereum') return `dApp (Ethereum) · ${targetUrl}`;
    if (targetKind === 'web3-base') return `dApp (Base) · ${targetUrl}`;
    return targetUrl;
  }
  if (targetKind === 'system-prompt') return 'Pasted system prompt';
  if (targetKind === 'api-spec') return 'API (OpenAPI / Swagger spec)';
  if (targetKind === 'api-raw') return 'API endpoint';
  if (targetKind === 'web3-ethereum' || targetKind === 'web3-base') return 'Web3 dApp';
  if (targetKind !== null && targetKind !== '') {
    return targetKind;
  }
  return '—';
}
