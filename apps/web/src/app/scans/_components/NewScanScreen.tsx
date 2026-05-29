'use client';

import Link from 'next/link';
import { useState, type FormEvent } from 'react';

import type { PaymentRequiredResponse } from '@anthrion/shared/x402';
import { Button, buttonClassName, Card, Field, Input, Textarea } from '@anthrion/ui';

import type { ApiError, ScanApiClient } from '../../../lib/api-client';

import { PageShell } from './PageShell';
import { PaymentRequirementsNotice } from './PaymentRequirementsNotice';
import { Segmented } from './Segmented';
import {
  buildCreateScanPayload,
  hasErrors,
  initialNewScanFormState,
  validateNewScanForm,
  WEB_CRAWL_DEFAULT_MAX_DEPTH,
  WEB_CRAWL_DEFAULT_MAX_PAGES,
  type NewScanFormErrors,
  type NewScanFormState,
} from './new-scan-form';

export interface NewScanScreenProps {
  client: ScanApiClient;
  /** Navigate to the created scan (injected `router.push` — keeps the screen router-free). */
  push: (href: string) => void;
  /** Optional slot rendered above the form (T5.4: the free-trial availability indicator). */
  beforeForm?: React.ReactNode;
}

/** Container: the create-scan form. On success it redirects to the new scan's detail page. */
export function NewScanScreen({ client, push, beforeForm }: NewScanScreenProps): React.ReactElement {
  const [form, setForm] = useState<NewScanFormState>(initialNewScanFormState);
  const [errors, setErrors] = useState<NewScanFormErrors>({});
  const [submitting, setSubmitting] = useState(false);
  const [submitError, setSubmitError] = useState<string | null>(null);
  // x402: set when POST /scans answers 402 (T5.4 Part 3). Not reached by normal users in Phase 1
  // (price 0 → free scan), but handled honestly rather than as a generic error / silent failure.
  const [paymentRequired, setPaymentRequired] = useState<PaymentRequiredResponse | null>(null);
  // T-FIX.8: set when POST /scans answers 429 (NestJS ThrottlerGuard). Distinct state so the UI
  // renders a styled notice instead of leaking `ThrottlerException: Too Many Requests` text.
  const [rateLimited, setRateLimited] = useState<ApiError | null>(null);

  function update<K extends keyof NewScanFormState>(key: K, value: NewScanFormState[K]): void {
    setForm((prev) => ({ ...prev, [key]: value }));
  }

  async function handleSubmit(event: FormEvent): Promise<void> {
    event.preventDefault();
    setSubmitError(null);
    setPaymentRequired(null);
    setRateLimited(null);
    const validation = validateNewScanForm(form);
    setErrors(validation);
    if (hasErrors(validation)) {
      return;
    }

    setSubmitting(true);
    const result = await client.createScan(buildCreateScanPayload(form));
    if (result.ok) {
      push(`/scans/${result.data.scanId}`);
      return; // keep `submitting` true through navigation
    }
    // 402 → show the x402 requirements + the honest "paid scans not active yet" scaffold, not a
    // bare error string. The body carries PaymentRequirements (T5.2 contract).
    if (result.error.kind === 'payment-required' && result.error.paymentRequired !== undefined) {
      setPaymentRequired(result.error.paymentRequired);
      setSubmitting(false);
      return;
    }
    // 429 → on-brand notice (T-FIX.8) instead of leaking the NestJS exception class name.
    if (result.error.kind === 'rate-limited') {
      setRateLimited(result.error);
      setSubmitting(false);
      return;
    }
    setSubmitError(result.error.message);
    setSubmitting(false);
  }

  return (
    <PageShell className="max-w-2xl">
      {beforeForm !== undefined ? <div className="mb-8">{beforeForm}</div> : null}
      <form onSubmit={(event) => void handleSubmit(event)} className="flex flex-col gap-8" noValidate>
        <header className="flex flex-col gap-2">
          <h1 className="text-h2 font-semibold text-ice">New scan</h1>
          <p className="text-small text-text-secondary">Configure a target and start a scan.</p>
        </header>

        <Card className="flex flex-col gap-6">
          <Field label="Scan type">
            <Segmented
              value={form.scanKind}
              onChange={(value) => update('scanKind', value)}
              options={[
                { value: 'ai-llm-attack', label: 'AI / LLM attack' },
                { value: 'web-app-vuln', label: 'Web app vuln' },
                { value: 'api-scan', label: 'API security' },
                { value: 'web3-dapp', label: 'Web3 dApp' },
              ]}
            />
          </Field>

          {form.scanKind === 'web-app-vuln' ? (
            <>
              <Field label="Target URL" htmlFor="web-url" error={errors.webUrl}>
                <Input
                  id="web-url"
                  placeholder="https://target.example"
                  value={form.webUrl}
                  onChange={(event) => update('webUrl', event.target.value)}
                />
              </Field>
              <Field
                label="Scan mode"
                hint={
                  form.webMode === 'crawl'
                    ? `Multi-page crawl — discovers same-origin links and scans each (up to ${WEB_CRAWL_DEFAULT_MAX_PAGES} pages, depth ${WEB_CRAWL_DEFAULT_MAX_DEPTH}). robots.txt is respected. Coverage gaps are surfaced when the page limit is hit.`
                    : 'Single page — scans only the target URL above.'
                }
              >
                <Segmented
                  value={form.webMode}
                  onChange={(value) => update('webMode', value)}
                  options={[
                    { value: 'single', label: 'Single page' },
                    { value: 'crawl', label: 'Multi-page crawl' },
                  ]}
                />
              </Field>
            </>
          ) : null}

          {form.scanKind === 'ai-llm-attack' ? (
            <>
              <Field label="Target mode">
                <Segmented
                  value={form.aiMode}
                  onChange={(value) => update('aiMode', value)}
                  options={[
                    { value: 'endpoint', label: 'Agent endpoint' },
                    { value: 'system-prompt', label: 'System prompt' },
                  ]}
                />
              </Field>

              {form.aiMode === 'endpoint' ? (
                <div className="flex flex-col gap-6">
                  <Field label="Endpoint URL" htmlFor="endpoint-url" error={errors.endpointUrl}>
                    <Input
                      id="endpoint-url"
                      placeholder="https://agent.example/chat"
                      value={form.endpointUrl}
                      onChange={(event) => update('endpointUrl', event.target.value)}
                    />
                  </Field>
                  <Field label="Model (optional)" htmlFor="endpoint-model">
                    <Input
                      id="endpoint-model"
                      placeholder="e.g. the agent's model id"
                      value={form.endpointModel}
                      onChange={(event) => update('endpointModel', event.target.value)}
                    />
                  </Field>
                  <Field label="Authentication">
                    <Segmented
                      value={form.authMode}
                      onChange={(value) => update('authMode', value)}
                      options={[
                        { value: 'none', label: 'None' },
                        { value: 'bearer', label: 'Bearer' },
                        { value: 'apiKey', label: 'API key' },
                      ]}
                    />
                  </Field>
                  {form.authMode !== 'none' ? (
                    <Field
                      label="Auth value"
                      htmlFor="auth-value"
                      error={errors.authValue}
                      hint={form.authMode === 'bearer' ? 'Sent as Authorization: Bearer …' : 'Sent as an API-key header'}
                    >
                      <Input
                        id="auth-value"
                        type="password"
                        value={form.authValue}
                        onChange={(event) => update('authValue', event.target.value)}
                      />
                    </Field>
                  ) : null}
                  {form.authMode === 'apiKey' ? (
                    <Field label="Header name (optional)" htmlFor="auth-header" hint="Defaults to X-API-Key">
                      <Input
                        id="auth-header"
                        placeholder="X-API-Key"
                        value={form.authHeaderName}
                        onChange={(event) => update('authHeaderName', event.target.value)}
                      />
                    </Field>
                  ) : null}
                </div>
              ) : (
                <Field label="System prompt" htmlFor="system-prompt" error={errors.systemPrompt}>
                  <Textarea
                    id="system-prompt"
                    rows={6}
                    placeholder="Paste the system prompt to test…"
                    value={form.systemPrompt}
                    onChange={(event) => update('systemPrompt', event.target.value)}
                  />
                </Field>
              )}
            </>
          ) : null}

          {form.scanKind === 'api-scan' ? (
            <div className="flex flex-col gap-6">
              <Field label="Target mode">
                <Segmented
                  value={form.apiMode}
                  onChange={(value) => update('apiMode', value)}
                  options={[
                    { value: 'raw', label: 'Single endpoint' },
                    { value: 'spec', label: 'OpenAPI spec' },
                  ]}
                />
              </Field>

              {form.apiMode === 'raw' ? (
                <Field
                  label="Endpoint URL"
                  htmlFor="api-raw-url"
                  error={errors.apiRawUrl}
                  hint="Raw mode probes a single endpoint — coverage is shallow by construction; the report marks this."
                >
                  <Input
                    id="api-raw-url"
                    placeholder="https://api.example/v1/users/42"
                    value={form.apiRawUrl}
                    onChange={(event) => update('apiRawUrl', event.target.value)}
                  />
                </Field>
              ) : (
                <>
                  <Field
                    label="OpenAPI / Swagger spec (JSON)"
                    htmlFor="api-spec-document"
                    error={errors.apiSpecDocument}
                    hint="Paste a JSON-shape OpenAPI/Swagger document. YAML is not supported in this release — convert with `yq -o=json`."
                  >
                    <Textarea
                      id="api-spec-document"
                      rows={10}
                      placeholder='{ "openapi": "3.0.0", "info": { … }, "paths": { … } }'
                      value={form.apiSpecDocument}
                      onChange={(event) => update('apiSpecDocument', event.target.value)}
                    />
                  </Field>
                  <Field
                    label="Base URL (optional)"
                    htmlFor="api-spec-baseurl"
                    error={errors.apiSpecBaseUrl}
                    hint="The API root URL (e.g. `https://api.example.com` or `https://api.example.com/v1`). Leave blank to derive from the spec."
                  >
                    <Input
                      id="api-spec-baseurl"
                      placeholder="https://api.example.com/v1"
                      value={form.apiSpecBaseUrl}
                      onChange={(event) => update('apiSpecBaseUrl', event.target.value)}
                    />
                  </Field>
                </>
              )}

              <Field label="Authentication">
                <Segmented
                  value={form.authMode}
                  onChange={(value) => update('authMode', value)}
                  options={[
                    { value: 'none', label: 'None' },
                    { value: 'bearer', label: 'Bearer' },
                    { value: 'apiKey', label: 'API key' },
                  ]}
                />
              </Field>
              {form.authMode !== 'none' ? (
                <Field
                  label="Auth value"
                  htmlFor="api-auth-value"
                  error={errors.authValue}
                  hint={form.authMode === 'bearer' ? 'Sent as Authorization: Bearer …' : 'Sent as an API-key header'}
                >
                  <Input
                    id="api-auth-value"
                    type="password"
                    value={form.authValue}
                    onChange={(event) => update('authValue', event.target.value)}
                  />
                </Field>
              ) : null}
              {form.authMode === 'apiKey' ? (
                <Field label="Header name (optional)" htmlFor="api-auth-header" hint="Defaults to X-API-Key">
                  <Input
                    id="api-auth-header"
                    placeholder="X-API-Key"
                    value={form.authHeaderName}
                    onChange={(event) => update('authHeaderName', event.target.value)}
                  />
                </Field>
              ) : null}
            </div>
          ) : null}

          {form.scanKind === 'web3-dapp' ? (
            <div data-testid="web3-form" className="flex flex-col gap-6">
              <Field
                label="dApp URL"
                htmlFor="web3-url"
                error={errors.web3Url}
                hint="The dApp page Playwright will load. The synthetic EIP-1193 provider intercepts wallet calls (NO real wallet, NO private key, NO mnemonic — by construction)."
              >
                <Input
                  id="web3-url"
                  placeholder="https://dapp.example"
                  value={form.web3Url}
                  onChange={(event) => update('web3Url', event.target.value)}
                />
              </Field>
              <Field
                label="Chain"
                hint="Selects the L3 read-only provider (Ethereum vs Base mainnet) for on-chain context lookups."
              >
                <Segmented
                  value={form.web3Chain}
                  onChange={(value) => update('web3Chain', value)}
                  options={[
                    { value: 'ethereum', label: 'Ethereum' },
                    { value: 'base', label: 'Base' },
                  ]}
                />
              </Field>
              <Field
                label="Wallet interaction depth"
                hint={
                  form.web3WalletDepth === 'try-connect-button'
                    ? 'Try-connect-button (recommended) — after navigation, heuristically clicks a Connect button to drive the dApp deeper. The synthetic provider records the resulting wallet calls.'
                    : 'Landing-page-only — load and wait; do not click anything. If the dApp gates wallet activity behind Connect, L1 will report no interactive flow honestly.'
                }
              >
                <Segmented
                  value={form.web3WalletDepth}
                  onChange={(value) => update('web3WalletDepth', value)}
                  options={[
                    { value: 'try-connect-button', label: 'Try Connect' },
                    { value: 'landing-page-only', label: 'Landing page only' },
                  ]}
                />
              </Field>
              <p className="font-mono text-caption text-text-muted">
                Three layers run against the loaded dApp: L1 wallet interaction (approval phishing,
                EIP-7702, chain mismatch…), L2 frontend / infrastructure (SRI, bundle-drift,
                known-bad domain, TLS/DNS hygiene), L3 on-chain context (verified source, proxy
                implementation, EOA admin, fresh deployment, token impersonation).
              </p>
            </div>
          ) : null}
        </Card>

        {submitError !== null ? (
          <p data-testid="submit-error" className="font-mono text-caption text-magenta-core">
            {submitError}
          </p>
        ) : null}

        {rateLimited !== null ? <RateLimitNotice error={rateLimited} /> : null}

        {paymentRequired !== null ? <PaymentRequirementsNotice paymentRequired={paymentRequired} /> : null}

        <div className="flex items-center gap-4">
          <Button type="submit" variant="primary" disabled={submitting}>
            {submitting ? 'Starting…' : 'Start scan'}
          </Button>
          <Link href="/scans" className={buttonClassName({ variant: 'ghost' })}>
            Cancel
          </Link>
        </div>
      </form>
    </PageShell>
  );
}

/**
 * T-FIX.8: on-brand 429 notice. Replaces the raw `ThrottlerException: Too Many Requests`
 * line that leaked through the generic submit-error path in B1. The copy is the message
 * the api-client maps 429 to; the "try again in N" hint only appears when the server sent
 * a parseable `Retry-After` header (we never invent one).
 */
function RateLimitNotice({ error }: { error: ApiError }): React.ReactElement {
  const retryHint = formatRetryAfter(error.retryAfterSeconds);
  return (
    <Card
      data-testid="rate-limit-notice"
      className="border-l-2 border-l-magenta-core/80"
      role="alert"
    >
      <p className="text-body font-medium text-magenta-light">Scan rate limit reached</p>
      <p className="mt-2 text-small text-text-secondary">{error.message}</p>
      {retryHint !== null ? (
        <p className="mt-2 font-mono text-caption uppercase tracking-wide text-text-muted">
          {retryHint}
        </p>
      ) : null}
    </Card>
  );
}

/** Pretty-print a Retry-After in seconds as "Try again in N minute(s) / second(s)". */
function formatRetryAfter(seconds: number | undefined): string | null {
  if (seconds === undefined || seconds <= 0) return null;
  if (seconds < 60) return `Try again in ${seconds} second${seconds === 1 ? '' : 's'}.`;
  const minutes = Math.ceil(seconds / 60);
  return `Try again in ${minutes} minute${minutes === 1 ? '' : 's'}.`;
}
