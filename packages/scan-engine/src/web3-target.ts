import type { Page, Response } from 'playwright';
import { z } from 'zod';

import type { Web3Chain } from './config';
import { PlaywrightPageContext } from './web-page-context';
import type { PageContext } from './web-probe';
import { harvestReferencedContracts } from './web3-address-harvest';
import { CAPTURE_GLOBAL_KEY } from './web3-provider-script';
import {
  walletRequestSchema,
  type ReferencedContract,
  type WalletRequest,
} from './web3-types';

/**
 * `Web3DAppTarget` — engine surface for L1 + L2 probes (Sprint A3, T-A3.2).
 *
 * Founder-confirmed in T-A3.1: L1 (wallet interaction) and L2 (frontend
 * infrastructure) share the same data source (one loaded Playwright page),
 * so they sit behind ONE target interface that extends `PageContext` with the
 * Web3-specific surface. L3 (on-chain context) lives on a separate channel
 * (`OnChainContextProvider`) since RPC + explorer access has a different
 * mechanic, lifetime, and failure mode.
 *
 * Probes never see Playwright directly — they depend only on this interface.
 * This is the same rule the AI scan applies to `ScanTarget`, the API scan to
 * `ApiTarget`, and the web scan to `PageContext`. Keeps probes unit-testable
 * without a browser.
 */
export interface Web3DAppTarget extends PageContext {
  /** Chain the L1 provider reports to the dApp. The L3 provider also uses
   * this when looking up on-chain context (T-A3.4). */
  readonly chain: Web3Chain;
  /** Every EIP-1193 `request({ method, params })` call the synthetic
   * provider observed during the L1 capture window, in observation order. */
  walletRequests(): Promise<readonly WalletRequest[]>;
  /** Unique contract addresses referenced during the L1 capture, with
   * provenance preserved. L3 probes iterate this list. */
  referencedContracts(): Promise<readonly ReferencedContract[]>;
  /** True iff the synthetic provider captured at least one wallet request.
   * False is the honest signal for the L1 coverage gap
   * `web3-l1-no-interactive-flow-observed`. */
  observedInteractiveFlow(): Promise<boolean>;
}

/** Capture result returned by `harvestWeb3Capture`. */
export interface Web3CaptureResult {
  walletRequests: readonly WalletRequest[];
  referencedContracts: readonly ReferencedContract[];
  observedInteractiveFlow: boolean;
}

const walletRequestArraySchema = z.array(walletRequestSchema);

/**
 * Read the synthetic-provider capture array off the loaded page. Untrusted
 * page data — Zod-validated before consumption (CLAUDE.md §3). A malformed
 * or missing array is treated as "no requests observed", which the runner
 * then surfaces honestly as the no-interactive-flow coverage gap.
 *
 * The `referencedContracts()` pass happens in the dedicated harvester; this
 * function only reads the raw `WalletRequest[]`.
 */
export async function readCapturedWalletRequests(
  page: Page,
): Promise<readonly WalletRequest[]> {
  let raw: unknown;
  try {
    raw = await page.evaluate(
      `(() => window[${JSON.stringify(CAPTURE_GLOBAL_KEY)}] || null)()`,
    );
  } catch {
    return [];
  }
  if (raw === null || raw === undefined) return [];
  const parsed = walletRequestArraySchema.safeParse(raw);
  if (!parsed.success) {
    // A malformed capture is not a vulnerability signal; treat as "no
    // requests" rather than crashing the whole scan. The runner's
    // observedInteractiveFlow gap then fires honestly.
    return [];
  }
  return parsed.data;
}

/**
 * Playwright-backed `Web3DAppTarget`. Wraps the same `Page` + main-navigation
 * `Response` that `PlaywrightPageContext` does (L1 + L2 share one loaded page,
 * §1 of T-A3.1), and adds the synthetic-provider capture surface on top.
 *
 * Memoization rules match the parent: `walletRequests`, `referencedContracts`,
 * and `observedInteractiveFlow` are each computed at most once per scan and
 * shared across all probes — N probes do not cause N browser round-trips.
 *
 * Constructor inputs are the same shape as `PlaywrightPageContext` plus
 * `chain`. The caller is responsible for having installed the synthetic
 * provider via `page.addInitScript(buildSyntheticProviderScript(chain))`
 * BEFORE `page.goto(...)`; otherwise `walletRequests()` will be empty (the
 * harvester reads an unset global) and `observedInteractiveFlow()` will return
 * `false`, which the L1 runner surfaces as the honest no-interactive-flow
 * coverage gap — never a silent "all clear".
 */
export class PlaywrightWeb3DAppTarget extends PlaywrightPageContext implements Web3DAppTarget {
  readonly chain: Web3Chain;
  private readonly web3Page: Page;
  private walletRequestsPromise: Promise<readonly WalletRequest[]> | undefined;
  private referencedContractsPromise: Promise<readonly ReferencedContract[]> | undefined;

  constructor(page: Page, response: Response, requestedUrl: string, chain: Web3Chain) {
    super(page, response, requestedUrl);
    this.chain = chain;
    this.web3Page = page;
  }

  walletRequests(): Promise<readonly WalletRequest[]> {
    if (this.walletRequestsPromise === undefined) {
      this.walletRequestsPromise = readCapturedWalletRequests(this.web3Page);
    }
    return this.walletRequestsPromise;
  }

  async observedInteractiveFlow(): Promise<boolean> {
    const requests = await this.walletRequests();
    return requests.length > 0;
  }

  referencedContracts(): Promise<readonly ReferencedContract[]> {
    if (this.referencedContractsPromise === undefined) {
      this.referencedContractsPromise = this.loadReferencedContracts();
    }
    return this.referencedContractsPromise;
  }

  private async loadReferencedContracts(): Promise<readonly ReferencedContract[]> {
    const [walletRequests, html] = await Promise.all([this.walletRequests(), this.html()]);
    return harvestReferencedContracts({ walletRequests, html });
  }
}
