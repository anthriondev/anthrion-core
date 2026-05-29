import { Injectable } from '@nestjs/common';

import type { ScanJobType } from '@anthrion/shared';

export interface ScanPrice {
  /** Price in atomic USDC units (6 decimals). */
  atomicUnits: bigint;
  /** True when the price is 0 → FREE_PRICING (the valid free path, not a rejection). */
  isFree: boolean;
}

/**
 * Scan price resolver (T5.1). Phase 1 uses a single GLOBAL price for all scan types, read from
 * env (`SCAN_PRICE_USDC_ATOMIC`, atomic USDC). Per-scan-type pricing can be added later without
 * touching callers. A price of 0 (the Phase 1 default, promo phase) means FREE_PRICING.
 *
 * Constructed from the (validated) env value at module wiring; tests construct it directly with
 * an explicit price, so pricing is exercised without mutating process env.
 */
@Injectable()
export class ScanPricing {
  private readonly atomicUnits: bigint;

  constructor(atomicUnits: string) {
    this.atomicUnits = BigInt(atomicUnits);
  }

  priceForScan(scanType: ScanJobType): ScanPrice {
    void scanType; // global price in Phase 1
    return { atomicUnits: this.atomicUnits, isFree: this.atomicUnits === 0n };
  }
}
