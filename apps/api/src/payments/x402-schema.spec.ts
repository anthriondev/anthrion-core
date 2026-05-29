import {
  parsePaymentHeader,
  paymentPayloadSchema,
  paymentRequiredResponseSchema,
  paymentRequirementsSchema,
} from '@anthrion/shared';

/**
 * x402 wire-schema validation (T5.1). All inbound x402 data is external → Zod-validated
 * before trust (CLAUDE.md §3). These guard the EVM `exact` shapes mirrored from x402 1.2.0.
 */

const validPayload = {
  x402Version: 1,
  scheme: 'exact',
  network: 'base',
  payload: {
    signature: '0xsignature',
    authorization: {
      from: '0xPayer',
      to: '0xTreasury',
      value: '10000',
      validAfter: '0',
      validBefore: '9999999999',
      nonce: '0xnonce',
    },
  },
};

const validRequirements = {
  scheme: 'exact',
  network: 'base',
  maxAmountRequired: '10000',
  resource: '/scans/scan_1',
  description: 'ANTHRION security scan',
  mimeType: 'application/json',
  payTo: '0xTreasury',
  maxTimeoutSeconds: 60,
  asset: '0xUSDC',
  extra: { name: 'USDC', version: '2' },
};

describe('x402 wire schemas', () => {
  it('accepts a valid EVM exact payment payload', () => {
    expect(paymentPayloadSchema.safeParse(validPayload).success).toBe(true);
  });

  it('rejects an unsupported network (Phase 1 = Base only)', () => {
    expect(paymentPayloadSchema.safeParse({ ...validPayload, network: 'polygon' }).success).toBe(false);
  });

  it('rejects a non-integer atomic value', () => {
    const bad = {
      ...validPayload,
      payload: { ...validPayload.payload, authorization: { ...validPayload.payload.authorization, value: '0.01' } },
    };
    expect(paymentPayloadSchema.safeParse(bad).success).toBe(false);
  });

  it('rejects a missing signature / authorization field', () => {
    expect(paymentPayloadSchema.safeParse({ ...validPayload, payload: { authorization: validPayload.payload.authorization } }).success).toBe(false);
  });

  it('accepts valid payment requirements', () => {
    expect(paymentRequirementsSchema.safeParse(validRequirements).success).toBe(true);
  });

  it('rejects requirements with a non-exact scheme', () => {
    expect(paymentRequirementsSchema.safeParse({ ...validRequirements, scheme: 'upto' }).success).toBe(false);
  });

  // ── 402 response body (T5.2) ────────────────────────────────────────────────

  it('accepts a valid 402 Payment Required body (x402Version + accepts[])', () => {
    const body = { x402Version: 1, accepts: [validRequirements], error: 'Payment required to run this scan' };
    expect(paymentRequiredResponseSchema.safeParse(body).success).toBe(true);
  });

  it('rejects a 402 body with an empty accepts list (must advertise at least one option)', () => {
    expect(paymentRequiredResponseSchema.safeParse({ x402Version: 1, accepts: [] }).success).toBe(false);
  });

  it('rejects a 402 body whose accepts entry is not valid requirements', () => {
    const body = { x402Version: 1, accepts: [{ ...validRequirements, scheme: 'upto' }] };
    expect(paymentRequiredResponseSchema.safeParse(body).success).toBe(false);
  });

  describe('parsePaymentHeader (base64 X-PAYMENT)', () => {
    it('decodes and validates a well-formed header', () => {
      const header = Buffer.from(JSON.stringify(validPayload), 'utf8').toString('base64');
      const parsed = parsePaymentHeader(header);
      expect(parsed?.network).toBe('base');
      expect(parsed?.payload.authorization.nonce).toBe('0xnonce');
    });

    it('returns undefined for non-base64 / non-JSON input', () => {
      expect(parsePaymentHeader('not-valid-base64-json!!!')).toBeUndefined();
    });

    it('returns undefined for a structurally invalid payload (no throw)', () => {
      const header = Buffer.from(JSON.stringify({ x402Version: 1, scheme: 'exact' }), 'utf8').toString('base64');
      expect(parsePaymentHeader(header)).toBeUndefined();
    });
  });
});
