import { chainIdDecimal, chainIdHex } from './web3-types';
import {
  MAX_UINT160_HEX_LOWER,
  MAX_UINT256_HEX_LOWER,
  NO_L1_DETECTIONS,
  PERMIT2_CONTRACT_ADDRESS,
  chainIdMatches,
  clipForEvidence,
  decodeErc20Approve,
  decodeSetApprovalForAll,
  decodeTypedDataPayload,
  firstParam,
  hexChainEquals,
  readField,
  type Web3L1Detection,
  type Web3L1Probe,
} from './web3-l1-probe';
import type { WalletRequest } from './web3-types';

/**
 * Curated Web3 L1 probes (Sprint A3, T-A3.3).
 *
 * Six probes covering OWASP Web3 WA06 (wallet interaction / approval phishing)
 * plus the EIP-7702 SetCode and Permit2 patterns that the public OWASP list
 * names but does not pin to a single slug yet (`category.ts` documents the
 * synthesis). One probe per L1 slug from `owaspWeb3CategorySchema`; the slug
 * list is the contract — never add a seventh probe without extending the enum
 * first.
 *
 * Probes consume the synthetic-provider capture (`target.walletRequests()`)
 * and inspect intercepted JSON-RPC payloads structurally. They do NOT need a
 * browser, an LLM, or a network call: each probe is a pure function of
 * `(request[], target.chain) → detections`. The runner (T-A3.3 cont.) wires
 * them against `Web3DAppTarget` and emits `Finding`s.
 *
 * Honesty rules (mirror api-probes / web-probes):
 *  - "I didn't find anything" returns an empty array, never throws.
 *  - "I cannot tell either way" — for L1 specifically — is surfaced by the
 *    runner via the no-interactive-flow coverage gap (`Web3L1Report.outcome
 *    === 'no-interactive-flow-observed'`), NOT by a probe inventing a finding.
 *  - Evidence carries only the offending field(s), not the whole params blob.
 *    Truncation via `clipForEvidence` guards against pathological inputs.
 */

// ── 1. wallet-approval-phishing ─────────────────────────────────────────────

/**
 * `web3:l1:wallet-approval-phishing` — WA06 (T-A3.3).
 *
 * Three concrete patterns, evaluated against every intercepted request:
 *  1. `eth_sendTransaction` calldata decodes as ERC-20 `approve(spender, amount)`
 *     with `amount === 2**256 - 1` (the "infinite allowance" idiom every
 *     phishing site uses).
 *  2. `eth_sendTransaction` calldata decodes as `setApprovalForAll(operator,
 *     true)` (ERC-721 / ERC-1155 — grants all current AND future NFTs of the
 *     collection; same exposure shape).
 *  3. EIP-2612 `Permit` signed via `eth_signTypedData_v4` with `value === max
 *     uint256`. The `permit` signature lets a contract pull tokens later
 *     without a separate transaction — the same fund-loss exposure as an
 *     unlimited `approve`, hidden behind a sign-only UX.
 *
 * Severity is High for every variant; concrete fund-loss outcome is identical.
 */
const walletApprovalPhishingProbe: Web3L1Probe = {
  id: 'web3:l1:wallet-approval-phishing',
  technique: 'Approval-payload inspection (ERC-20 / ERC-721 / EIP-2612)',
  category: 'wallet-approval-phishing',
  severity: 'High',
  title: 'dApp requested an unlimited token approval',
  description:
    'The dApp asked the wallet to grant an unlimited token allowance (ERC-20 max approve, NFT setApprovalForAll, or EIP-2612 permit with max value). Once granted, the approved spender can move the user\'s entire balance of that token, or all NFTs of that collection, at any time — even after the user leaves the site.',
  recommendation:
    'Approve only the exact amount the dApp needs for the current action. For NFTs, prefer per-token approvals to setApprovalForAll. Review and revoke unused allowances at revoke.cash or a wallet\'s built-in allowance manager.',
  async evaluate(target) {
    const requests = await target.walletRequests();
    const detections: Web3L1Detection[] = [];
    for (const req of requests) {
      detections.push(...findApprovalPhishing(req));
    }
    return detections;
  },
};

function findApprovalPhishing(req: WalletRequest): Web3L1Detection[] {
  const detections: Web3L1Detection[] = [];

  // (1) + (2) — eth_sendTransaction with approve / setApprovalForAll calldata.
  if (req.method === 'eth_sendTransaction') {
    const tx = firstParam(req.params);
    const data = readField(tx, 'data');
    const to = readField(tx, 'to');
    const decoded = decodeErc20Approve(data);
    if (decoded !== undefined && decoded.amountHex === MAX_UINT256_HEX_LOWER) {
      detections.push({
        walletRequestSequence: req.sequence,
        walletRequestMethod: req.method,
        rationale: `eth_sendTransaction calldata decodes as ERC-20 approve(${decoded.spender}, max_uint256).`,
        evidence: clipForEvidence(
          `to=${String(to)}; selector=approve(address,uint256); spender=${decoded.spender}; amount=2**256-1 (unlimited).`,
        ),
        metadata: {
          pattern: 'erc20-approve-max',
          spender: decoded.spender,
          token: typeof to === 'string' ? to : '',
        },
      });
      return detections; // an approve is either max or it isn't — no further match
    }
    const decodedAll = decodeSetApprovalForAll(data);
    if (decodedAll !== undefined && decodedAll.approved) {
      detections.push({
        walletRequestSequence: req.sequence,
        walletRequestMethod: req.method,
        rationale: `eth_sendTransaction calldata decodes as setApprovalForAll(${decodedAll.operator}, true).`,
        evidence: clipForEvidence(
          `to=${String(to)}; selector=setApprovalForAll(address,bool); operator=${decodedAll.operator}; approved=true (grants all current and future NFTs of this collection).`,
        ),
        metadata: {
          pattern: 'set-approval-for-all-true',
          operator: decodedAll.operator,
          collection: typeof to === 'string' ? to : '',
        },
      });
      return detections;
    }
  }

  // (3) — EIP-2612 Permit signed via eth_signTypedData with max-uint256 value.
  if (req.method.startsWith('eth_signTypedData')) {
    const typedData = decodeTypedDataPayload(req);
    if (typedData === undefined) return detections;
    const primaryType = readField(typedData, 'primaryType');
    if (primaryType !== 'Permit') return detections;
    const message = readField(typedData, 'message');
    const value = readField(message, 'value');
    if (typeof value !== 'string') return detections;
    // EIP-712 message values arrive as hex or decimal strings depending on
    // the dApp; normalise both before comparing.
    const isMax = matchesMaxUint256(value);
    if (!isMax) return detections;
    const domain = readField(typedData, 'domain');
    const verifyingContract = readField(domain, 'verifyingContract');
    const spender = readField(message, 'spender');
    detections.push({
      walletRequestSequence: req.sequence,
      walletRequestMethod: req.method,
      rationale: `${req.method} requests an EIP-2612 Permit with value=max_uint256 — the equivalent of approve(max) but signed off-chain.`,
      evidence: clipForEvidence(
        `primaryType=Permit; verifyingContract=${String(verifyingContract)}; spender=${String(spender)}; value=2**256-1 (unlimited).`,
      ),
      metadata: {
        pattern: 'eip2612-permit-max',
        ...(typeof verifyingContract === 'string' ? { token: verifyingContract } : {}),
        ...(typeof spender === 'string' ? { spender } : {}),
      },
    });
  }

  return detections;
}

/** True iff `value` represents `2**256 - 1` in either hex (`0xff…f`) or decimal
 * (`115792089237316195423570985008687907853269984665640564039457584007913129639935`)
 * form. Robust against leading zeros / casing. */
function matchesMaxUint256(value: string): boolean {
  const trimmed = value.trim();
  if (trimmed === '') return false;
  try {
    const asBig = BigInt(trimmed);
    return asBig === (1n << 256n) - 1n;
  } catch {
    return false;
  }
}

// ── 2. deceptive-typed-data-signature ───────────────────────────────────────

/**
 * `web3:l1:deceptive-typed-data-signature` — WA06 (T-A3.3).
 *
 * Structural smells in `eth_signTypedData_*` payloads that prevent the wallet
 * from rendering a meaningful preview to the user. None of these are proof of
 * malice on their own; together they describe a signed object the user almost
 * certainly cannot understand at the moment of approval — the precondition for
 * approval phishing.
 *
 * Three detection rules, each producing one detection per offending request:
 *  - `eth_signTypedData_v1` (legacy array-of-{type,name,value} format) — flag
 *    every use. v1 does not carry the EIP-712 type schema modern wallets need
 *    to render structured previews; using it in 2025+ is a smell on its own.
 *  - `eth_signTypedData_v3` / `_v4` / `eth_signTypedData` with `types`
 *    missing or empty — no schema means the wallet renders only an opaque
 *    message bag. High.
 *  - `eth_signTypedData_v3` / `_v4` / `eth_signTypedData` whose `primaryType`
 *    is not a key in `types` — broken structure. Some wallets fall back to
 *    rendering raw fields without labels; others reject. High.
 */
const deceptiveTypedDataSignatureProbe: Web3L1Probe = {
  id: 'web3:l1:deceptive-typed-data-signature',
  technique: 'EIP-712 typed-data structural inspection',
  category: 'deceptive-typed-data-signature',
  severity: 'Medium',
  title: 'dApp requested a typed-data signature in a form the wallet cannot render',
  description:
    'The dApp asked the wallet to sign EIP-712 typed data in a way that prevents the wallet from showing a meaningful preview to the user: legacy v1 format, missing/empty types schema, or a primaryType not declared in types. A user cannot give informed consent to a signed object they cannot read — this is the precondition for approval phishing.',
  recommendation:
    'Always request typed-data signatures via eth_signTypedData_v4 with a complete EIP-712 schema (types + primaryType present in types + domain.verifyingContract set). Treat any dApp that asks for legacy or schemaless signatures as untrusted.',
  async evaluate(target) {
    const requests = await target.walletRequests();
    const detections: Web3L1Detection[] = [];
    for (const req of requests) {
      if (!req.method.startsWith('eth_signTypedData')) continue;
      const detection = inspectTypedDataShape(req);
      if (detection !== undefined) detections.push(detection);
    }
    return detections;
  },
};

function inspectTypedDataShape(req: WalletRequest): Web3L1Detection | undefined {
  if (req.method === 'eth_signTypedData_v1') {
    return {
      walletRequestSequence: req.sequence,
      walletRequestMethod: req.method,
      rationale: 'eth_signTypedData_v1 is the legacy array-of-{type,name,value} format, which lacks the EIP-712 type schema modern wallets need to render structured previews.',
      evidence: 'method=eth_signTypedData_v1 (legacy format — flag every use).',
      severity: 'Medium',
      metadata: { pattern: 'legacy-v1-format' },
    };
  }
  const typedData = decodeTypedDataPayload(req);
  if (typedData === undefined) {
    return {
      walletRequestSequence: req.sequence,
      walletRequestMethod: req.method,
      rationale: `${req.method} payload could not be parsed as an EIP-712 typed-data object.`,
      evidence: clipForEvidence(`method=${req.method}; payload could not be decoded as JSON or a plain object — wallet will render an opaque blob.`),
      severity: 'Medium',
      metadata: { pattern: 'unparseable-payload' },
    };
  }
  const types = readField(typedData, 'types');
  const primaryType = readField(typedData, 'primaryType');
  // Rule (b): types missing or empty.
  if (types === undefined || types === null) {
    return {
      walletRequestSequence: req.sequence,
      walletRequestMethod: req.method,
      rationale: `${req.method} typed-data payload omits the EIP-712 \`types\` schema.`,
      evidence: clipForEvidence(`method=${req.method}; primaryType=${String(primaryType)}; types=<missing> — wallet has no schema to label the message fields.`),
      severity: 'High',
      metadata: { pattern: 'missing-types-schema' },
    };
  }
  if (typeof types !== 'object' || Object.keys(types as Record<string, unknown>).length === 0) {
    return {
      walletRequestSequence: req.sequence,
      walletRequestMethod: req.method,
      rationale: `${req.method} typed-data payload carries an empty \`types\` schema.`,
      evidence: clipForEvidence(`method=${req.method}; primaryType=${String(primaryType)}; types={} — wallet has no schema to label the message fields.`),
      severity: 'High',
      metadata: { pattern: 'empty-types-schema' },
    };
  }
  // Rule (c): primaryType not in types.
  if (typeof primaryType !== 'string' || primaryType === '') {
    return {
      walletRequestSequence: req.sequence,
      walletRequestMethod: req.method,
      rationale: `${req.method} typed-data payload omits a \`primaryType\` declaration.`,
      evidence: clipForEvidence(`method=${req.method}; primaryType=<missing>; types keys=${Object.keys(types as Record<string, unknown>).join(',')}`),
      severity: 'High',
      metadata: { pattern: 'missing-primary-type' },
    };
  }
  if (!Object.prototype.hasOwnProperty.call(types as Record<string, unknown>, primaryType)) {
    return {
      walletRequestSequence: req.sequence,
      walletRequestMethod: req.method,
      rationale: `${req.method} typed-data payload's \`primaryType\` "${primaryType}" is not declared in the \`types\` schema.`,
      evidence: clipForEvidence(`method=${req.method}; primaryType=${primaryType}; types keys=${Object.keys(types as Record<string, unknown>).join(',')}`),
      severity: 'High',
      metadata: { pattern: 'primary-type-not-in-types', primaryType },
    };
  }
  return undefined;
}

// ── 3. personal-sign-payload-smell ──────────────────────────────────────────

/**
 * `web3:l1:personal-sign-payload-smell` — WA06 (T-A3.3).
 *
 * `personal_sign` prepends `"\x19Ethereum Signed Message:\n<len>"` to the
 * payload, but offers NO structured rendering — the wallet shows whatever the
 * payload decodes to as UTF-8, or raw hex if it doesn't. Two smells warrant
 * flagging (each emits one detection per offending request):
 *
 *  - **Hash-shaped payload.** The payload is exactly 32 bytes of hex with no
 *    obvious UTF-8 text. Real personal_sign use cases sign human-readable
 *    nonces ("Sign in to Foo, nonce: 12345"); a 32-byte opaque blob is the
 *    shape of a typed-data digest or a state-root commitment — signing one is
 *    the classic "you signed something you couldn't read" phishing vector.
 *    Severity Medium.
 *  - **Address-bearing UTF-8 payload.** The payload decodes to UTF-8 that
 *    contains an EVM address pattern (`0x[a-f0-9]{40}`). A message that names
 *    an on-chain address should be typed-data — not a personal_sign blob —
 *    because typed-data is the form wallets render with structured field
 *    labels. Severity Medium.
 *
 * Indicator-not-verdict wording (T-FIX.6 lesson): the finding says "this
 * shape is the kind phishing flows use," not "this is phishing."
 */
const personalSignPayloadSmellProbe: Web3L1Probe = {
  id: 'web3:l1:personal-sign-payload-smell',
  technique: 'personal_sign payload shape inspection',
  category: 'personal-sign-payload-smell',
  severity: 'Medium',
  title: 'dApp asked the wallet to personal_sign a payload that should have been typed-data',
  description:
    'The dApp called personal_sign with a payload that bypasses the wallet\'s structured-signing safeguards: a 32-byte hash-shaped blob, or a UTF-8 message that names an on-chain address. Either shape is what wallets render as opaque text — the user cannot meaningfully review what they are authorising. Typed-data (eth_signTypedData_v4) is the correct interface for messages that should be human-readable.',
  recommendation:
    'Treat personal_sign requests with hash-shaped or address-bearing payloads as untrusted. Legitimate sign-in flows (EIP-4361 / Sign-In With Ethereum) use human-readable text only; on-chain authorisations (permits, approvals) should be requested via eth_signTypedData_v4.',
  async evaluate(target) {
    const requests = await target.walletRequests();
    const detections: Web3L1Detection[] = [];
    for (const req of requests) {
      if (req.method !== 'personal_sign') continue;
      const detection = inspectPersonalSign(req);
      if (detection !== undefined) detections.push(detection);
    }
    return detections;
  },
};

function inspectPersonalSign(req: WalletRequest): Web3L1Detection | undefined {
  // personal_sign params shape: [messageHex, address]. The hex payload is
  // params[0]; if it's a non-hex string, it's a raw UTF-8 message.
  if (!Array.isArray(req.params)) return undefined;
  const raw = req.params[0];
  if (typeof raw !== 'string') return undefined;

  // Hex-shaped payload — try to decode to UTF-8.
  const hexBody = raw.startsWith('0x') && /^0x[0-9a-fA-F]*$/.test(raw)
    ? raw.slice(2)
    : undefined;

  if (hexBody !== undefined) {
    // Empty / odd-length hex: unusual but not necessarily phishing-shaped.
    if (hexBody.length === 0 || hexBody.length % 2 !== 0) return undefined;
    if (hexBody.length === 64) {
      // 32 bytes — possibly a hash. Decode UTF-8 to confirm it's not readable text.
      const utf8 = safeHexToUtf8(hexBody);
      if (utf8 === undefined || !looksHumanReadable(utf8)) {
        return {
          walletRequestSequence: req.sequence,
          walletRequestMethod: req.method,
          rationale: 'personal_sign payload is a 32-byte opaque blob — the shape of a digest or commitment, not a human-readable nonce.',
          evidence: clipForEvidence(`payload=${raw} (32 bytes, no readable UTF-8 — wallet renders this as raw hex; user cannot review what they are signing).`),
          metadata: { pattern: 'hash-shaped-payload' },
        };
      }
    }
    // Decode hex to UTF-8 and check for embedded EVM address.
    const utf8 = safeHexToUtf8(hexBody);
    if (utf8 !== undefined && /0x[0-9a-fA-F]{40}/.test(utf8)) {
      return {
        walletRequestSequence: req.sequence,
        walletRequestMethod: req.method,
        rationale: 'personal_sign payload (UTF-8 decoded) contains an EVM address — messages that name on-chain entities should use eth_signTypedData_v4 for structured rendering.',
        evidence: clipForEvidence(`payload=${clipForEvidence(utf8)} (contains an EVM address; should be typed-data).`),
        metadata: { pattern: 'address-bearing-utf8' },
      };
    }
    return undefined;
  }

  // Raw UTF-8 string payload (not hex-prefixed). Apply the address check.
  if (/0x[0-9a-fA-F]{40}/.test(raw)) {
    return {
      walletRequestSequence: req.sequence,
      walletRequestMethod: req.method,
      rationale: 'personal_sign payload contains an EVM address — messages that name on-chain entities should use eth_signTypedData_v4 for structured rendering.',
      evidence: clipForEvidence(`payload=${clipForEvidence(raw)} (contains an EVM address; should be typed-data).`),
      metadata: { pattern: 'address-bearing-utf8' },
    };
  }
  return undefined;
}

/** Decode a hex string (no `0x` prefix, even length) to UTF-8. Returns
 * `undefined` if any byte fails to decode as UTF-8 (the `fatal` decoder
 * surfaces malformed sequences). */
function safeHexToUtf8(hex: string): string | undefined {
  if (hex.length === 0 || hex.length % 2 !== 0) return undefined;
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < hex.length; i += 2) {
    const byte = Number.parseInt(hex.slice(i, i + 2), 16);
    if (!Number.isFinite(byte)) return undefined;
    bytes[i / 2] = byte;
  }
  try {
    return new TextDecoder('utf-8', { fatal: true }).decode(bytes);
  } catch {
    return undefined;
  }
}

/** Heuristic: at least 8 of the first 64 characters are printable ASCII
 * (space through `~`). A 32-byte hash decoded as UTF-8 will typically have
 * mostly non-printable bytes; a sign-in nonce will be almost all printable. */
function looksHumanReadable(text: string): boolean {
  const head = text.slice(0, 64);
  let printable = 0;
  for (let i = 0; i < head.length; i += 1) {
    const code = head.charCodeAt(i);
    if (code >= 0x20 && code <= 0x7e) printable += 1;
  }
  return printable >= 8;
}

// ── 4. eip-7702-set-code-delegation ─────────────────────────────────────────

/**
 * `web3:l1:eip-7702-set-code-delegation` — WA06 + new pattern (T-A3.3).
 *
 * EIP-7702 introduces transaction type `0x04` carrying an `authorizationList`
 * that delegates the EOA's code slot to a smart-contract implementation —
 * permanent until the user submits a counter-authorization to clear it. A dApp
 * requesting this hands the EOA's account permanent contract control to whatever
 * implementation address is listed; this is novel enough that ANY detection
 * is Critical, regardless of who the implementation address belongs to. The
 * scan emits the finding; the user decides if they trust the implementation.
 *
 * Detection: `eth_sendTransaction` with either `type === '0x4'` (or any
 * lower-case variant / leading-zero variant) OR `authorizationList` present
 * and non-empty.
 */
const eip7702SetCodeDelegationProbe: Web3L1Probe = {
  id: 'web3:l1:eip-7702-set-code-delegation',
  technique: 'EIP-7702 transaction-type inspection',
  category: 'eip-7702-set-code-delegation',
  severity: 'Critical',
  title: 'dApp requested EIP-7702 SetCode delegation (account code upgrade)',
  description:
    'The dApp asked the wallet to sign an EIP-7702 (transaction type 0x04) authorisation that delegates the EOA\'s code slot to a smart-contract implementation. Once signed, the EOA behaves as that contract until the user submits a counter-authorisation to clear the delegation. This is one of the most powerful signing requests an EOA can grant — the dApp gains permanent contract-level control over the account.',
  recommendation:
    'Treat any EIP-7702 SetCode request as a high-stakes operation, regardless of which implementation is listed. Verify the implementation address corresponds to a contract the user has independently chosen to trust; if in doubt, reject and ask the dApp for an alternative flow. Keep track of active delegations and revoke them when no longer needed.',
  async evaluate(target) {
    const requests = await target.walletRequests();
    const detections: Web3L1Detection[] = [];
    for (const req of requests) {
      if (req.method !== 'eth_sendTransaction') continue;
      const detection = detectEip7702(req);
      if (detection !== undefined) detections.push(detection);
    }
    return detections;
  },
};

function detectEip7702(req: WalletRequest): Web3L1Detection | undefined {
  const tx = firstParam(req.params);
  if (tx === null || typeof tx !== 'object') return undefined;
  const obj = tx as Record<string, unknown>;
  // Detect by `type === 0x04` (EIP-7702 tx type) OR `authorizationList` array.
  const type = obj['type'];
  const authList = obj['authorizationList'];
  const isType7702 = typeof type === 'string' && hexChainEquals(type, '0x4');
  const hasAuthList = Array.isArray(authList) && authList.length > 0;
  if (!isType7702 && !hasAuthList) return undefined;
  const delegate = hasAuthList ? extractDelegateAddress(authList[0]) : undefined;
  return {
    walletRequestSequence: req.sequence,
    walletRequestMethod: req.method,
    rationale: 'eth_sendTransaction request is an EIP-7702 SetCode delegation (transaction type 0x04 / authorizationList present).',
    evidence: clipForEvidence(
      `type=${typeof type === 'string' ? type : '<unset>'}; authorizationList=${hasAuthList ? `[entries: ${authList.length}]` : '<absent>'}; first delegate=${delegate ?? '<unknown>'}`,
    ),
    metadata: {
      pattern: 'eip-7702-set-code',
      ...(delegate !== undefined ? { delegate } : {}),
    },
  };
}

function extractDelegateAddress(entry: unknown): string | undefined {
  if (entry === null || typeof entry !== 'object') return undefined;
  const candidate = (entry as Record<string, unknown>)['address'];
  if (typeof candidate !== 'string') return undefined;
  if (!/^0x[0-9a-fA-F]{40}$/.test(candidate)) return undefined;
  return candidate.toLowerCase();
}

// ── 5. mismatched-chainid-request ───────────────────────────────────────────

/**
 * `web3:l1:mismatched-chainid-request` — WA06 (T-A3.3).
 *
 * The dApp asserts a chain different from the one the scan configured. Two
 * detection sources:
 *  - `wallet_switchEthereumChain` / `wallet_addEthereumChain` with
 *    `params[0].chainId` not equal to the configured chain id. Classic
 *    phishing flow: dApp silently switches the user to a chain where its
 *    contracts behave differently (or where the user has no UX safety net).
 *  - `eth_signTypedData_*` with `domain.chainId` set to a chain other than
 *    the configured one. The signature would replay-validate on a chain the
 *    user did not intend to authorise.
 *
 * Severity High in both cases.
 */
const mismatchedChainIdRequestProbe: Web3L1Probe = {
  id: 'web3:l1:mismatched-chainid-request',
  technique: 'Chain-id consistency inspection',
  category: 'mismatched-chainid-request',
  severity: 'High',
  title: 'dApp asserted a chain different from the one it claims to operate on',
  description:
    'The dApp asked the wallet to switch to / add a chain other than the configured chain, or signed an EIP-712 typed-data payload bound to a different chainId. Either pattern desynchronises what the user thinks they are interacting with from what the signed payload will validate against — a phishing-favourable condition for cross-chain replay or silent network switching.',
  recommendation:
    'Verify that the chain the dApp UI advertises matches the chain its wallet requests target. Reject wallet_switchEthereumChain / wallet_addEthereumChain calls that surprise the user; check domain.chainId in every typed-data preview before signing.',
  async evaluate(target) {
    const expectedHex = chainIdHex(target.chain);
    const expectedDecimal = chainIdDecimal(target.chain);
    const requests = await target.walletRequests();
    const detections: Web3L1Detection[] = [];
    for (const req of requests) {
      detections.push(...findChainMismatch(req, expectedHex, expectedDecimal));
    }
    return detections;
  },
};

function findChainMismatch(
  req: WalletRequest,
  expectedHex: string,
  expectedDecimal: string,
): Web3L1Detection[] {
  const detections: Web3L1Detection[] = [];

  if (
    req.method === 'wallet_switchEthereumChain' ||
    req.method === 'wallet_addEthereumChain'
  ) {
    const arg = firstParam(req.params);
    const chainId = readField(arg, 'chainId');
    if (typeof chainId === 'string' && !hexChainEquals(chainId, expectedHex)) {
      detections.push({
        walletRequestSequence: req.sequence,
        walletRequestMethod: req.method,
        rationale: `${req.method} requests chainId=${chainId}, but the dApp was scanned on chainId=${expectedHex} (${expectedDecimal}).`,
        evidence: clipForEvidence(`requested chainId=${chainId}; expected chainId=${expectedHex} (${expectedDecimal} decimal).`),
        metadata: {
          pattern: 'wallet-chain-switch',
          requestedChainId: chainId,
          expectedChainId: expectedHex,
        },
      });
    }
    return detections;
  }

  if (req.method.startsWith('eth_signTypedData')) {
    const typedData = decodeTypedDataPayload(req);
    if (typedData === undefined) return detections;
    const domain = readField(typedData, 'domain');
    const chainId = readField(domain, 'chainId');
    if (chainId === undefined || chainId === null) return detections;
    if (!chainIdMatches(chainId, expectedDecimal)) {
      detections.push({
        walletRequestSequence: req.sequence,
        walletRequestMethod: req.method,
        rationale: `${req.method} domain.chainId is ${String(chainId)}, but the dApp was scanned on chainId=${expectedDecimal} (${expectedHex}).`,
        evidence: clipForEvidence(`typed-data domain.chainId=${String(chainId)}; expected ${expectedDecimal} (${expectedHex} hex). Signature would bind to a different chain than the dApp claims.`),
        metadata: {
          pattern: 'typed-data-chain-mismatch',
          domainChainId: String(chainId),
          expectedChainId: expectedDecimal,
        },
      });
    }
  }

  return detections;
}

// ── 6. permit2-mass-approval ────────────────────────────────────────────────

/**
 * `web3:l1:permit2-mass-approval` — WA06 (T-A3.3).
 *
 * Permit2 (Uniswap) is a single contract that centralises ERC-20 allowances
 * across the ecosystem. A `PermitSingle` / `PermitBatch` signature granted via
 * Permit2 with `amount === max_uint160` (Permit2's "unlimited" sentinel —
 * its amount field is uint160, not uint256) gives the spender unrestricted
 * transferFrom on the user's tokens via Permit2 until the expiration. Common,
 * dangerous, and rendered by some wallets without obvious "unlimited" framing.
 *
 * Detection: `eth_signTypedData_v4` (or _v3) with `domain.name === 'Permit2'`
 * AND a message `details.amount` (or `details[].amount`) equal to max_uint160.
 * The probe also flags direct `eth_sendTransaction` to the canonical Permit2
 * contract address (`PERMIT2_CONTRACT_ADDRESS`) — a hint that a Permit2 batch
 * approve is being sent on-chain.
 *
 * Severity High.
 */
const permit2MassApprovalProbe: Web3L1Probe = {
  id: 'web3:l1:permit2-mass-approval',
  technique: 'Permit2 (Uniswap) payload inspection',
  category: 'permit2-mass-approval',
  severity: 'High',
  title: 'dApp requested an unlimited Permit2 allowance',
  description:
    'The dApp asked the wallet to grant a Permit2 (Uniswap) allowance whose amount is the maximum uint160 value — the Permit2 equivalent of an unlimited ERC-20 approval. Permit2 lets the approved spender transferFrom the user\'s tokens at any time before the expiration, with no further wallet interaction.',
  recommendation:
    'Approve Permit2 allowances for the exact amount and short expiration the current action requires. Review and revoke active Permit2 allowances at revoke.cash or via the wallet\'s Permit2 manager.',
  async evaluate(target) {
    const requests = await target.walletRequests();
    const detections: Web3L1Detection[] = [];
    for (const req of requests) {
      detections.push(...findPermit2MassApproval(req));
    }
    return detections;
  },
};

function findPermit2MassApproval(req: WalletRequest): Web3L1Detection[] {
  const detections: Web3L1Detection[] = [];

  // Signed Permit2 grant — eth_signTypedData with Permit2 domain.
  if (req.method.startsWith('eth_signTypedData')) {
    const typedData = decodeTypedDataPayload(req);
    if (typedData === undefined) return detections;
    const domain = readField(typedData, 'domain');
    const domainName = readField(domain, 'name');
    if (domainName !== 'Permit2') return detections;
    const message = readField(typedData, 'message');
    const matches = collectPermit2MaxAmountMatches(message);
    for (const match of matches) {
      const verifyingContract = readField(domain, 'verifyingContract');
      detections.push({
        walletRequestSequence: req.sequence,
        walletRequestMethod: req.method,
        rationale: `${req.method} requests a Permit2 grant with amount=2**160-1 (Permit2's unlimited-allowance sentinel).`,
        evidence: clipForEvidence(`domain.name=Permit2; verifyingContract=${String(verifyingContract)}; token=${match.token ?? '<unknown>'}; spender=${match.spender ?? '<unknown>'}; amount=2**160-1 (unlimited).`),
        metadata: {
          pattern: 'permit2-amount-max',
          ...(match.token !== undefined ? { token: match.token } : {}),
          ...(match.spender !== undefined ? { spender: match.spender } : {}),
        },
      });
    }
    return detections;
  }

  // Direct on-chain Permit2 call — eth_sendTransaction to canonical address.
  if (req.method === 'eth_sendTransaction') {
    const tx = firstParam(req.params);
    const to = readField(tx, 'to');
    if (typeof to === 'string' && to.toLowerCase() === PERMIT2_CONTRACT_ADDRESS) {
      const data = readField(tx, 'data');
      detections.push({
        walletRequestSequence: req.sequence,
        walletRequestMethod: req.method,
        rationale: 'eth_sendTransaction targets the canonical Permit2 contract directly — Permit2 allowances grant ecosystem-wide transferFrom rights via a single approval.',
        evidence: clipForEvidence(`to=${String(to)} (canonical Permit2 contract); data=${typeof data === 'string' ? data.slice(0, 20) : '<unset>'}...; review which token/spender/amount this transaction sets.`),
        severity: 'Medium',
        description: 'The dApp sent a direct on-chain call to the canonical Permit2 contract. Permit2 allowances grant ecosystem-wide transferFrom rights — verify the exact token, spender, and amount being approved before signing the transaction.',
        metadata: { pattern: 'permit2-direct-call' },
      });
    }
  }

  return detections;
}

interface Permit2Match {
  token?: string;
  spender?: string;
}

/**
 * Walk a Permit2 message looking for `amount` fields equal to max_uint160.
 * Real Permit2 messages place the amount under `details.amount` (PermitSingle)
 * or `details[].amount` (PermitBatch). We accept either shape, plus the bare
 * `amount` slot some custom Permit2-style domains use.
 */
function collectPermit2MaxAmountMatches(message: unknown): Permit2Match[] {
  if (message === null || typeof message !== 'object') return [];
  const matches: Permit2Match[] = [];
  const msg = message as Record<string, unknown>;
  const spender = readField(msg, 'spender');
  const spenderStr = typeof spender === 'string' ? spender : undefined;

  const details = readField(msg, 'details');
  if (Array.isArray(details)) {
    for (const entry of details) {
      const match = matchPermit2Amount(entry, spenderStr);
      if (match !== undefined) matches.push(match);
    }
  } else if (details !== undefined) {
    const match = matchPermit2Amount(details, spenderStr);
    if (match !== undefined) matches.push(match);
  } else {
    // No `details` slot — try the bare `amount` field on the message itself.
    const match = matchPermit2Amount(msg, spenderStr);
    if (match !== undefined) matches.push(match);
  }
  return matches;
}

function matchPermit2Amount(entry: unknown, spender: string | undefined): Permit2Match | undefined {
  if (entry === null || typeof entry !== 'object') return undefined;
  const e = entry as Record<string, unknown>;
  const amount = e['amount'];
  if (typeof amount !== 'string' && typeof amount !== 'number') return undefined;
  const amountStr = String(amount);
  let isMax = false;
  try {
    isMax = BigInt(amountStr) === (1n << 160n) - 1n;
  } catch {
    isMax = false;
  }
  if (!isMax) {
    // Permit2 allowances are sometimes serialised as bare hex strings of length 40 (all f).
    if (typeof amount === 'string' && amount.startsWith('0x')) {
      const body = amount.slice(2).toLowerCase();
      if (body === MAX_UINT160_HEX_LOWER) isMax = true;
    }
  }
  if (!isMax) return undefined;
  const token = readField(e, 'token');
  const out: Permit2Match = {};
  if (typeof token === 'string') out.token = token;
  if (spender !== undefined) out.spender = spender;
  return out;
}

// ── Export the curated probe set ────────────────────────────────────────────

/**
 * The six L1 probes, in display order. Order is stable so report progress and
 * the per-probe result list read deterministically scan-after-scan; it has no
 * semantic meaning. Frozen so callers cannot mutate the curated set.
 *
 * Slug coverage (matches `owaspWeb3CategorySchema` L1 block exactly):
 *  - wallet-approval-phishing
 *  - deceptive-typed-data-signature
 *  - personal-sign-payload-smell
 *  - eip-7702-set-code-delegation
 *  - mismatched-chainid-request
 *  - permit2-mass-approval
 */
export const WEB3_L1_PROBES: readonly Web3L1Probe[] = Object.freeze([
  walletApprovalPhishingProbe,
  deceptiveTypedDataSignatureProbe,
  personalSignPayloadSmellProbe,
  eip7702SetCodeDelegationProbe,
  mismatchedChainIdRequestProbe,
  permit2MassApprovalProbe,
]);

// Re-export NO_L1_DETECTIONS so consumers don't have to drill into the helper module.
export { NO_L1_DETECTIONS };
