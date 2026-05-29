import type { OnChainContext } from './web3-onchain-context';
import {
  DEFAULT_RECENT_DEPLOYMENT_MAX_AGE_SECONDS,
  NO_L3_DETECTIONS,
  STALE_DEPLOYMENT_AGE_SECONDS,
  WELL_KNOWN_TOKEN_REGISTRY,
  clipForEvidence,
  type Web3L3Detection,
  type Web3L3Probe,
} from './web3-l3-probe';

/**
 * Curated Web3 L3 probes (Sprint A3, T-A3.5).
 *
 * Five probes covering OWASP SC01 (broken access control on-chain),
 * SC10 (poorly-deployed proxy), and WA10 (token impersonation) — see
 * `category.ts` for the framework synthesis. Exactly one probe per L3 slug
 * from `owaspWeb3CategorySchema`; the slug list is the contract. The
 * aggregate `elevated-risk-contract` finding is composed by the runner
 * (`web3-l3.ts`) AFTER per-probe evaluation, NOT by a probe — keep this
 * file focused on the indicator rules themselves.
 *
 * Probes consume a single `OnChainContext` (the loader's per-address output)
 * and inspect already-fetched fields. They do NOT round-trip to the chain or
 * to an explorer — that's the loader's job. A probe that needs a field the
 * loader couldn't fetch (`availability !== 'complete'`) returns no detection
 * rather than guessing; the runner's coverage gap surfaces honestly that L3
 * did not have the whole picture.
 *
 * Honesty rules (mirror api-probes / web3-l1-probes):
 *  - "I checked and the indicator isn't present" returns an empty array,
 *    never throws.
 *  - Negative findings ("contract is verified") are NOT emitted — silence is
 *    silence in this layer.
 *  - Evidence carries only the offending field(s), not the whole context
 *    blob. Provider API keys NEVER appear (sub-agent rubric §12 — the
 *    `OnChainContext` shape carries none, so this is structural, not a
 *    runtime check).
 */

// ── 1. contract-source-not-verified ─────────────────────────────────────────

/**
 * `web3:l3:contract-source-not-verified` — SC10 (T-A3.5).
 *
 * Fires when the explorer reports the contract's source as unverified. The
 * spec calls for Low/Medium calibration depending on age: a contract that has
 * been on-chain for a long time and remained unverified is a different signal
 * from one deployed yesterday with no source. The probe uses
 * `STALE_DEPLOYMENT_AGE_SECONDS` as the cutoff: older → Low (default Low is
 * the field on the probe), younger or unknown → Medium (per-detection
 * override). When the explorer record is missing entirely the probe is
 * SILENT — the loader's coverage gap captures the "we couldn't check" case.
 */
const contractSourceNotVerifiedProbe: Web3L3Probe = {
  id: 'web3:l3:contract-source-not-verified',
  technique: 'Explorer source-verification check',
  category: 'contract-source-not-verified',
  severity: 'Low',
  title: 'Contract source code is not verified on the block explorer',
  description:
    "The block explorer does not have the contract's source code on file. A user interacting with the contract is approving logic they cannot read, and tools that rely on verified ABIs (wallet decoders, block explorers' \"decode input\" feature) cannot translate the on-chain calldata into human-readable actions. This is an indicator, not a verdict — long-running legitimate contracts are sometimes verified only on an explorer the scan did not consult — but warrants extra caution before signing.",
  recommendation:
    'Check the contract on a second block explorer before granting any allowance. If no explorer carries verified source, treat any wallet interaction with this contract as high-risk: the logic the user is approving is opaque.',
  evaluate(context) {
    const detections: Web3L3Detection[] = [];
    if (context.explorer === null) return NO_L3_DETECTIONS;
    if (context.explorer.sourceVerified !== false) return NO_L3_DETECTIONS;
    const deployedAt = context.explorer.deploymentTimestamp;
    const isOldEnoughToBeFresh = deployedAt !== null
      ? nowSeconds() - deployedAt < STALE_DEPLOYMENT_AGE_SECONDS
      : true; // unknown age → treat as fresh (more cautious)
    const severity = isOldEnoughToBeFresh ? 'Medium' : 'Low';
    detections.push({
      address: context.address,
      severity,
      rationale: `Explorer reports sourceVerified=false for ${context.address} on ${context.chain}.`,
      evidence: clipForEvidence(
        `address=${context.address}; chain=${context.chain}; sourceVerified=false; deploymentTimestamp=${
          deployedAt === null ? '<unknown>' : String(deployedAt)
        }; severity=${severity} (${isOldEnoughToBeFresh ? 'fresh/unknown deployment age' : 'older than 180 days — verification likely intentional gap'}).`,
      ),
      metadata: {
        ageBucket: isOldEnoughToBeFresh ? 'fresh-or-unknown' : 'aged',
        ...(deployedAt !== null ? { deploymentTimestamp: String(deployedAt) } : {}),
      },
    });
    return detections;
  },
};

// ── 2. proxy-without-verified-implementation ────────────────────────────────

/**
 * `web3:l3:proxy-without-verified-implementation` — SC10 (T-A3.5).
 *
 * Two materially different failure modes share this slug; severity diverges:
 *  - **Medium**: the contract is a proxy but the implementation slot is empty
 *    / unresolved (legacy proxy patterns, beacon proxies, custom delegates).
 *    The L3 loader cannot find the implementation address; the upgradeable
 *    logic the user is approving is therefore unknown.
 *  - **High**: the implementation address IS known, but the explorer reports
 *    its source as unverified. The user is approving a proxy that points at
 *    opaque, swappable code — strictly worse than an unverified non-proxy
 *    because the contract author can change the logic without re-deploying.
 *
 * The second branch needs to know the implementation's source-verified
 * status. The L3 loader (T-A3.4) currently fetches the implementation slot
 * but does NOT recursively fetch the implementation's explorer record (one
 * round-trip per address is the contract). So the probe can only emit the
 * Medium variant from the inputs available here; the High variant fires when
 * the proxy structure resolves but the loader's per-address fetch of the
 * implementation address yields an unverified explorer record — surfaced via
 * the runner's address-coverage layer in a follow-up enhancement. For now we
 * emit Medium when the proxy implementation is unresolved.
 */
const proxyWithoutVerifiedImplementationProbe: Web3L3Probe = {
  id: 'web3:l3:proxy-without-verified-implementation',
  technique: 'EIP-1967 proxy slot + explorer cross-check',
  category: 'proxy-without-verified-implementation',
  severity: 'Medium',
  title: 'Contract is a proxy whose implementation could not be resolved or is unverified',
  description:
    "The contract is a proxy (the EIP-1967 implementation slot is non-empty, or the bytecode shape matches a known delegate pattern), but the implementation address could not be resolved from the inputs L3 fetched. A user approving a proxy whose implementation logic is unknown is approving upgradeable code they cannot review. This is an indicator, not a verdict — the proxy may simply use a non-standard storage pattern — but warrants extra caution.",
  recommendation:
    'Identify the implementation address out-of-band (the project\'s documentation or a second explorer) and verify the implementation\'s source is published before granting allowances to the proxy.',
  evaluate(context) {
    if (context.proxy === null) return NO_L3_DETECTIONS;
    if (!context.proxy.isProxy) return NO_L3_DETECTIONS;
    // Detection only fires when the implementation is missing — a proxy with
    // a resolved implementation address whose source we cannot judge here is
    // silent at this layer (the per-implementation verified check is a
    // T-A3.5 follow-up; see probe header note).
    if (context.proxy.implementation !== null) return NO_L3_DETECTIONS;
    const detection: Web3L3Detection = {
      address: context.address,
      rationale: `${context.address} bytecode / storage indicates a proxy but the implementation address could not be resolved from the EIP-1967 storage slots.`,
      evidence: clipForEvidence(
        `address=${context.address}; chain=${context.chain}; isProxy=true; implementation=<unresolved>; admin=${
          context.proxy.admin ?? '<unresolved>'
        }.`,
      ),
      metadata: {
        proxyResolution: 'implementation-unresolved',
        ...(context.proxy.admin !== null ? { proxyAdmin: context.proxy.admin } : {}),
      },
    };
    return [detection];
  },
};

// ── 3. eoa-admin-single-key ─────────────────────────────────────────────────

/**
 * `web3:l3:eoa-admin-single-key` — SC01 (T-A3.5).
 *
 * Fires when `owner()` (or its variants surfaced in `admin.ownerKind`)
 * resolves to an EOA — a single externally-owned account can sign upgrades
 * or admin actions alone, with no multisig delay or timelock. Severity is
 * Medium by default; per-detection elevates to High when COMBINED on the
 * same context with an unverified source (the upgrade path has no time-lock
 * AND the code is opaque). The COMBINATION check stays local to this probe
 * — it inspects fields of the same `OnChainContext` it was given, so the
 * elevation logic is auditable without cross-probe coupling.
 *
 * Silence when:
 *  - `admin === null` (the loader couldn't fetch the role surface),
 *  - `ownerKind === 'not-exposed'` (the contract doesn't have an `owner()`
 *    accessor — many DeFi contracts are deliberately ownership-renounced),
 *  - `ownerKind !== 'eoa'` (a contract owner is likely a multisig / timelock,
 *    which is the GOOD pattern).
 */
const eoaAdminSingleKeyProbe: Web3L3Probe = {
  id: 'web3:l3:eoa-admin-single-key',
  technique: 'owner() / pendingOwner() resolution + EOA check',
  category: 'eoa-admin-single-key',
  severity: 'Medium',
  title: 'Contract admin / owner is a single externally-owned account',
  description:
    "The contract's owner() accessor returns an externally-owned account (EOA), not a contract. A single keyholder can sign privileged actions (upgrades, parameter changes, withdrawals) alone — no multisig threshold, no time-lock delay. This is an indicator, not a verdict — some legitimate small projects keep a single-key admin during early operation — but it means the entire trust assumption of the contract rests on one private key.",
  recommendation:
    'Treat any contract with a single-EOA owner as one with elevated centralisation risk. Before granting allowances or significant deposits, confirm the project\'s governance roadmap (multisig migration, time-lock adoption) and weigh the size of the position accordingly.',
  evaluate(context) {
    if (context.admin === null) return NO_L3_DETECTIONS;
    if (context.admin.ownerKind !== 'eoa') return NO_L3_DETECTIONS;
    const owner = context.admin.owner;
    const ownerStr = owner ?? '<unset>';
    // Combined-context elevation: EOA admin AND unverified source → High.
    const sourceUnverified = context.explorer?.sourceVerified === false;
    const severity = sourceUnverified ? 'High' : 'Medium';
    const description = sourceUnverified
      ? "The contract is owned by a single externally-owned account (EOA) AND its source code is not verified on the explorer. The admin path has no multisig threshold or time-lock delay, and the on-chain logic the user is approving is opaque. This combination is a stronger indicator than either signal alone — the project's entire trust assumption rests on one key whose contract a user cannot read."
      : undefined;
    const detection: Web3L3Detection = {
      address: context.address,
      severity,
      rationale: sourceUnverified
        ? `${context.address}: owner() resolves to EOA ${ownerStr} AND explorer reports sourceVerified=false — combined indicator elevates severity to High.`
        : `${context.address}: owner() resolves to EOA ${ownerStr}.`,
      evidence: clipForEvidence(
        `address=${context.address}; chain=${context.chain}; owner=${ownerStr}; ownerKind=eoa${
          sourceUnverified ? '; sourceVerified=false (combined indicator → High)' : ''
        }.`,
      ),
      ...(description !== undefined ? { description } : {}),
      metadata: {
        ownerKind: 'eoa',
        ...(owner !== null ? { owner } : {}),
        ...(sourceUnverified ? { combinedWithUnverifiedSource: 'true' } : {}),
      },
    };
    return [detection];
  },
};

// ── 4. recent-contract-deployment ───────────────────────────────────────────

/**
 * `web3:l3:recent-contract-deployment` — SC10 + WA10 framing (T-A3.5).
 *
 * Fires when `explorer.deploymentTimestamp` is within
 * `DEFAULT_RECENT_DEPLOYMENT_MAX_AGE_SECONDS` (72h by default) of "now". Flat
 * Medium per the spec — a fresh deployment doesn't prove malice; many
 * legitimate projects ship contracts and surface them on day one. The
 * indicator framing matters because phishing flows lean on freshly-deployed
 * router/spender contracts (the older the bad address, the more chance it
 * was flagged by community trackers).
 *
 * Silence when:
 *  - explorer record absent (the loader couldn't fetch),
 *  - deploymentTimestamp null (the explorer record exists but doesn't carry
 *    a deployment time — many older explorer APIs don't),
 *  - deployment older than the cutoff.
 *
 * The "now" reference is taken at evaluation time — `nowSeconds()` is the
 * only non-input boundary the probe touches; documented here so tests can
 * inject a fake clock via the runner if they need deterministic age math.
 */
const recentContractDeploymentProbe: Web3L3Probe = {
  id: 'web3:l3:recent-contract-deployment',
  technique: 'Explorer deployment-timestamp inspection',
  category: 'recent-contract-deployment',
  severity: 'Medium',
  title: 'Contract was deployed in the last 72 hours',
  description:
    'The contract was deployed on-chain within the last 72 hours according to the block explorer. Fresh deployments are common in legitimate launches AND in phishing flows — the latter rely on brand-new spender/router contracts that community trackers have not yet flagged. This is an indicator, not a verdict; treat a fresh contract as one whose reputation has not had time to accumulate.',
  recommendation:
    'Avoid granting unlimited allowances to brand-new contracts. Verify the project\'s legitimacy through independent channels (founder presence, audit reports, deployer history) before signing transactions that grant the contract authority over user funds.',
  evaluate(context) {
    if (context.explorer === null) return NO_L3_DETECTIONS;
    const deployedAt = context.explorer.deploymentTimestamp;
    if (deployedAt === null) return NO_L3_DETECTIONS;
    const ageSeconds = nowSeconds() - deployedAt;
    if (ageSeconds > DEFAULT_RECENT_DEPLOYMENT_MAX_AGE_SECONDS) return NO_L3_DETECTIONS;
    if (ageSeconds < 0) {
      // Clock skew or explorer time in the future. Don't fabricate "negative
      // age" findings — silence is the honest answer.
      return NO_L3_DETECTIONS;
    }
    const ageHours = Math.floor(ageSeconds / 3600);
    const detection: Web3L3Detection = {
      address: context.address,
      rationale: `${context.address} was deployed ${ageHours}h ago (under the 72h freshness cutoff).`,
      evidence: clipForEvidence(
        `address=${context.address}; chain=${context.chain}; deploymentTimestamp=${deployedAt} (~${ageHours}h ago); cutoff=${DEFAULT_RECENT_DEPLOYMENT_MAX_AGE_SECONDS / 3600}h.`,
      ),
      metadata: {
        deploymentTimestamp: String(deployedAt),
        ageHours: String(ageHours),
      },
    };
    return [detection];
  },
};

// ── 5. token-impersonation-indicator ────────────────────────────────────────

/**
 * `web3:l3:token-impersonation-indicator` — WA10 (T-A3.5).
 *
 * Fires when the contract's explorer-reported `contractName` matches a token
 * in `WELL_KNOWN_TOKEN_REGISTRY` on the same chain AND the contract's address
 * is NOT the canonical one for that token on that chain. This is the one L3
 * indicator the spec allows to be phrased strongly — the name collision is a
 * verifiable structural fact, not a probabilistic signal — but the
 * recommendation still reads as user-actionable caution, not as a
 * pronouncement against the contract author (a legitimate fork might
 * deliberately name itself `USDC-bridged-${something}`; we match exact
 * canonical names only).
 *
 * Severity High per the spec.
 *
 * Silence when:
 *  - explorer record absent or contractName null,
 *  - contractName doesn't match any registry entry (case-insensitive,
 *    exact-match on the canonical name — substring matches and
 *    "USDC-bridged" variants intentionally do NOT fire),
 *  - matched token has no canonical address registered for this chain,
 *  - matched token's canonical address EQUALS the contract's address — the
 *    contract IS the canonical token, no impersonation.
 */
const tokenImpersonationIndicatorProbe: Web3L3Probe = {
  id: 'web3:l3:token-impersonation-indicator',
  technique: 'Well-known-token name vs canonical-address cross-check',
  category: 'token-impersonation-indicator',
  severity: 'High',
  title: 'Contract bears a well-known token name at a non-canonical address',
  description:
    "The contract's verified name on the block explorer matches a well-known token (USDC / USDT / DAI / WETH) but the contract address is NOT the canonical address for that token on this chain. A user who recognises only the name and approves the contract may be approving a look-alike — phishing flows exploit this by routing the wallet's approve call to a contract that displays a familiar symbol in the wallet UI.",
  recommendation:
    'Before approving the contract, verify its address character-for-character against the project\'s official documentation. Wallet UIs that show the token symbol prominently can mask the address mismatch; copy the address and check it against the canonical list (e.g. coingecko.com or the project\'s docs) yourself.',
  evaluate(context) {
    if (context.explorer === null) return NO_L3_DETECTIONS;
    const name = context.explorer.contractName;
    if (name === null) return NO_L3_DETECTIONS;
    const normalised = name.toUpperCase();
    const match = WELL_KNOWN_TOKEN_REGISTRY.find((t) => t.name === normalised);
    if (match === undefined) return NO_L3_DETECTIONS;
    const canonical = match.byChain[context.chain];
    if (canonical === undefined) return NO_L3_DETECTIONS; // token not deployed on this chain
    const ours = context.address.toLowerCase();
    if (ours === canonical.toLowerCase()) return NO_L3_DETECTIONS; // legitimate canonical contract
    const detection: Web3L3Detection = {
      address: context.address,
      rationale: `${context.address} is verified on the explorer as "${name}" but the canonical ${match.name} on ${context.chain} is ${canonical}.`,
      evidence: clipForEvidence(
        `address=${context.address}; chain=${context.chain}; contractName="${name}"; canonical-${match.name}-on-${context.chain}=${canonical}.`,
      ),
      metadata: {
        contractName: name,
        canonicalToken: match.name,
        canonicalAddress: canonical,
      },
    };
    return [detection];
  },
};

// ── Time abstraction ────────────────────────────────────────────────────────

/**
 * Single "now" boundary the probes touch. Returns unix seconds. Pulled out so
 * runner-level tests (`web3-l3.test.ts`) can stub it via a probe-set override
 * if a deterministic clock is needed; individual probe tests pass timestamps
 * relative to `Date.now()` directly, which keeps the probe surface small.
 */
function nowSeconds(): number {
  return Math.floor(Date.now() / 1000);
}

// ── Export the curated probe set ────────────────────────────────────────────

/**
 * The five L3 probes, in display order. Order is stable so report progress
 * and the per-probe result list read deterministically scan-after-scan; it
 * has no semantic meaning. Frozen so callers cannot mutate the curated set.
 *
 * Slug coverage (matches `owaspWeb3CategorySchema` L3 block exactly, ONE
 * probe per indicator slug — the aggregate `elevated-risk-contract` slug is
 * NOT a probe; the runner composes it):
 *  - contract-source-not-verified
 *  - proxy-without-verified-implementation
 *  - eoa-admin-single-key
 *  - recent-contract-deployment
 *  - token-impersonation-indicator
 */
export const WEB3_L3_PROBES: readonly Web3L3Probe[] = Object.freeze([
  contractSourceNotVerifiedProbe,
  proxyWithoutVerifiedImplementationProbe,
  eoaAdminSingleKeyProbe,
  recentContractDeploymentProbe,
  tokenImpersonationIndicatorProbe,
]);
