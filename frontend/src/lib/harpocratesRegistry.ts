/**
 * harpocratesRegistry — typed reader for the Harpocrates registry contract.
 *
 * Wraps the on-chain `get_metadata_envelope(proof_id)` view function described in
 * `contracts/METADATA_ENVELOPE.md`. The envelope bonds a proof record to the
 * metadata hash that was embedded in the artifact at bind time.
 *
 * Also wraps the timestamp-claim read functions described in
 * `contracts/TIMESTAMP_CLAIMS.md`: `get_timestamp_claim(proof_id)` and
 * `has_independent_timestamp_anchor(proof_id)`.
 *
 * This module is intentionally thin: it only normalises the contract response
 * into a stable JS shape and returns `null` when no envelope is bound. It never
 * throws for an absent envelope, so callers can treat "no envelope" as a
 * non-fatal, optional signal.
 */

import type { ApiClientError } from '../services/apiError'

/**
 * Normalised on-chain metadata envelope.
 *
 * - `version`: envelope schema version as reported by the contract.
 * - `metadataHash`: hex encoded metadata hash bound to the proof (lowercased).
 * - `boundAt`: Unix timestamp (seconds) when the envelope was bound.
 */
export type MetadataEnvelope = {
  version: number
  metadataHash: string
  boundAt: number
}

/**
 * Typed decoding of the `claim_sources` bit flags on a timestamp claim.
 *
 * - `stellar`: the claim is anchored on the Stellar ledger.
 * - `claimed`: the claim was asserted by the proof owner.
 * - `rfc3161`: the claim is backed by an RFC3161 timestamp token.
 */
export type TimestampClaimSources = {
  stellar: boolean
  claimed: boolean
  rfc3161: boolean
}

/**
 * Normalised on-chain timestamp claim.
 *
 * - `proofId`: the proof the claim belongs to.
 * - `claimedAt`: Unix timestamp (seconds) when the claim was recorded.
 * - `sources`: decoded claim source bit flags.
 * - `sourcesRaw`: the raw bit flag integer as reported by the contract.
 */
export type TimestampClaim = {
  proofId: string
  claimedAt: number
  sources: TimestampClaimSources
  sourcesRaw: number
}

/**
 * Shape of the raw value returned by the contract's `get_metadata_envelope`
 * view. Stellar contracts return `Option<MetadataEnvelope>`, which the SDK decodes
 * as `undefined` / `null` when empty, or an object with snake_case keys.
 */
type RawMetadataEnvelope = {
  version?: number | string
  metadata_hash?: string
  metadataHash?: string
  bound_at?: number | string
  boundAt?: number | string
}

/**
 * Shape of the raw value returned by the contract's `get_timestamp_claim`
 * view. Stellar contracts return `Option<TimestampClaim>`, which the SDK decodes
 * as `undefined` / `null` when empty, or an object with snake_case keys.
 */
type RawTimestampClaim = {
  proof_id?: string
  proofId?: string
  claimed_at?: number | string
  claimedAt?: number | string
  sources?: number | string
}

/**
 * Adapter that performs the actual contract call. Injectable so hook tests can
 * mock the registry without network access.
 */
export type MetadataEnvelopeReader = (proofId: string) => Promise<RawMetadataEnvelope | null | undefined>

/**
 * Adapter that performs the actual timestamp-claim contract call. Injectable so
 * hook tests can mock the registry without network access.
 */
export type TimestampClaimReader = (proofId: string) => Promise<RawTimestampClaim | null | undefined>

/**
 * Adapter for the `has_independent_timestamp_anchor` view. Injectable for tests.
 */
export type IndependentTimestampAnchorReader = (proofId: string) => Promise<boolean | null | undefined>

let readerOverride: MetadataEnvelopeReader | null = null
let timestampClaimReaderOverride: TimestampClaimReader | null = null
let independentAnchorReaderOverride: IndependentTimestampAnchorReader | null = null

/**
 * Test-only hook to install a fake registry reader. Passing `null` restores
 * the default reader.
 */
export function __setMetadataEnvelopeReaderForTests(reader: MetadataEnvelopeReader | null): void {
  readerOverride = reader
}

/**
 * Test-only hook to install a fake timestamp-claim reader. Passing `null`
 * restores the default reader.
 */
export function __setTimestampClaimReaderForTests(reader: TimestampClaimReader | null): void {
  timestampClaimReaderOverride = reader
}

/**
 * Test-only hook to install a fake independent-anchor reader. Passing `null`
 * restores the default reader.
 */
export function __setIndependentTimestampAnchorReaderForTests(
  reader: IndependentTimestampAnchorReader | null,
): void {
  independentAnchorReaderOverride = reader
}

function toNumber(value: number | string | undefined): number | null {
  if (typeof value === 'number') return Number.isFinite(value) ? value : null
  if (typeof value === 'string') {
    const parsed = Number(value)
    return Number.isFinite(parsed) ? parsed : null
  }
  return null
}

function normaliseHash(value: string | undefined): string | null {
  if (typeof value !== 'string') return null
  const trimmed = value.trim().toLowerCase()
  return trimmed.length > 0 ? trimmed : null
}

/**
 * Normalise a raw contract response into a `MetadataEnvelope`. Returns `null`
 * if the response is absent or incomplete (e.g. missing hash), so callers can
 * treat it as "no envelope bound" rather than a false mismatch.
 */
export function normaliseMetadataEnvelope(
  raw: RawMetadataEnvelope | null | undefined,
): MetadataEnvelope | null {
  if (!raw) return null
  const version = toNumber(raw.version)
  const metadataHash = normaliseHash(raw.metadata_hash ?? raw.metadataHash)
  const boundAt = toNumber(raw.bound_at ?? raw.boundAt)
  if (version === null || metadataHash === null || boundAt === null) {
    return null
  }
  return { version, metadataHash, boundAt }
}

/**
 * Bit flags for the `claim_sources` field on a timestamp claim. Must match the
 * contract definition in `contracts/TIMESTAMP_CLAIMS.md`.
 */
export const TIMESTAMP_CLAIM_SOURCE_STALLAR = 1 << 0
export const TIMESTAMP_CLAIM_SOURCE_CLAIMED = 1 << 1
export const TIMESTAMP_CLAIM_SOURCE_RFC3161 = 1 << 2

/**
 * Decode the `claim_sources` bit flags into a typed `TimestampClaimSources`
 * object. Unknown bits are ignored so forward-compatible additions to the
 * contract do not break the frontend.
 */
export function decodeTimestampClaimSources(flags: number | string | null | undefined): TimestampClaimSources {
  const value = toNumber(flags ?? undefined)
  if (value === null) {
    return { stellar: false, claimed: false, rfc3161: false }
  }
  const intFlags = Math.trunc(value)
  return {
    stellar: (intFlags & TIMESTAMP_CLAIM_SOURCE_STALLAR) !== 0,
    claimed: (intFlags & TIMESTAMP_CLAIM_SOURCE_CLAIMED) !== 0,
    rfc3161: (intFlags & TIMESTAMP_CLAIM_SOURCE_RFC3161) !== 0,
  }
}

/**
 * Normalise a raw contract response into a `TimestampClaim`. Returns `null`
 * if the response is absent or incomplete (e.g. missing timestamp), so callers
 * can treat it as "no claim" rather than a false negative.
 */
export function normaliseTimestampClaim(
  raw: RawTimestampClaim | null | undefined,
  proofIdHint?: string,
): TimestampClaim | null {
  if (!raw) return null
  const proofId = (raw.proof_id ?? raw.proofId ?? proofIdHint ?? '').trim()
  if (proofId.length === 0) return null
  const claimedAt = toNumber(raw.claimed_at ?? raw.claimedAt)
  if (claimedAt === null) return null
  const sourcesRaw = toNumber(raw.sources ?? undefined) ?? 0
  return {
    proofId,
    claimedAt,
    sources: decodeTimestampClaimSources(sourcesRaw),
    sourcesRaw,
  }
}

/**
 * Default reader that delegates to the contract via the shared verification
 * service. The service owns the Stellar client and contract ID configuration,
 * so this wrapper stays free of duplicated network setup.
 */
async function defaultReader(proofId: string): Promise<RawMetadataEnvelope | null> {
  const { getMetadataEnvelopeRaw } = await import('../services/verificationService')
  const raw = await getMetadataEnvelopeRaw(proofId)
  return raw ?? null
}

async function defaultTimestampClaimReader(proofId: string): Promise<RawTimestampClaim | null> {
  const { getTimestampClaimRaw } = await import('../services/verificationService')
  const raw = await getTimestampClaimRaw(proofId)
  return raw ?? null
}

async function defaultIndependentAnchorReader(proofId: string): Promise<boolean | null> {
  const { getIndependentTimestampAnchorRaw } = await import('../services/verificationService')
  const raw = await getIndependentTimestampAnchorRaw(proofId)
  return typeof raw === 'boolean' ? raw : null
}

/**
 * Read the on-chain metadata envelope for a proof.
 *
 * Returns `{ version, metadataHash, boundAt }` when an envelope is bound, or
 * `null` when no envelope exists. Network/decoding errors propagate to the
 * caller so it can decide whether to surface a dependency failure.
 */
export async function getMetadataEnvelope(proofId: string): Promise<MetadataEnvelope | null> {
  if (typeof proofId !== 'string' || proofId.trim().length === 0) {
    return null
  }
  const reader = readerOverride ?? defaultReader
  const raw = await reader(proofId.trim())
  return normaliseMetadataEnvelope(raw)
}

/**
 * Read the on-chain timestamp claim for a proof.
 *
 * Returns `{ proofId, claimedAt, sources, sourcesRaw }` when a claim is recorded,
 * or `null` when no claim exists. Network/decoding errors propagate to the
 * caller so it can decide whether to surface a dependency failure.
 */
export async function getTimestampClaim(proofId: string): Promise<TimestampClaim | null> {
  if (typeof proofId !== 'string' || proofId.trim().length === 0) {
    return null
  }
  const trimmed = proofId.trim()
  const reader = timestampClaimReaderOverride ?? defaultTimestampClaimReader
  const raw = await reader(trimmed)
  return normaliseTimestampClaim(raw, trimmed)
}

/**
 * Read whether a proof has an independent timestamp anchor.
 *
 * Returns the contract boolean, or `null` when the proof id is invalid or the
 * contract response could not be interpreted as a boolean.
 */
export async function hasIndependentTimestampAnchor(proofId: string): Promise<boolean | null> {
  if (typeof proofId !== 'string' || proofId.trim().length === 0) {
    return null
  }
  const reader = independentAnchorReaderOverride ?? defaultIndependentAnchorReader
  const raw = await reader(proofId.trim())
  return typeof raw === 'boolean' ? raw : null
}