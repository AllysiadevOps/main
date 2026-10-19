/**
 * harpocratesRegistry — typed reader for the Harpocrates registry contract.
 *
 * Wraps the on-chain `get_metadata_envelope(proof_id)` view function described in
 * `contracts/METADATA_ENVELOPE.md`. The envelope bonds a proof record to the
 * metadata hash that was embedded in the artifact at bind time.
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
 * Adapter that performs the actual contract call. Injectable so hook tests can
 * mock the registry without network access.
 */
export type MetadataEnvelopeReader = (proofId: string) => Promise<RawMetadataEnvelope | null | undefined>

let readerOverride: MetadataEnvelopeReader | null = null

/**
 * Test-only hook to install a fake registry reader. Passing `null` restores
 * the default reader.
 */
export function __setMetadataEnvelopeReaderForTests(reader: MetadataEnvelopeReader | null): void {
  readerOverride = reader
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
 * Default reader that delegates to the contract via the shared verification
 * service. The service owns the Stellar client and contract ID configuration,
 * so this wrapper stays free of duplicated network setup.
 */
async function defaultReader(proofId: string): Promise<RawMetadataEnvelope | null> {
  const { getMetadataEnvelopeRaw } = await import('../services/verificationService')
  const raw = await getMetadataEnvelopeRaw(proofId)
  return raw ?? null
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
  const raw = await reader(prooofId.trim())
  return normaliseMetadataEnvelope(raw)
}
