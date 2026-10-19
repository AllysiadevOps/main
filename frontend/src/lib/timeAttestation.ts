/**
 * timeAttestation — typed helpers for on-chain timestamp claims.
 *
 * The Harpocrates registry contract stores a timestamp claim with a
 * `sources` bitflag field (see `contracts/TIMESTAMP_CLAIMS.MD`). This module
 * decodes those flags into a stable, typed JS shape so the frontend can
 * reason about which timestamp sources back a given proof.
 */

/**
 * Decoded source flags for a timestamp claim.
 *
 * - `stellar`: ledger timestamp + sequence recorded (bit 0x02).
 * - `claimed`: optional claimed capture time present (bit 0x01).
 * - `rfc3161`: 32-byte RFC 3161 token commitment present (bit 0x04).
 */
export type TimestampSources = {
  stellar: boolean
  claimed: boolean
  rfc3161: boolean
}

/** Bit flag constants as defined by the contract. */
export const TIMESTAMP_SOURCE_CLAIMED = 0x01
export const TIMESTAMP_SOURCE_STELLAR = 0x02
export const TIMESTAMP_SOURCE_RFC3161 = 0x04

/**
 * Decode the contract's `sources` bitflag into a typed object.
 *
 * Unknown bits are ignored. A non-finite or negative input decodes to all
 * `false` so callers always get a stable shape.
 */
export function decodeTimestampSources(sources: number): TimestampSources {
  if (typeof sources !== 'number' || !Number.isFinite(sources) || sources < 0) {
    return { stellar: false, claimed: false, rfc3161: false }
  }
  const flags = Math.trunc(sources)
  return {
    stellar: (flags & TIMESTAMP_SOURCE_STELLAR) === TIMESTAMP_SOURCE_STELLAR,
    claimed: (flags & TIMESTAMP_SOURCE_CLAIMED) === TIMESTAMP_SOURCE_CLAIMED,
    rfc3161: (flags & TIMESTAMP_SOURCE_RFC3161) === TIMESTAMP_SOURCE_RFC3161,
  }
}
