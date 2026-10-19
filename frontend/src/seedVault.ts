const BN254_FIELD_MODULUS =
  21888242871839275222246405745257275088548364400416034343698204186575808495617n

function hex(buffer: ArrayBuffer) {
  return [...new Uint8Array(buffer)]
    .map((byte) => byte.toString(16).padStart(2, '0'))
    .join('')
}

async function sha256(input: ArrayBuffer | string) {
  const bytes = typeof input === 'string' ? new TextEncoder().encode(input) : input
  return hex(await crypto.subtle.digest('SHA-256', bytes))
}

export { fieldSecret } from './utils'

/**
 * Derive a BN254 field element from a scope string.
 *
 * The scope string is encoded as:
 *   SHA-256("harpocrates:scope:{scopeString}") % BN254_FIELD_MODULUS
 *
 * Scope strings must be non-empty ASCII, max 64 bytes, lowercase, no whitespace.
 * Returns a decimal string suitable for use as a Noir public input.
 */
export async function deriveScopeField(scopeString: string): Promise<string> {
  if (!scopeString || scopeString.length === 0) {
    throw new Error('Scope string must not be empty.')
  }
  if (scopeString.length > 64) {
    throw new Error('Scope string must be at most 64 bytes.')
  }
  if (!/^[a-z0-9:_-]+$/.test(scopeString)) {
    throw new Error(
      'Scope string must be lowercase ASCII alphanumeric with colons, hyphens, or underscores only.'
    )
  }
  const digest = await sha256(`harpocrates:scope:${scopeString}`)
  const value = BigInt(`0x${digest}`) % BN254_FIELD_MODULUS
  return value === 0n ? '1' : value.toString(10)
}

/**
 * Derive a scope field element from a verifier address and optional purpose.
 *
 * Canonical format: "v:{verifierAddress}:p:{purpose}"
 * If purpose is empty, uses "v:{verifierAddress}:p:default"
 */
export async function deriveVerifierScope(
  verifierAddress: string,
  purpose: string = 'default'
): Promise<string> {
  const normalizedVerifier = verifierAddress.toLowerCase().trim()
  const normalizedPurpose = purpose.toLowerCase().trim() || 'default'
  const scopeString = `v:${normalizedVerifier}:p:${normalizedPurpose}`
  return deriveScopeField(scopeString)
}

export type SeedPair = {
  credentialSeed: string
  nullifierSeed: string
}

export class InvalidSeedError extends Error {}

export function deriveSeeds(raw: SeedPair): SeedPair {
  const cSeed = raw.credentialSeed.trim()
  const nSeed = raw.nullifierSeed.trim()

  if (cSeed.length > 256 || nSeed.length > 256) {
    throw new InvalidSeedError('Seeds must be 256 characters or fewer')
  }

  return {
    credentialSeed: cSeed,
    nullifierSeed: nSeed,
  }
}

export function hasSeeds(raw: SeedPair): boolean {
  return raw.credentialSeed.trim().length > 0 && raw.nullifierSeed.trim().length > 0 && raw.credentialSeed.trim().length <= 256 && raw.nullifierSeed.trim().length <= 256
}

export function createClearSeeds(setter: (value: string) => void): () => void {
  return () => {
    setter('')
  }
}
