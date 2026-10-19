import { createHash } from 'node:crypto'

//** Produce a SHA-256 hex digest of the supplied bytes or UTF-8 string. */
export function sha256(data: string | Uint8Array): string {
  return createHash('sha256').update(data).digest('hex')
}

/**
 * Serialise a JSON-serialisable value with recursive dictionary-key
 * sorting and no extra whitespace. This matches Python's
 * `json.dumps(v, sort_keys=True, separators=(',', ':'))`.
 */
function canonicalize(value: unknown): string {
  if (value === null) {
    return 'null'
  }

  if (Array.isArray(value)) {
    return '[' + value.map((item) => canonicalize(item)).join(',') + ']'
  }

  if (typeof value === 'object') {
    const obj = value as Record<string, unknown>
    const keys = Object.keys(obj).sort()
    const entries = keys.map((key) => JSON.stringify(key) + ':' + canonicalize(obj[key]))
    return '{' + entries.join(',') + '}'
  }

  // Primitives (string, number, boolean) and anything JSON.stringify
  // handles directly (including undefined -> undefined, but callers pass
  // JSON-serialisable values).
  return JSON.stringify(value)
}

/**
 * Produce a canonical SHA-256 hex digest of a JSON-serialisable value.
 *
 * The value is serialised with recursive dictionary-key sorting and
 * no extra whitespace – the same encoding convention used by the
 * Harpocrates backend and contract layers.
 */
export function canonicalHash(value: unknown): string {
  return sha256(canonicalize(value))
}

/**
 * Validate that a string is a 32-byte (64-character) lowercase hex value.
 * Returns the normalised string or throws.
 */
export function asHex32(value: string, label = 'value'): string {
  if (!/^[0-9a-fA-F]{64}$/.test(value)) {
    throw new Error(`${label} must be a 32-byte hex string`)
  }
  return value.toLowerCase()
}

/**
 * Validate that a string is an even-length hex byte string.
 * Returns the normalised string or throws.
 */
export function asHexBytes(value: string, label = 'value'): string {
  if (!/^[0-9a-fA-F]{64}$/.test(value) || value.length % 2 !== 0) {
    throw new Error(`${label} must be an even-length hex byte string`)
  }
  return value.toLowerCase()
}

/** Convert a Uint8Array or array-like to a lowercase hex string. */
export function bytesToHex(value: Uint8Array | ArrayLike<number>): string {
  return Array.from(value, (b) => Number(b).toString(16).padStart(2, '0')).join('')
}

/** Convert a hex string to a Uint8Array. */
export function hexToBytes(value: string): Uint8Array {
  const normalised = asHexBytes(value)
  const bytes = new Uint8Array(normalised.length / 2)
  for (let i = 0; i < bytes.length; i++) {
    bytes[i] = Number.parseInt(normalised.slice(i * 2, i * 2 + 2), 16)
  }
  return bytes
}
