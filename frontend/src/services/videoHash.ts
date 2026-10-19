/**
 * videoHash — shared validation for video hashes used in backend URL paths.
 *
 * A video hash is a SHA-256 digest rendered as 64 lowercase hex characters.
 * Validating before interpolating into a URL prevents path/query injection.
 */

export const VIDEO_HASH_PATTERN = /^[0-9a-f]{64}$/

// Typed validation error so callers can distinguish bad input from network failures.
export class InvalidVideoHashError extends Error {
  readonly videoHash: unknown

  constructor(videoHash: unknown) {
    super('Invalid video hash: expected 64 lowercase hex characters.')
    this.name = 'InvalidVideoHashError'
    this.videoHash = videoHash
  }
}

/** Return true when the value is a 64-char lowercase hex string. */
export function isValidVideoHash(value: unknown): value is string {
  return typeof value === 'string' && VIDEO_HASH_PATTERN.test(value)
}

/**
 * Validate a video hash and return its URL-safe encoded form.
 * Throws InvalidVideoHashError for any non-conforming input.
 */
export function assertValidVideoHash(value: unknown): string {
  if (!isValidVideoHash(value)) {
    throw new InvalidVideoHashError(value)
  }
  // Defence in depth: hex is already URL-safe, but encode anyway.
  return encodeURIComponent(value)
}
