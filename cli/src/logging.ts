/**
 * Privacy-safe logging utilities.
 * Ensures sensitive fields are redacted before reaching logs or storage.
 *
 * The key set mirrors the backend `logging_utils.SENSITIVE_KEYS` so CLI and
 * server redaction behave identically. Keys are matched exactly (case and
 * punctuation-insensitive) so public protocol identifiers such as `proofId`
 * and `metadataHash` survive redaction.
 */

export const REDACTED_VALUE = '[REDACTED]'

const SENSITIVE_KEYS = new Set([
  'authorization',
  'cookie',
  'credentialsecret',
  'nullifiersecret',
  'password',
  'privatekey',
  'proof',
  'publicinputs',
  'rawbytes',
  'secret',
  'token',
  'witness',
])

function isSensitiveKey(key: string): boolean {
  const normalized = key.replace(/[^a-z0-9]/gi, '').toLowerCase()
  return SENSITIVE_KEYS.has(normalized) || normalized.includes('witness')
}

function redactValue(value: unknown, seen = new WeakSet<object>()): unknown {
  if (value === null || value === undefined) {
    return value
  }

  if (typeof value !== 'object') {
    return value
  }

  if (seen.has(value)) {
    return REDACTED_VALUE
  }
  seen.add(value)

  if (Array.isArray(value)) {
    return value.map(item => redactValue(item, seen))
  }

  const result: Record<string, unknown> = {}

  for (const [key, val] of Object.entries(value as Record<string, unknown>)) {
    if (isSensitiveKey(key)) {
      result[key] = REDACTED_VALUE
    } else if (val && typeof val === 'object') {
      result[key] = redactValue(val, seen)
    } else {
      result[key] = val
    }
  }

  return result
}

export function redactSensitive<T extends Record<string, unknown>>(obj: T): T {
  return redactValue(obj) as T
}

export type StructuredLogLevel = 'info' | 'warn' | 'error' | 'debug'
export type StructuredLogger = Record<StructuredLogLevel, (message: string) => void>

export function logStructured(logger: StructuredLogger, level: StructuredLogLevel, data: Record<string, unknown>): void {
  const redacted = redactSensitive(data)
  const message = JSON.stringify(redacted)
  logger[level](message)
}