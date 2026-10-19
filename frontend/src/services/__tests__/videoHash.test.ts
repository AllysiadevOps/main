import { describe, expect, it } from 'vitest'
import {
  InvalidVideoHashError,
  assertValidVideoHash,
  isValidVideoHash,
} from '../videoHash'

const VALID_HASH = 'a'.repeat(64)

describe('videoHash', () => {
  describe('isValidVideoHash', () => {
    it('accepts 64 lowercase hex characters', () => {
      expect(isValidVideoHash(VALID_HASH)).to.be(true)
      expect(isValidVideoHash('0123456789abcdef'.repeat(4))).to.be(true)
    })

    it('rejects path traversal inputs', () => {
      expect(isValidVideoHash('../')).to.be(false)
      expect(isValidVideoHash(`${VALID_HASH}/../`)).to.be(false)
    })

    it('rejects query string injection', () => {
      expect(isValidVideoHash('?x=1')).to.be(false)
      expect(isValidVideoHash(`${VALID_HASH}?x=1`)).to.be(false)
    })

    it('rejects uppercase hex', () => {
      expect(isValidVideoHash('A'.repeat(64))).to.be(false)
    })

    it('rejects short inputs', () => {
      expect(isValidVideoHash('abc')).to.be(false)
      expect(isValidVideoHash('a'.repeat(63))).to.be(false)
    })

    it('rejects non-string values', () => {
      expect(isValidVideoHash(undefined)).to.be(false)
      expect(isValidVideoHash(null)).to.be(false)
      expect(isValidVideoHash(123)).to.be(false)
    })
  })

  describe('assertValidVideoHash', () => {
    it('returns the URL-encoded hash for valid input', () => {
      expect(assertValidVideoHash(VALID_HASH)).toBe(VALID_HASH)
    })

    it('throws InvalidVideoHashError for invalid input', () => {
      expect(() => assertValidVideoHash('../')).toThrow(InvalidVideoHashError)
      expect(() => assertValidVideoHash('?x=1')).toThrow(InvalidVideoHashError)
    })
  })
})
