import { describe, it, expect, vi } from 'vitest'
import { fieldSecret, hasSeeds, deriveSeeds, createClearSeeds } from './seedVault'
import { fieldSecret as utilsFieldSecret } from './utils'

describe('fieldSecret', () => {
  it('is the single canonical implementation re-exported from utils', () => {
    expect(fieldSecret).toBe(utilsFieldSecret)
  })

  it('returns a deterministic decimal string for a given label and seed', async () => {
    const a = await fieldSecret('credential', 'my-secret')
    const b = await fieldSecret('credential', 'my-secret')
    expect(a).toBe(b)
    expect(a).toMatch(/^\d+$/)
  })

  it('returns different values for different labels', async () => {
    const credential = await fieldSecret('credential', 'same-seed')
    const nullifier = await fieldSecret('nullifier', 'same-seed')
    expect(credential).not.toBe(nullifier)
  })

  it('returns different values for different seeds', async () => {
    const a = await fieldSecret('credential', 'seed-a')
    const b = await fieldSecret('credential', 'seed-b')
    expect(a).not.toBe(b)
  })

  it('never returns zero (maps zero to "1")', async () => {
    const results = await Promise.all(
      Array.from({ length: 50 }, (_, i) => fieldSecret('credential', `seed-${i}`)),
    )
    for (const result of results) {
      expect(result).not.toBe('0')
      expect(result).not.toBe('0n')
    }
  })

  it('returns a value within the BN254 field', async () => {
    const value = await fieldSecret('credential', 'test-seed')
    const bn = BigInt(value)
    expect(bn).toBeGreaterThan(0n)
    expect(bn).toBeLessThan(
      21888242871839275222246405745257275088548364400416034343698204186575808495617n,
    )
  })
})

describe('hasSeeds', () => {
  it('returns true when both seeds are non-empty', () => {
    expect(hasSeeds({ credentialSeed: 'abc', nullifierSeed: 'def' })).toBe(true)
  })

  it('returns false when credential seed is empty', () => {
    expect(hasSeeds({ credentialSeed: '', nullifierSeed: 'def' })).toBe(false)
  })

  it('returns false when nullifier seed is empty', () => {
    expect(hasSeeds({ credentialSeed: 'abc', nullifierSeed: '' })).toBe(false)
  })

  it('returns false when both seeds are empty', () => {
    expect(hasSeeds({ credentialSeed: '', nullifierSeed: '' })).toBe(false)
  })

  it('trims whitespace before checking', () => {
    expect(hasSeeds({ credentialSeed: '   ', nullifierSeed: 'def' })).toBe(false)
    expect(hasSeeds({ credentialSeed: 'abc', nullifierSeed: '   ' })).toBe(false)
  })
})

describe('deriveSeeds', () => {
  it('trims whitespace from both seeds', () => {
    const result = deriveSeeds({ credentialSeed: '  abc  ', nullifierSeed: '  def  ' })
    expect(result).toEqual({ credentialSeed: 'abc', nullifierSeed: 'def' })
  })

  it('returns the same values when already trimmed', () => {
    const result = deriveSeeds({ credentialSeed: 'abc', nullifierSeed: 'def' })
    expect(result).toEqual({ credentialSeed: 'abc', nullifierSeed: 'def' })
  })
})

describe('createClearSeeds', () => {
  it('returns a function that calls the setter with empty string', () => {
    const setter = vi.fn()
    const clear = createClearSeeds(setter)
    clear()
    expect(setter).toHaveBeenCalledWith('')
  })

  it('can be used to clear both credential and nullifier setters', () => {
    const setCredential = vi.fn()
    const setNullifier = vi.fn()
    const clearCredential = createClearSeeds(setCredential)
    const clearNullifier = createClearSeeds(setNullifier)

    clearCredential()
    clearNullifier()

    expect(setCredential).toHaveBeenCalledWith('')
    expect(setNullifier).toHaveBeenCalledWith('')
  })
})
