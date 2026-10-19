import { describe, expect, it } from 'vitest'
import {
  COMPATIBILITY_NETWORK,
  COMPATIBILITY_RELEASE_ID,
  assertReleaseCompatibility,
  checkReleaseCompatibility,
} from './releaseCompatibility'

describe('release compatibility constants', () => {
  it('binds the v1 release to testnet', () => {
    expect(COMPATIBILITY_RELEASE_ID).toBe('harpocrates-1.0.0')
    expect(COMPATIBILITY_NETWORK).toBe('testnet')
  })
})

describe('checkReleaseCompatibility', () => {
  it('returns compatible: true when release and network match approved values', () => {
    const result = checkReleaseCompatibility({
      releaseId: COMPATIBILITY_RELEASE_ID,
      network: COMPATIBILITY_NETWORK,
    })

    expect(result.compatible).toBe(true)
    expect(result.expectedReleaseId).toBe(COMPATIBILITY_RELEASE_ID)
    expect(result.expectedNetwork).toBe(COMPATIBILITY_NETWORK)
    expect(result.configuredReleaseId).toBe(COMPATIBILITY_RELEASE_ID)
    expect(result.configuredNetwork).toBe(COMPATIBILITY_NETWORK)
    expect(result.message).toBeUndefined()
  })

  it('returns compatible: false when releaseId mismatches', () => {
    const result = checkReleaseCompatibility({
      releaseId: 'harpocrates-2.0.0',
      network: COMPATIBILITY_NETWORK,
    })

    expect(result.compatible).toBe(false)
    expect(result.expectedReleaseId).toBe(COMPATIBILITY_RELEASE_ID)
    expect(result.configuredReleaseId).toBe('harpocrates-2.0.0')
    expect(result.message).toContain('harpocrates-1.0.0')
    expect(result.message).toContain('harpocrates-2.0.0')
  })

  it('returns compatible: false when network mismatches', () => {
    const result = checkReleaseCompatibility({
      releaseId: COMPATIBILITY_RELEASE_ID,
      network: 'mainnet',
    })

    expect(result.compatible).toBe(false)
    expect(result.expectedNetwork).toBe(COMPATIBILITY_NETWORK)
    expect(result.configuredNetwork).toBe('mainnet')
    expect(result.message).toContain('testnet')
    expect(result.message).toContain('mainnet')
  })

  it('returns compatible: false when both releaseId and network mismatch', () => {
    const result = checkReleaseCompatibility({
      releaseId: 'custom-v0',
      network: 'futurenet',
    })

    expect(result.compatible).toBe(false)
    expect(result.expectedReleaseId).toBe(COMPATIBILITY_RELEASE_ID)
    expect(result.expectedNetwork).toBe(COMPATIBILITY_NETWORK)
    expect(result.configuredReleaseId).toBe('custom-v0')
    expect(result.configuredNetwork).toBe('futurenet')
  })
})

describe('assertReleaseCompatibility', () => {
  it('does not throw when configuration is compatible', () => {
    expect(() => assertReleaseCompatibility()).not.toThrow()
  })
})
