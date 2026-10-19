import { describe, expect, it } from 'vitest'
import { networkFromPassphrase } from './explorerLinks'

describe('networkFromPassphrase', () => {
  it('maps the public passphrase', () => {
    expect(networkFromPassphrase('Public Global Stellar Network ; February 2016')).toBe('public')
  })

  it('maps the testnet passphrase', () => {
    expect(networkFromPassphrase('Test Stellar Network ; September 2015')).toBe('testnet')
  })

  it('returns null for the Futurenet passphrase', () => {
    expect(networkFromPassphrase('Future Network ; October 2022')).toBeNull()
  })

  it('returns null for garbage strings', () => {
    expect(networkFromPassphrase('')).toBeNull()
    expect(networkFromPassphrase('standalone network')).toBeNull()
    expect(networkFromPassphrase('public')).toBeNull()
    expect(networkFromPassphrase('testnet')).toBeNull()
  })
})
