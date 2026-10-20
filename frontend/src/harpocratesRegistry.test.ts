import { describe, it, expect, vi, beforeEach } from 'vitest'
import { xdrToScVal, scValToNative, nativeToScVal } from '@stellar/stellar-sdk'

const simulateTransaction = vi.fn()
const getAccount = vi.fn()

vi.mock('@stellar/stellar-sdk', async () => {
  const actual = await vi.importActual('@stellar/stellar-sdk')
  return {
    ...actual,
    rpc: {
      ...actual.rpc,
      Server: class {
        getAccount = getAccount
        simulateTransaction = simulateTransaction
      },
    },
  }
})

vi.mock('@stellar/freighter-api', async () => {
  const actual = await vi.importActual('@stellar/freighter-api')
  return {
    ...actual,
    signTransaction: vi.fn(),
  }
})

const { getDispute, getOpenDisputeCount, requireReadSource } = await import('./harpocratesRegistry')

const CONTRACT_ID = 'CCAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA'
const SOURCE = 'GBAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA'
const DISPUTE_ID = '01'.repeat(32)
const PROOF_ID = '02'.repeat(32)

function success(retval: unknown) {
  return {
    result: { retval: nativeToScVal(retval) },
    latestLedger: 1,
    events: [],
  }
}

beforeEach(() => {
  simulateTransaction.mockReset()
  getAccount.mockReset()
  getAccount.mockResolvedValue({
    accountId: () => SOURCE,
    sequenceNumber: () => '0',
  })
})

describe('getDispute', () => {
  it('returns a typed dispute record when present', async () => {
    simulateTransaction.mockResolvedValue(
      success({
        dispute_id: Uint8Array.from({ length: 32 }, _ => 1),
        proof_id: Uint8Array.from({ length: 32 }, _ => 2),
        reason: 'evidence tampered',
        status: 1,
        opened_at: 1700000000,
        resolved_at: null,
        opener: SOURCE,
      }),
    )

    const record = await getDispute(CONTRACT_ID, DISPUTE_ID, SOURCE)

    expect(record).toEqual({
      disputeId: '01'.repeat(32),
      proofId: '02'.repeat(32),
      reason: 'evidence tampered',
      status: 1,
      openedAt: 1700000000,
      resolvedAt: null,
      opener: SOURCE,
    })
  })

  it('returns null when the contract returns None', async () => {
    simulateTransaction.mockResolvedValue(success(null))

    await expect(getDispute(CONTRACT_ID, DISPUTE_ID, SOURCE)).resolves.toBeNull()
  })

  it('throws the simulation error when the read fails', async () => {
    simulateTransaction.mockResolvedValue({
      error: 'host failure',
    })

    await expect(getDispute(CONTRACT_ID, DISPUTE_ID, SOURCE)).rejects.toThrow('host failure')
  })
})

describe('getOpenDisputeCount', () => {
  it('returns the count when present', async () => {
    simulateTransaction.mockResolvedValue(success(3))

    await expect(getOpenDisputeCount(CONTRACT_ID, PROOF_ID, SOURCE)).resolves.toBe(3)
  })

  it('returns null when the contract returns no value', async () => {
    simulateTransaction.mockResolvedValue(success(null))

    await expect(getOpenDisputeCount(CONTRACT_ID, PROOF_ID, SOURCE)).resolves.toBeNull()
  })

  it('throws the simulation error when the read fails', async () => {
    simulateTransaction.mockResolvedValue({
      error: 'host failure',
    })

    await expect(getOpenDisputeCount(CONTRACT_ID, PROOF_ID, SOURCE)).rejects.toThrow('host failure')
  })
})

describe('requireReadSource', () => {
  it('throws the same message when no source is configured', () => {
    expect(() => requireReadSource()).toThrow(
      'Set VITE_STELLAR_READONLY_SOURCE or connect a wallet for on-chain verification.',
    )
    expect(() => requireReadSource('')).toThrow(
      'Set VITE_STELLAR_READONLY_SOURCE or connect a wallet for on-chain verification.',
    )
  })

  it('returns the provided source when present', () => {
    expect(requireReadSource(SOURCE)).toBe(SOURCE)
  })
})

