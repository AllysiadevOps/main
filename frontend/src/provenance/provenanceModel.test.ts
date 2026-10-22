import { describe, expect, it } from 'vitest'
import type { ChainProofRecord, IdentityTier } from '../stellarTypes'
import { buildProvenanceRecord, disputeNotice, NOIR_CIRCUIT_VERSION } from './provenanceModel'

const BASE_MANIFEST = {
  protocol: 'harpocrates' as const,
  version: 1,
  proofId: 'd'.repeat(64),
  tier: 'source' as IdentityTier,
  network: 'Test Network Passphrase',
  contractId: 'C'.repeat(56),
  transactionRef: 'e'.repeat(64),
  videoHash: 'a'.repeat(64),
  metadataHash: 'b'.repeat(64),
  sourceHash: 'c'.repeat(64),
  timestamp: '2026-07-25T11:55:00.000Z',
}

const FETCHED_AT = new Date('2026-07-25T12:00:00.000Z')

const MATCHING_CHAIN_PROOF: ChainProofRecord = {
  videoHash: BASE_MANIFEST.videoHash,
  metadataHash: BASE_MANIFEST.metadataHash,
  tier: 1,
  status: 1,
  createdAt: '2026-07-25T11:58:30.000Z',
  expiresAt: 0,
  source: null,
  issuer: null,
}

function buildRecord(chainProof: ChainProofRecord | null) {
  return buildProvenanceRecord({
    manifest: BASE_MANIFEST,
    chainProof,
    rpcUrl: 'https://rpc.example.test',
    transactionHash: 'f'.repeat(64),
    method: 'register_source',
    fetchedAt: FETCHED_AT,
  })
}

describe('buildProvenanceRecord', () => {
  it('does not report mismatches when manifest and chain proof agree', () => {
    const record = buildRecord(MATCHING_CHAIN_PROOF)

    expect(record.circuit).toEqual({ name: 'silent_witness', version: NOIR_CIRCUIT_VERSION })
    expect(record.mismatches).toEqual([])
  })

  it('flags a video hash mismatch', () => {
    const record = buildRecord({
      ...MATCHING_CHAIN_PROOF,
      videoHash: '0'.repeat(64),
    })

    expect(record.mismatches).toEqual([
      {
        field: 'videoHash',
        manifestValue: BASE_MANIFEST.videoHash,
        chainValue: '0'.repeat(64),
      },
    ])
  })

  it('flags a metadata hash mismatch', () => {
    const record = buildRecord({
      ...MATCHING_CHAIN_PROOF,
      metadataHash: '1'.repeat(64),
    })

    expect(record.mismatches).toEqual([
      {
        field: 'metadataHash',
        manifestValue: BASE_MANIFEST.metadataHash,
        chainValue: '1'.repeat(64),
      },
    ])
  })

  it('flags a tier mismatch', () => {
    const record = buildRecord({
      ...MATCHING_CHAIN_PROOF,
      tier: 2,
    })

    expect(record.mismatches).toEqual([
      {
        field: 'tier',
        manifestValue: '1',
        chainValue: '2',
      },
    ])
  })

  it('treats missing chain proof as stale', () => {
    const record = buildRecord(null)

    expect(record.staleness).toEqual({ stale: true, reason: 'no-chain-record' })
  })

  it('treats an old pending proof as stale', () => {
    const record = buildRecord({
      ...MATCHING_CHAIN_PROOF,
      status: 0,
      createdAt: '2026-07-25T11:50:00.000Z',
    })

    expect(record.staleness).toEqual({ stale: true, reason: 'fetched-long-ago' })
  })

  it('does not treat a confirmed proof as stale when it is old', () => {
    const record = buildRecord({
      ...MATCHING_CHAIN_PROOF,
      status: 1,
      createdAt: '2026-07-25T11:30:00.000Z',
    })

    expect(record.staleness).toEqual({ stale: false })
  })

  it('does not treat a recent pending proof as stale', () => {
    const record = buildRecord({
      ...MATCHING_CHAIN_PROOF,
      status: 0,
      createdAt: '2026-07-25T11:58:30.000Z',
    })

    expect(record.staleness).toEqual({ stale: false })
  })
})

describe('provenance disputes', () => {
  function withDisputes(openDisputeCount: number | null | undefined) {
    return buildProvenanceRecord({
      manifest: BASE_MANIFEST,
      chainProof: MATCHING_CHAIN_PROOF,
      rpcUrl: 'https://rpc.example.test',
      transactionHash: 'f'.repeat(64),
      method: 'register_source',
      openDisputeCount,
      fetchedAt: FETCHED_AT,
    })
  }

  it('keeps the count unknown when it was not looked up', () => {
    expect(buildRecord(MATCHING_CHAIN_PROOF).disputes).toEqual({ openCount: null })
    expect(withDisputes(undefined).disputes).toEqual({ openCount: null })
    expect(withDisputes(null).disputes).toEqual({ openCount: null })
  })

  it('carries a zero and a positive count through unchanged', () => {
    expect(withDisputes(0).disputes).toEqual({ openCount: 0 })
    expect(withDisputes(3).disputes).toEqual({ openCount: 3 })
  })

  it('treats negative, fractional or non-finite counts as unknown', () => {
    for (const bad of [-1, 1.5, Number.NaN, Number.POSITIVE_INFINITY]) {
      expect(withDisputes(bad).disputes).toEqual({ openCount: null })
    }
  })

  it('includes the disputes field in the exported provenance JSON', () => {
    const parsed = JSON.parse(JSON.stringify(withDisputes(2)))
    expect(parsed.disputes).toEqual({ openCount: 2 })
  })

  it('produces a notice only when the count is greater than zero', () => {
    expect(disputeNotice(withDisputes(null))).toBeNull()
    expect(disputeNotice(withDisputes(0))).toBeNull()
    expect(disputeNotice(withDisputes(1))).toBe(
      'This proof has 1 open dispute recorded on chain. A dispute does not by itself invalidate the proof.',
    )
    expect(disputeNotice(withDisputes(4))).toContain('4 open disputes')
  })
})
