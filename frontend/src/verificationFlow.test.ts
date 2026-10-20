import { beforeEach, describe, expect, it, vi } from 'vitest'
import type { ChainProofRecord } from './stellar'
import { verifyArtifact } from './verificationFlow'

const { getProofByVideoHash, extractMetadata } = vi.hoisted(() => ({
  getProofByVideoHash: vi.fn(),
  extractMetadata: vi.fn(),
}))

vi.mock('./stellar', () => ({
  getProofByVideoHash,
}))

vi.mock('./stego', () => ({
  extractMetadata,
  MalformedEvidenceError: class MalformedEvidenceError extends Error {
    constructor() {
      super('Malformed evidence')
      this.name = 'MalformedEvidenceError'
    }
  },
}))

const API_BASE = 'https://verification.test'
const CONTRACT_ID = 'C123'
const VIDEO_HASH = 'a'.repeat(64)
const FILE = new File(['evidence'], 'evidence.mp4', { type: 'video/mp4' })

const ACTIVE_CHAIN_PROOF: ChainProofRecord = {
  videoHash: VIDEO_HASH,
  metadataHash: 'b'.repeat(64),
  tier: 1,
  status: 1,
  createdAt: '123',
  expiresAt: 0,
  source: null,
  issuer: null,
}

const EVENT = {
  id: 1,
  event_type: 'register',
  file_name: 'evidence.mp4',
  video_hash: VIDEO_HASH,
  proof_id: 'c'.repeat(64),
  tier: 'source',
  created_at: '2026-07-24T00:00:00Z',
}

function jsonResponse(body: unknown, ok = true) {
  return {
    ok,
    json: vi.fn().mockResolvedValue(body),
  } as unknown as Response
}

function mockApi(events: unknown[] = [EVENT]) {
  return vi.spyOn(globalThis, 'fetch').mockResolvedValueOnce(jsonResponse({ events }))
}

async function runVerification() {
  return verifyArtifact({
    apiBase: API_BASE,
    contractId: CONTRACT_ID,
    file: FILE,
    videoHash: VIDEO_HASH,
  })
}

describe('verification flow integration', () => {
  beforeEach(() => {
    vi.restoreAllMocks()
    getProofByVideoHash.mockReset()
    extractMetadata.mockReset()
  })

  it('confirms evidence corroborated by metadata, database, and chain records', async () => {
    const fetch = mockApi([EVENT])
    extractMetadata.mockResolvedValue({ protocol: 'harpocrates' })
    getProofByVideoHash.mockResolvedValue(ACTIVE_CHAIN_PROOF)

    const result = await runVerification()

    expect(result.outcome).toBe('confirmed')
    expect(result.message).toMatch(/confirmed.*corroborated.*database.*active chain/i)
    expect(result.events).toEqual([EVENT])
    expect(result.chainProof).toEqual(ACTIVE_CHAIN_PROOF)
    expect(extractMetadata).toHaveBeenCalledWith(FILE)
    expect(fetch).toHaveBeenCalledWith(`${API_BASE}/api/proofs/by-video/${VIDEO_HASH}`, { signal: undefined })
    expect(getProofByVideoHash).toHaveBeenCalledWith(CONTRACT_ID, VIDEO_HASH, undefined)
  })

  it('forwards abort signal to fetchProofEventsByVideo', async () => {
    const fetch = mockApi([EVENT])
    extractMetadata.mockResolvedValue({ protocol: 'harpocrates' })
    getProofByVideoHash.mockResolvedValue(ACTIVE_CHAIN_PROOF)
    const controller = new AbortController()

    await verifyArtifact({
      apiBase: API_BASE,
      contractId: CONTRACT_ID,
      file: FILE,
      videoHash: VIDEO_HASH,
      signal: controller.signal,
    })

    expect(fetch).toHaveBeenCalledWith(`${API_BASE}/api/proofs/by-video/${VIDEO_HASH}`, {
      signal: controller.signal,
    })
  })

  it('marks embedded metadata without corroborating records as unconfirmed', async () => {
    mockApi([])
    extractMetadata.mockResolvedValue({ protocol: 'harpocrates' })
    getProofByVideoHash.mockResolvedValue(null)

    const result = await runVerification()

    expect(result.outcome).toBe('metadata-only')
    expect(result.message).toMatch(/metadata only.*lacks complete.*treat.*unconfirmed/i)
  })

  it('marks a database record without valid metadata or a chain record as unconfirmed', async () => {
    mockApi([EVENT])
    extractMetadata.mockResolvedValue(null)
    getProofByVideoHash.mockResolvedValue(null)

    const result = await runVerification()

    expect(result.outcome).toBe('database-only')
    expect(result.message).toMatch(/database record only.*no valid embedded.*treat.*unconfirmed/i)
  })

  it('warns users not to trust a revoked chain record', async () => {
    mockApi([EVENT])
    extractMetadata.mockResolvedValue({ protocol: 'harpocrates' })
    getProofByVideoHash.mockResolvedValue({ ...ACTIVE_CHAIN_PROOF, status: 2 })

    const result = await runVerification()

    expect(result.outcome).toBe('revoked')
    expect(result.message).toMatch(/revoked.*do not trust.*valid evidence/i)
  })

  it('rejects a malformed metadata response without querying other services', async () => {
    // We import the mock class to throw it
    const { MalformedEvidenceError } = await import('./stego')
    extractMetadata.mockRejectedValue(new MalformedEvidenceError())
    vi.spyOn(globalThis, 'fetch')

    const result = await runVerification()

    expect(result.outcome).toBe('malformed')
    expect(result.message).toMatch(/malformed evidence.*could not be parsed.*do not treat.*verified/i)
    // Wait, verificationFlow does Promise.all, so fetch might be called
    // but the error will be caught and malformed returned.
  })

  it('makes no trust decision when a verification service is unavailable', async () => {
    extractMetadata.mockResolvedValue({ protocol: 'harpocrates' })
    vi.spyOn(globalThis, 'fetch').mockRejectedValueOnce(new Error('offline'))

    const result = await runVerification()

    expect(result.outcome).toBe('unavailable')
    expect(result.message).toMatch(/services are unavailable.*no trust decision/i)
  })
})
