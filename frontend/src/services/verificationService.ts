/**
 * verificationService — network calls for the verification portal flow.
 *
 * Responsibility: talk to the Flask extract API, NeonDB Lookup, and the
 * Soroban on-chain registry. Returns plain data; no React state.
 */

import type { ChainProofRecord } from '../stellarTypes'
import type { ProofEvent } from '../types'
import { ApiClientError, parseActionableApiError } from './apiError'
import { assertValidVideoHash } from './videoHash'

const API_BASE = import.meta.env.VITE_API_BASE ?? 'http://127.0.0.1:5050'
const CONTRACT_ID = import.meta.env.VITE_HARPOCRATES_REGISTRY_ID ?? ''

export type ExtractResult = {
  hasHarpocratesMetadata: boolean
}

/** Ask the Flask service to extract steganographic metadata from a video. */
export async function extractMetadata(file: File, signal?: AbortSignal): Promise<ExtractResult> {
  const form = new FormData()
  form.append('video', file)

  const response = await fetch(`${API_BASE}/api/stego/extract`, {
    method: 'POST',
    body: form,
    signal,
  })
  if (!response.ok) {
    throw new ApiClientError(await parseActionableApiError(response, 'Extraction service is unavailable.'))
  }
  const data = await response.json()
  return {
    hasHarpocratesMetadata: data.metadata?.protocol === 'harpocrates',
  }
}

/** Look up all NeonDB proof events for a given video hash. */
export async function fetchProofEventsByVideo(
  videoHash: string,
  signal?: AbortSignal,
  apiBase: string = API_BASE,
): Promise<ProofEvent[]> {
  // Validate before building the URL so malformed hashes never reach the network.
  const safeHash = assertValidVideoHash(videoHash)
  const base = apiBase || API_BASE
  const response = await fetch(`${base}/api/proofs/by-video/${safeHash}`, { signal })
  if (!response.ok) {
    throw new ApiClientError(await parseActionableApiError(response, 'Database lookup failed.'))
  }
  const data = await response.json()
  return (data.events ?? []) as ProofEvent[]
}

/**
 * Simulate `get_by_video` against the Soroban registry.
 * Returns null when the contract ID is not configured or the record is not found.
 */
export async function getOnChainProof(
  videoHash: string,
  sourceAddress?: string,
): Promise<ChainProofRecord | null> {
  if (!CONTRACT_ID) return null
  const safeHash = assertValidVideoHash(videoHash)
  const { getProofByVideoHash } = await import('../stellar')
  return getProofByVideoHash(CONTRACT_ID, safeHash, sourceAddress)
}

export const VERIFICATION_LIMITS = {
  maxFileSizeBytes: 100 * 1024 * 1024,
  supportedTypes: ['video/mp4', 'video/webm', 'video/quicktime', 'video/x-msvideo', 'video/avi'],
} as const
