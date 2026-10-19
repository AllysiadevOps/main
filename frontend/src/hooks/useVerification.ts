/**
 * useVerification — manages the verification portal flow:
 * local hash → stego extract → NeonDB lookup → on-chain query (online),
 * or a fully local, offline-safe equivalent (offline mode).
 *
 * Offline mode makes ZERO network calls: it hashes and extracts locally and
 * performs structural/binding checks only. It never yields a confirmed trust
 * decision — chain/registry status is reported as not checked. See
 * `offlineVerification.ts`.
 *
 * Mobile-hardened: input validation, AbortController cancellation, stale-result
 * guard, and privacy-safe error codes. No raw evidence, media, or secrets is
 * written to logs or user-facing errors beyond stable categories.
 */

import { useCallback, useEffect, useRef, useState } from 'react'
import type { ChainProofRecord } from '../stellarTypes'
import type { ProofEvent } from '../types'
import { ApiClientError, toVerificationErrorCode } from '../services/apiError'
import type { VerificationSharePayload } from '../verificationShareLink'

export type VerificationStatus = 'idle' | 'validating' | 'hashing' | 'verifying' | 'success' | 'error' | 'cancelled'

export type VerificationErrorCode =
  | 'EMPTY_INPUT'
  | 'UNSUPPORTED_ARTIFACT'
  | 'OVERSIZED_ARTIFACT'
  | 'INVALID_EVIDENCE'
  | 'EXPIRED_EVIDENCE'
  | 'REVOKED_EVIDENCE'
  | 'VERIFICATION_FAILED'
  | 'DEPENDENCY_UNAVAILABLE'
  | 'CANCELLED'
  | 'WALLET_UNAVAILABLE'
  | 'METADATA_ENVELOPE_MISMATCH'

// 100 MB — frontend guard, consistent with batchVerifier DEFAULT_BATCH_CONFIG
// (100 MB per-file) and within backend MAX_VIDEO_BYTES (250 MB, backend/config.py).
// Do not raise above backend limit; see docs/streaming-uploads.md UPLOAD_MAX_BYTES.
const MAX_VERIFY_FILE_BYTES = 100 * 1024 * 1024

const SAFE_MESSAGES: Record<VerificationErrorCode, string> = {
  EMPTY_INPUT: 'No file provided. Choose a video to verify.',
  UNSUPPORTED_ARTIFACT: 'Unsupported file type. Provide an MP4, WebM, or MOV video.',
  OVERSIZED_ARTIFACT: 'File exceeds the size limit (100 MB). Choose a smaller artifact.',
  INVALID_EVIDENCE: 'Invalid evidence: the file could not be verified as Harpocrates evidence.',
  EXPIRED_EVIDENCE: 'Expired: the chain record for this artifact has expired. Do not treat it as valid evidence.',
  REVOKED_EVIDENCE: 'Revoked: the chain record for this artifact has been revoked. Do not trust it as valid evidence.',
  VERIFICATION_FAILED: 'Verification failed. No trust decision was made.',
  DEPENDENCY_UNAVAILABLE: 'Verification services are unavailable. No trust decision was made.',
  CANCELLED: 'Verification cancelled.',
  WALLET_UNAVAILABLE: 'Wallet unavailable. Connect a wallet or try again without wallet lookup.',
  METADATA_ENVELOPE_MISMATCH:
    'Metadata mismatch: the embedded metadata hash does not match the on-chain envelope bound to this proof. Treat this artifact as tampered with.',
}

function isAbortError(error: unknown): boolean {
  return (
    error instanceof DOMException && error.name === 'AbortError' ||
    (error instanceof Error && (error.name === 'AbortError' || /aborted|cancelled/i.test(error.message)))
  )
}

function mapChainStatus(status: number): VerificationErrorCode | null {
  if (status === 2) return 'REVOKED_EVIDENCE'
  if (status === 3) return 'EXPIRED_EVIDENCE'
  return null
}

function normaliseHashForCompare(value: string | null | undefined): string | null {
  if (typeof value !== 'string') return null
  const trimmed = value.trim().toLowerCase()
  return trimmed.length > 0 ? trimmed : null
}

function validateFile(file: File): { ok: true } | { ok: false; code: VerificationErrorCode } {
  if (file.size === 0) return { ok: false, code: 'EMPTY_INPUT' }
  if (file.size > MAX_VERIFY_FILE_BYTES) return { ok: false, code: 'OVERSIZED_ARTIFACT' }
  // Allow emptty type (some mobile browsers omit it) but reject clearly unsupported types
  if (file.type && !file.type.startsWith('video/')) {
    return { ok: false, code: 'UNSUPPORTED_ARTIFACT' }
  }
  return { ok: true }
}

export type UseVerificationReturn = {
  verifyHash: string
  verifyResult: string
  events: ProofEvent[]
  chainProof: ChainProofRecord | null
  status: VerificationStatus
  errorCode: VerificationErrorCode | null
  isVerifying: boolean
  /** True when verification runs fully offline (no network calls). */
  offline: boolean
  setOffline: (next: boolean) => void
  verifyEvidence: (file: File | null, walletAddress?: string) => Promise<void>
  loadEvents: () => Promise<void>
  cancel: () => void
  retry: () => Promise<void>
  loadSharedVerification: (payload: VerificationSharePayload) => Promise<void>
  clear: () => void
}

export function useVerification(): UseVerificationReturn {
  const [verifyHash, setVerifyHash] = useState('')
  const [verifyResult, setVerifyResult] = useState('')
  const [events, setEvents] = useState<ProofEvent[]>([])
  const [chainProof, setChainProof] = useState<ChainProofRecord | null>(null)
  const [status, setStatus] = useState<VerificationStatus>('idle')
  const [errorCode, setErrorCode] = useState<VerificationErrorCode | null>(null)
  // Offline mode mirrors the user-visible toggle so retries/effect reads stay
  // consistent even when the toggle could change mid-flow.
  const [offline, setOfflineState] = useState(false)
  const offlineRef = useRef(false)
  const setOffline = useCallback((next: boolean) => {
    offlineRef.current = next
    setOfflineState(next)
  }, [])

  const seqRef = useRef(0)
  const abortRef = useRef<AbortController | null>(null)
  const lastFileRef = useRef<{ file: File; wallet?: string } | null>(null)

  const isVerifying = status === 'validating' || status === 'hashing' || status === 'verifying'

  const clear = useCallback(() => {
    abortRef.current?.abort()
    abortRef.current = null
    seqRef.current += 1
    setVerifyHash('')
    setVerifyResult('')
    setEvents([])
    setChainProof(null)
    setStatus('idle')
    setErrorCode(null)
    lastFileRef.current = null
  }, [])

  const cancel = useCallback(() => {
    abortRef.current?.abort()
    // Immediately reflect cancellation in UI so mobile user sees feedback, even if
    // in-flight mocks do not reject with AbortError
    setStatus('cancelled')
    setErrorCode('CANCELLED')
    setVerifyResult(SAFE_MESSAGES.CANCELLED)
  }, [])

  const loadEvents = useCallback(async () => {
    // Offline mode never reaches the NeonDB feed.
    if (offlineRef.current) return
    try {
      const { fetchRecentEvents } = await import('../services/evidenceService')
      const loaded = await fetchRecentEvents(6)
      setEvents(loaded)
    } catch {
      // keep existing events; surface no sensitive detail
    }
  }, [])

  const loadSharedVerification = useCallback(async (payload: VerificationSharePayload) => {
    setVerifyHash(payload.videoHash)
    setErrorCode(null)
    setStatus('verifying')
    setVerifyResult('Loading the public verification record…')
    try {
      const { fetchProofEventsByVideo, getOnChainProof } = await import('../services/verificationService')
      const [dbMatches, onChain] = await Promise.all([
        fetchProofEventsByVideo(payload.videoHash),
        getOnChainProof(payload.videoHash),
      ])
      setEvents(dbMatches)
      setChainProof(onChain)
      setVerifyResult(
        dbMatches.length > 0 || onChain
          ? 'Public verification record loaded. Confirm the embedded artifact before treating it as authentic.'
          : 'No public verification record was found for this artifact.',
      )
      setStatus('success')
    } catch (error) {
      setStatus('error')
      setErrorCode(toVerificationErrorCode(error) ?? 'DEPENDENCY_UNAVAILABLE')
      setVerifyResult('The public verification record could not be loaded.')
    }
  }, [])

  const runVerify = useCallback(async (file: File, walletAddress: string | undefined, seq: number, signal: AbortSignal) => {
    // Validate synchronously before any expensive work
    const validated = validateFile(file)
    if (!validated.ok) {
      if (seq !== seqRef.current) return
      setStatus('error')
      setErrorCode(validated.code)
      setVerifyResult(SAFE_MESSAGES[validated.code])
      // keep hash empty so UI does not show stale hash for rejected input
      return
    }

    setStatus('hashing')
    setErrorCode(null)
    setVerifyResult('Hashing evidence locally…')
    setChainProof(null)
    setEvents([])

    let videoHash: string
    try {
      const { sha256 } = await import('../utils')
      // Allow early abort before reading
      if (signal.aborted) throw new DOMException('Aborted', 'AbortError')
      const buffer = await file.arrayBuffer()
      if (signal.aborted) throw new DOMException('Aborted', 'AbortError')
      videoHash = await sha256(buffer)
      if (signal.aborted) throw new DOMException('Aborted', 'AbortError')
      if (seq !== seqRef.current) return
      setVerifyHash(videoHash)
    } catch (error) {
      if (isAbortError(error) || signal.aborted) {
        if (seq !== seqRef.current) return
        setStatus('cancelled')
        setErrorCode('CANCELLED')
        setVerifyResult(SAFE_MESSAGES.CANCELLED)
        return
      }
      if (seq !== seqRef.current) return
      setStatus('error')
      setErrorCode('INVALID_EVIDENCE')
      setVerifyResult(SAFE_MESSAGES.INVALID_EVIDENCE)
      return
    }

    setStatus('verifying')
    setVerifyResult('Inspecting evidence…')

    try {
      const { extractMetadata, fetchProofEventsByVideo, getOnChainProof } = await import(
        '../services/verificationService'
      )

      if (signal.aborted) throw new DOMException('Aborted', 'AbortError')

      // Extract and DB lookup share the same abort signal; on-chain has no signal but we race it
      const extractP = extractMetadata(file, signal)
      const dbP = fetchProofEventsByVideo(videoHash, signal)
      const chainP = getOnChainProof(videoHash, walletAddress)

      // If signal aborts, chainP will still resolve but we will discard due to stale guard
      const [extractResult, dbMatches, onChain] = await Promise.all([extractP, dbP, chainP])

      if (seq !== seqRef.current) return
      if (signal.aborted) {
        setStatus('cancelled')
        setErrorCode('CANCELLED')
        setVerifyResult(SAFE_MESSAGES.CANCELLED)
        return
      }

      // Canonical revoked/expired handling takes precedence over metadata presence
      const chainCode = onChain ? mapChainStatus(onChain.status) : null
      if (chainCode) {
        setStatus('error')
        setErrorCode(chainCode)
        setVerifyResult(SAFE_MESSAGES[chainCode])
        setEvents(dbMatches)
        setChainProof(onChain)
        return
      }

      const hasMetadata = extractResult.hasHarpocratesMetadata

      // Compare the on-chain metadata envelope (if bound) with the extracted
      // metadata hash. An absent envelope is not an error and preserves the
      // existing behaviour. A mismatch is a distinct, tamper-signalling error.
      const proofId = onChain?.proofId ?? onChain ? onChain.prooofId : undefined
      const envelope = proofId
        ? await (async () => {
            try {
              const { getMetadataEnvelope } = await import('../lib/harpocratesRegistry')
            return await getMetadataEnvelope(proofId)
          } catch {
            // Envelope read failure must not mask a confirmed result; treat as
            // "no envelope" and let the rest of the flow report as usual.
            return null
          }
        })()
        : null

      if (seq !== seqRef.current) return
      if (signal.aborted) {
        setStatus('cancelled')
        setErrorCode('CANCELLED')
        setVerifyResult(SAFE_MESSAGES.CANCELLED)
        return
      }

      if (envelope) {
        const extractedHash = normaliseHashForCompare(extractResult.metadataHash)
        const envelopeHash = normaliseHashForCompare(envelope.metadataHash)
        // Only flag a mismatch when we have both sides; a missing extracted
        // hash falls through to the existing metadata-only messaging.
        if (extractedHash && envelopeHash && extractedHash !== envelopeHash) {
          setStatus('error')
          setErrorCode('METADATA_ENVELOPE_MISMATCH')
          setVerifyResult(SAFE_MESSAGES.METADATA_ENVELOPE_MISMATCH)
          setEvents(dbMatches)
          setChainProof(onChain)
          return
        }
      }

      // Privacy-safe, stable user messages — no file names, hashes, or raw proof data
      if (hasMetadata && dbMatches.length > 0 && onChain) {
        setVerifyResult(
          'Confirmed: embedded Harpocrates metadata is corroborated by database and active chain records.',
        )
      } else if (hasMetadata) {
        setVerifyResult(
          'Metadata only: embedded Harpocrates metadata lacks complete database and chain confirmation. Treat this artifact as unconfirmed.',
        )
      } else if (dbMatches.length > 0) {
        setVerifyResult(
          'Database record only: no valid embedded Harpocrates metadata or chain record was found. Treat this artifact as unconfirmed.',
        )
      } else {
        setVerifyResult(
          'No verification evidence found: metadata, database, and chain records did not confirm this artifact. Treat it as unverified.',
        )
      }
      setEvents(dbMatches)
      setChainProof(onChain)
      setStatus('success')
      setErrorCode(null)
    } catch (error) {
      if (isAbortError(error) || signal.aborted) {
        if (seq !== seqRef.current) return
        setStatus('cancelled')
        setErrorCode('CANCELLED')
        setVerifyResult(SAFE_MESSAGES.CANCELLED)
        return
      }
      if (seq !== seqRef.current) return
      // Map structured backend errors to actionable verification codes; keep wallet heuristic.
      const mapped = toVerificationErrorCode(error)
      if (mapped) {
        setStatus('error')
        setErrorCode(mapped)
        // Prefer actionable API message for oversized/unsupported/invalid; else stable copy.
        const apiMessage = error instanceof ApiClientError ? error.message : ''
        const useApiMessage =
          apiMessage.length > 0 &&
          (mapped === 'OVERSIZED_ARTIFACT' ||
            mapped === 'UNSUPPORTED_ARTIFACT' ||
            mapped === 'INVALID_EVIDENCE')
        setVerifyResult(useApiMessage ? apiMessage : SAFE_MESSAGES[mapped])
        return
      }
      // Wallet heuristic: a wallet provider failure should not be reported as a
      // generic verification failure.
      if (error instanceof Error && /wallet/i.test(error.message)) {
        setStatus('error')
        setErrorCode('WALLET_UNAVAILABLE')
        setVerifyResult(SAFE_MESSAGES.WALLET_UNAVAILABLE)
        return
      }
      setStatus('error')
      setErrorCode('VERIFICATION_FAILED')
      setVerifyResult(SAFE_MESSAGES.VERIFICATION_FAILED)
    }
  }, [])

  const verifyEvidence = useCallback(async (file: File | null, walletAddress?: string) => {
    if (!file) {
      setStatus('error')
      setErrorCode('EMPTY_INPUT')
      setVerifyResult(SAFE_MESSAGES.EMPTY_INPUT)
      return
    }
    // Offline mode is a separate code path that never touches the network.
    if (offlineRef.current) {
      const { runOfflineVerification } = await import('../offlineVerification')
      const result = await runOfflineVerification(file)
      setVerifyHash(result.videoHash)
      setVerifyResult(result.message)
      setStatus(result.ok ? 'success' : 'error')
      setErrorCode(result.ok ? null : result.code)
      return
    }
    abortRef.current?.abort()
    const controller = new AbortController()
    abortRef.current = controller
    const seq = seqRef.current + 1
    seqRef.current = seq
    lastFileRef.current = { file, wallet: walletAddress }
    await runVerify(file, walletAddress, seq, controller.signal)
  }, [runVerify])

  const retry = useCallback(async () => {
    const last = lastFileRef.current
    if (!last) return
    abortRef.current?.abort()
    const controller = new AbortController()
    abortRef.current = controller
    const seq = seqRef.current + 1
    seqRef.current = seq
    await runVerify(last.file, last.wallet, seq, controller.signal)
  }, [runVerify])

  // Abort any in-flight work on unmount.
  useEffect(() => {
    return () => {
      abortRef.current?.abort()
    }
  }, [])

  return {
    verifyHash,
    verifyResult,
    events,
    chainProof,
    status,
    errorCode,
    isVerifying,
    offline,
    setOffline,
    verifyEvidence,
    loadEvents,
    cancel,
    retry,
    loadSharedVerification,
    clear,
  }
}
