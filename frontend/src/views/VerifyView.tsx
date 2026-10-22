import { useEffect, useMemo, useRef, useState } from 'react'
import { CheckCircle2, FileText, Loader2, RefreshCw, Upload, WifiOff, XCircle } from 'lucide-react'
import type { UseVerificationReturn } from '../hooks/useVerification'
import { ChainProofPanel } from '../components/ChainProofPanel'
import { EventList } from '../components/EventList'
import { ShareVerificationLink } from '../components/ShareVerificationLink'
import { VerifierSetStatusPanel } from '../components/VerifierSetStatusPanel'
import VerificationTimeline from '../components/VerificationTimeline'
import { shortHash } from '../utils'
import ProvenanceCard from '../provenance/ProvenanceCard'
import type { ProvenanceRecord } from '../provenance/provenanceModel'
import { CONTRACT_NETWORK_PASSPHRASE } from '../stellar'
import type { VerificationShareLinkInput } from '../verificationShareLink'
import { tryParseManifest } from '../batchVerifier'

const CONTRACT_ID = import.meta.env.VITE_HARPOCRATES_REGISTRY_ID ?? ''
const MAX_MANIFEST_SIZE_BYTES = 64 * 1024 // 64 KB cap

type Props = {
  wallet: string
  networkMismatch?: string | null
  verification: UseVerificationReturn
  provenanceRecord: ProvenanceRecord | null
}

function statusLabel(status: UseVerificationReturn['status'], offline: boolean): string {
  switch (status) {
    case 'validating': return 'Validating file…'
    case 'hashing': return 'Hashing evidence…'
    case 'verifying': return offline ? 'Inspecting evidence locally…' : 'Inspecting evidence…'
    case 'success': return 'Verification complete.'
    case 'error': return 'Verification did not confirm this artifact.'
    case 'cancelled': return 'Verification cancelled.'
    default: return 'No verification run yet.'
  }
}

export function VerifyView({ wallet, networkMismatch, verification, provenanceRecord }: Props) {
  const {
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
    loadSharedVerification,
    cancel,
    retry,
    clear,
  } = verification

  const inputRef = useRef<HTMLInputElement | null>(null)
  const manifestInputRef = useRef<HTMLInputElement | null>(null)
  const [videoHashInput, setVideoHashInput] = useState('')
  const [proofIdInput, setProofIdInput] = useState('')
  const [manifestError, setManifestError] = useState<string | null>(null)

  // Keep videoHashInput synced when verifyHash updates externally
  useEffect(() => {
    if (verifyHash && !videoHashInput) {
      setVideoHashInput(verifyHash)
    }
  }, [verifyHash, videoHashInput])

  const handleManifestFile = async (file: File) => {
    if (file.size > MAX_MANIFEST_SIZE_BYTES) {
      setManifestError(`Manifest file exceeds the 64 KB size limit (${(file.size / 1024).toFixed(1)} KB).`)
      return
    }

    const manifest = await tryParseManifest(file)
    if (!manifest) {
      setManifestError('Invalid or malformed proof manifest JSON.')
      return
    }

    setManifestError(null)
    setVideoHashInput(manifest.videoHash)
    setProofIdInput(manifest.proofId ?? '')

    // Start chain verification
    if (typeof loadSharedVerification === 'function') {
      void loadSharedVerification({
        protocol: 'harpocrates-verification-link',
        version: 1,
        videoHash: manifest.videoHash,
        proofId: manifest.proofId,
        metadataHash: manifest.metadataHash,
        network: manifest.network || CONTRACT_NETWORK_PASSPHRASE,
        contractId: manifest.contractId || CONTRACT_ID,
        transactionRef: manifest.transactionRef || undefined,
        tier: manifest.tier,
      })
    }
  }

  const handleManualSubmit = async () => {
    const vHash = videoHashInput.trim()
    const pId = proofIdInput.trim()
    if (!vHash) return
    setManifestError(null)
    if (typeof loadSharedVerification === 'function') {
      void loadSharedVerification({
        protocol: 'harpocrates-verification-link',
        version: 1,
        videoHash: vHash,
        proofId: pId,
        metadataHash: '',
        network: CONTRACT_NETWORK_PASSPHRASE,
        contractId: CONTRACT_ID,
      })
    }
  }

  const revocationProofId =
    events.find((event) => event.video_hash === (videoHashInput || verifyHash) && event.proof_id)?.proof_id ??
    proofIdInput ??
    null

  const isError = status === 'error'
  const isCancelled = status === 'cancelled'
  const showRetry = isError && !manifestError && !!errorCode && errorCode !== 'CANCELLED' && errorCode !== 'REVOKED_EVIDENCE' && errorCode !== 'EXPIRED_EVIDENCE'
  // Revoked/expired are terminal trust decisions, retry still allowed but we keep it available via retry button
  const effectiveRetry = isError || isCancelled

  const shareLinkInput = useMemo((): VerificationShareLinkInput | null => {
    const activeHash = videoHashInput || verifyHash
    if (status !== 'success' || !activeHash || !CONTRACT_ID) return null
    const matchedEvent = events.find((event) => event.proof_id && event.video_hash === activeHash)
      ?? events.find((event) => !!event.proof_id)
    const proofId = matchedEvent?.proof_id ?? proofIdInput ?? null
    const metadataHash = chainProof?.metadataHash ?? provenanceRecord?.metadata.metadataHash ?? null
    if (!proofId || !metadataHash) return null
    const tierRaw = matchedEvent?.tier
    const tier =
      tierRaw === 'silent' || tierRaw === 'source' || tierRaw === 'seal' ? tierRaw : undefined
    return {
      videoHash: activeHash,
      proofId,
      metadataHash,
      network: provenanceRecord?.network.passphrase || CONTRACT_NETWORK_PASSPHRASE,
      contractId: CONTRACT_ID,
      transactionRef: provenanceRecord?.ledger.transactionHash || matchedEvent?.tx_hash || undefined,
      tier,
    }
  }, [status, videoHashInput, verifyHash, events, proofIdInput, chainProof, provenanceRecord])

  return (
    <section className="workspace app-page verify-page" id="verify">
      <div className="studio verify-studio">
        <header className="page-header">
          <h2 id="verify-heading" tabIndex={-1}>Verify Artifact</h2>
          <p>Inspect a received video against embedded metadata and the Stellar registry.</p>
        </header>

        {networkMismatch ? (
          <div className="network-mismatch-banner" role="alert" aria-live="assertive" aria-atomic="true">
            <span className="network-mismatch-icon" aria-hidden="true">⚠</span>
            <span>{networkMismatch}</span>
          </div>
        ) : null}

        {manifestError ? (
          <div className="network-mismatch-banner manifest-error-banner" role="alert" aria-live="assertive" aria-atomic="true">
            <span className="network-mismatch-icon" aria-hidden="true">⚠</span>
            <span>{manifestError}</span>
          </div>
        ) : null}

        {/* Dropzone — keyboard: Tab focuses the label, Enter/Space opens the file picker */}
        <label
          className="dropzone"
          role="button"
          tabIndex={isVerifying ? -1 : 0}
          aria-label={isVerifying ? statusLabel(status, offline) : 'Drop or choose a received video. Press Enter or Space to open file picker'}
          aria-busy={isVerifying}
          aria-disabled={isVerifying}
          // ensure dropzone is a large touch target on mobile
          style={{ minHeight: 140 }}
          onKeyDown={(e) => {
            if ((e.key === 'Enter' || e.key === ' ') && !isVerifying) {
              e.preventDefault()
              inputRef.current?.click()
            }
          }}
          onDragOver={(e) => {
            e.preventDefault()
          }}
          onDrop={(e) => {
            e.preventDefault()
            const f = e.dataTransfer.files?.[0] ?? null
            if (f) {
              if (f.name.endsWith('.json') || f.type === 'application/json') {
                void handleManifestFile(f)
              } else {
                void verifyEvidence(f, wallet || undefined)
              }
            }
          }}
        >
          {isVerifying ? (
            <Loader2 size={20} className="spin" aria-hidden="true" />
          ) : (
            <Upload size={20} aria-hidden="true" />
          )}
          <span aria-hidden="true">{isVerifying ? statusLabel(status, offline) : 'Drop or choose a received video'}</span>
          <span className="muted" aria-hidden="true" style={{ fontSize: 11, textAlign: 'center', overflowWrap: 'anywhere' }}>
            MP4, WebM, or MOV · up to 100 MB
          </span>
          <input
            ref={inputRef}
            type="file"
            accept="video/*"
            tabIndex={-1}
            aria-hidden="true"
            disabled={isVerifying}
            onChange={(event) => {
              const f = event.target.files?.[0] ?? null
              void verifyEvidence(f, wallet || undefined)
              // allow re-selecting the same file
              event.target.value = ''
            }}
          />
        </label>

        {/* Manifest Dropzone — keyboard: Tab focuses label, Enter/Space opens manifest file picker */}
        <label
          className="dropzone manifest-dropzone"
          role="button"
          tabIndex={isVerifying ? -1 : 0}
          aria-label={isVerifying ? 'Manifest upload disabled during verification' : 'Proof manifest JSON upload. Press Enter or Space to open file picker'}
          aria-busy={isVerifying}
          aria-disabled={isVerifying}
          style={{ minHeight: 100 }}
          onKeyDown={(e) => {
            if ((e.key === 'Enter' || e.key === ' ') && !isVerifying) {
              e.preventDefault()
              manifestInputRef.current?.click()
            }
          }}
          onDragOver={(e) => {
            e.preventDefault()
          }}
          onDrop={(e) => {
            e.preventDefault()
            const f = e.dataTransfer.files?.[0] ?? null
            if (f) void handleManifestFile(f)
          }}
        >
          {isVerifying ? (
            <Loader2 size={20} className="spin" aria-hidden="true" />
          ) : (
            <FileText size={20} aria-hidden="true" />
          )}
          <span aria-hidden="true">{isVerifying ? 'Verification in progress…' : 'Drop or choose a proof manifest JSON'}</span>
          <span className="muted" aria-hidden="true" style={{ fontSize: 11, textAlign: 'center', overflowWrap: 'anywhere' }}>
            Portable manifest receipt · max 64 KB
          </span>
          <input
            ref={manifestInputRef}
            type="file"
            accept=".json,application/json"
            tabIndex={-1}
            aria-label="Drop or choose a proof manifest JSON"
            disabled={isVerifying}
            onChange={(event) => {
              const f = event.target.files?.[0] ?? null
              if (f) void handleManifestFile(f)
              event.target.value = ''
            }}
          />
        </label>

        {/* Verification form — prefilled by manifest or manual typing */}
        <form
          className="manifest-verify-form"
          aria-label="Manifest verification form"
          onSubmit={(e) => {
            e.preventDefault()
            void handleManualSubmit()
          }}
        >
          <div className="form-group">
            <label htmlFor="verify-video-hash">Video Hash</label>
            <input
              id="verify-video-hash"
              type="text"
              name="videoHash"
              value={videoHashInput}
              onChange={(e) => {
                setVideoHashInput(e.target.value)
                setManifestError(null)
              }}
              placeholder="Prefilled by manifest or enter 64-char hex video hash"
              disabled={isVerifying}
              aria-label="Video Hash"
            />
          </div>
          <div className="form-group">
            <label htmlFor="verify-proof-id">Proof ID</label>
            <input
              id="verify-proof-id"
              type="text"
              name="proofId"
              value={proofIdInput}
              onChange={(e) => {
                setProofIdInput(e.target.value)
                setManifestError(null)
              }}
              placeholder="Prefilled by manifest or enter proof ID"
              disabled={isVerifying}
              aria-label="Proof ID"
            />
          </div>
          <button
            type="submit"
            className="hero-secondary"
            disabled={isVerifying || !videoHashInput.trim()}
          >
            Verify On-Chain
          </button>
        </form>

        {/* Verification mode — offline runs entirely in the browser, online uses backend + registry */}
        <div className="verify-mode" role="group" aria-label="Verification mode">
          <button
            type="button"
            className={`mode-toggle ${offline ? 'active' : ''}`}
            aria-pressed={offline}
            disabled={isVerifying}
            onClick={() => setOffline(!offline)}
          >
            <WifiOff size={14} aria-hidden="true" />
            <span>Offline local check</span>
          </button>
          <p className="muted" style={{ fontSize: 11 }}>
            {offline
              ? 'Runs fully local: hashes, extracts, and validates the embedded envelope in this browser with no network calls. It never yields a confirmed trust decision and produces no shareable verification link.'
              : 'Runs against the backend API, the NeonDB event feed, and the Stellar registry.'}
          </p>
        </div>

        {/* Progress / status live region — always present so mobile screen readers observe changes */}
        <div
          className="verify-progress"
          role="status"
          aria-live="polite"
          aria-atomic="true"
          aria-busy={isVerifying}
        >
          {isVerifying ? (
            <div className="verify-progress-row">
              <Loader2 size={14} className="spin" aria-hidden="true" />
              <span>{statusLabel(status, offline)}</span>
            </div>
          ) : null}
        </div>

        <div
          className={`verify-result large ${isError || manifestError ? 'verify-error' : ''} ${isCancelled ? 'verify-cancelled' : ''}`}
          role={isError ? 'alert' : 'status'}
          aria-live={isError ? 'assertive' : 'polite'}
          aria-atomic="true"
        >
          {isError || manifestError ? (
            <XCircle size={14} aria-hidden="true" />
          ) : (
            <CheckCircle2 size={14} aria-hidden="true" />
          )}
          <div style={{ minWidth: 0, flex: 1 }}>
            <p style={{ overflowWrap: 'anywhere', wordBreak: 'break-word' }}>
              {manifestError || verifyResult || statusLabel(status, offline)}
            </p>
            {errorCode && !manifestError ? (
              <p className="muted" style={{ marginTop: 4, fontSize: 11 }}>
                Code: {errorCode}
              </p>
            ) : null}
          </div>
        </div>

        <VerificationTimeline
          status={status}
          verifyHash={verifyHash}
          events={events}
          chainProof={chainProof}
          errorCode={errorCode}
        />

        {/* Action row — reachable on mobile, adequate touch targets */}
        <div className="verify-actions" role="group" aria-label="Verification actions">
          {isVerifying ? (
            <button
              type="button"
              className="hero-secondary verify-action-btn"
              onClick={cancel}
              aria-label="Cancel verification"
            >
              Cancel
            </button>
          ) : null}
          {effectiveRetry ? (
            <button
              type="button"
              className="hero-secondary verify-action-btn"
              onClick={() => void retry()}
              aria-label="Retry verification"
            >
              <RefreshCw size={14} aria-hidden="true" />
              <span>Retry</span>
            </button>
          ) : null}
          {!isVerifying && (verifyHash || verifyResult || videoHashInput || proofIdInput || manifestError) ? (
            <button
              type="button"
              className="hero-secondary verify-action-btn"
              onClick={() => {
                setVideoHashInput('')
                setProofIdInput('')
                setManifestError(null)
                clear()
              }}
              aria-label="Clear verification result"
            >
              Clear
            </button>
          ) : null}
          {/* Hidden retry helper for tests / keyboard users */}
          {showRetry ? null : null}
        </div>

        {offline ? (
          <p className="muted" style={{ fontSize: 11 }} role="status">
            Offline mode produces no shareable verification link and no on-chain receipt.
          </p>
        ) : (
          <ShareVerificationLink input={shareLinkInput} />
        )}

        <dl className="data-list">
          <div>
            <dt>Received Hash</dt>
            <dd style={{ overflowWrap: 'anywhere', wordBreak: 'break-all', textAlign: 'right' }}>{shortHash(videoHashInput || verifyHash)}</dd>
          </div>
          <div>
            <dt>Proof ID</dt>
            <dd style={{ overflowWrap: 'anywhere', wordBreak: 'break-all', textAlign: 'right' }}>{shortHash(proofIdInput || revocationProofId || '')}</dd>
          </div>
          <div>
            <dt>Chain Status</dt>
            <dd>{offline ? 'Not checked (offline)' : chainProof ? (chainProof.status === 2 ? 'Revoked' : chainProof.status === 3 ? 'Expired' : 'Confirmed') : 'Not loaded'}</dd>
          </div>
          <div>
            <dt>Wallet</dt>
            <dd>{wallet ? `${wallet.slice(0, 5)}…${wallet.slice(-4)}` : 'Not connected'}</dd>
          </div>
        </dl>
      </div>

      <aside className="side-rail">
        <div className="rail-block">
          <h3>Chain Registry</h3>
          {offline ? (
            <p className="muted" style={{ fontSize: 11 }} role="status">
              On-chain status was not checked in offline mode. No trust decision was made.
            </p>
          ) : (
            <>
              <ChainProofPanel
                chainProof={chainProof}
                proofId={revocationProofId}
                sourceAddress={wallet || undefined}
              />
              <h4 style={{ marginTop: '1rem', fontSize: '0.8rem', color: 'var(--text-muted)' }}>Verifier Set Status</h4>
              <VerifierSetStatusPanel />
            </>
          )}
          {provenanceRecord ? <ProvenanceCard provenance={provenanceRecord} /> : null}
        </div>

        <div className="rail-block">
          <h3>Events</h3>
          {offline ? (
            <p className="muted" style={{ fontSize: 11 }} role="status">
              NeonDB events were not queried in offline mode.
            </p>
          ) : (
            <EventList events={events} onRefresh={() => void loadEvents()} />
          )}
        </div>
      </aside>
    </section>
  )
}
