import { useMemo, useState } from 'react'
import { disputeNotice, type ProvenanceRecord } from './provenanceModel'

type ProvenanceCardProps = {
  provenance: ProvenanceRecord
}

function shortValue(value: string, prefixLength = 12, suffixLength = 10) {
  if (value.length <= prefixLength + suffixLength + 3) return value
  return `${value.slice(0, prefixLength)}...${value.slice(-suffixLength)}`
}

function formatDateTime(value: string | null) {
  if (!value) return 'Not available'

  const parsed = new Date(value)
  if (Number.isNaN(parsed.getTime())) return value

  return new Intl.DateTimeFormat(undefined, {
    dateStyle: 'medium',
    timeStyle: 'medium',
  }).format(parsed)
}

function formatStatus(status: number | null) {
  if (status === null) return 'Not available'
  if (status === 0) return 'Pending'
  if (status === 1) return 'Confirmed'
  if (status === 2) return 'Revoked'
  return String(status)
}

function mismatchSummary(provenance: ProvenanceRecord) {
  if (provenance.mismatches.length === 0) return ''

  const fields = provenance.mismatches.map((mismatch) => mismatch.field).join(', ')
  return `Manifest mismatch detected for ${fields}.`
}

function stalenessSummary(provenance: ProvenanceRecord) {
  if (!provenance.staleness.stale) return ''

  if (provenance.staleness.reason === 'no-chain-record') {
    return 'No on-chain record was returned for this proof.'
  }

  if (provenance.staleness.reason === 'fetch-error') {
    return 'The chain record could not be refreshed.'
  }

  return 'The chain record is older than the current freshness window while still pending.'
}

export default function ProvenanceCard({ provenance }: ProvenanceCardProps) {
  const [copyState, setCopyState] = useState<'idle' | 'copied' | 'error'>('idle')
  const [hashCopyState, setHashCopyState] = useState<{
    status: 'idle' | 'copied' | 'error'
    label: string
  }>({ status: 'idle', label: '' })

  const serialized = useMemo(() => JSON.stringify(provenance, null, 2), [provenance])
  const warningMessage = [mismatchSummary(provenance), stalenessSummary(provenance)]
    .filter(Boolean)
    .join(' ')
  const disputeMessage = disputeNotice(provenance)

  async function copyProvenance() {
    try {
      await navigator.clipboard.writeText(serialized)
      setCopyState('copied')
    } catch {
      setCopyState('error')
    }
  }

  async function copyHash(value: string, label: string) {
    try {
      await navigator.clipboard.writeText(value)
      setHashCopyState({ status: 'copied', label })
    } catch {
      setHashCopyState({ status: 'error', label })
    }
  }

  function exportProvenance() {
    const blob = new Blob([serialized], { type: 'application/json' })
    const url = URL.createObjectURL(blob)
    const link = document.createElement('a')
    link.href = url
    link.download = 'provenance.json'
    link.rel = 'noopener'
    document.body.appendChild(link)
    link.click()
    link.remove()
    URL.revokeObjectURL(url)
  }

  return (
    <article className="provenance-card" aria-labelledby="provenance-card-title">
      <header className="provenance-card__header">
        <h4 id="provenance-card-title">Provenance Record</h4>
        <p>Portable proof manifest, on-chain record, and freshness checks.</p>
      </header>

      {warningMessage ? (
        <div className="provenance-warning" role="status" aria-live="polite">
          <strong>Verification warning</strong>
          <p>{warningMessage}</p>
        </div>
      ) : null}

      {disputeMessage ? (
        <div className="provenance-dispute" role="status" aria-live="polite" data-testid="provenance-dispute">
          <strong>Under dispute</strong>
          <p>{disputeMessage}</p>
        </div>
      ) : null}

      <dl className="provenance-grid">
        <div>
          <dt>Circuit</dt>
          <dd>
            {provenance.circuit.name} v{provenance.circuit.version}
          </dd>
        </div>
        {provenance.circuitVersion !== undefined && provenance.circuitVersion !== null ? (
          <div>
            <dt>Circuit version</dt>
            <dd>{provenance.circuitVersion}</dd>
          </div>
        ) : null}
        <div>
          <dt>Verifier</dt>
          <dd>
            <span>{provenance.verifier.contractId}</span>
            <span>{provenance.verifier.method}</span>
          </dd>
        </div>
        <div>
          <dt>Network</dt>
          <dd>{provenance.network.label}</dd>
        </div>
        <div>
          <dt>Transaction</dt>
          <dd>
            {provenance.ledger.transactionHash ? (
              <span className="provenance-hash-row">
                {provenance.links.transaction ? (
                  <a href={provenance.links.transaction} target="_blank" rel="noreferrer" title={provenance.ledger.transactionHash}>
                    {shortValue(provenance.ledger.transactionHash)}
                  </a>
                ) : (
                  <span title={provenance.ledger.transactionHash}>{shortValue(provenance.ledger.transactionHash)}</span>
                )}
                <button
                  type="button"
                  className="provenance-copy-btn"
                  onClick={() => void copyHash(provenance.ledger.transactionHash!, 'Transaction hash')}
                  aria-label="Copy transaction hash"
                >
                  {hashCopyState.status === 'copied' && hashCopyState.label === 'Transaction hash' ? 'Copied' : 'Copy'}
                </button>
              </span>
            ) : (
              'Not available'
            )}
          </dd>
        </div>
        <div>
          <dt>Status</dt>
          <dd>{formatStatus(provenance.ledger.status)}</dd>
        </div>
        <div>
          <dt>Created</dt>
          <dd>{formatDateTime(provenance.ledger.createdAt)}</dd>
        </div>
        <div>
          <dt>Metadata</dt>
          <dd>
            <span className="provenance-hash-row">
              <span title={provenance.metadata.videoHash}>{shortValue(provenance.metadata.videoHash)}</span>
              <button
                type="button"
                className="provenance-copy-btn"
                onClick={() => void copyHash(provenance.metadata.videoHash, 'Video hash')}
                aria-label="Copy video hash"
              >
                {hashCopyState.status === 'copied' && hashCopyState.label === 'Video hash' ? 'Copied' : 'Copy'}
              </button>
            </span>
            <span className="provenance-hash-row">
              <span title={provenance.metadata.metadataHash}>{shortValue(provenance.metadata.metadataHash)}</span>
              <button
                type="button"
                className="provenance-copy-btn"
                onClick={() => void copyHash(provenance.metadata.metadataHash, 'Proof ID')}
                aria-label="Copy proof ID"
              >
                {hashCopyState.status === 'copied' && hashCopyState.label === 'Proof ID' ? 'Copied' : 'Copy'}
              </button>
            </span>
            <span className="provenance-hash-row">
              <span title={provenance.metadata.sourceHash}>{shortValue(provenance.metadata.sourceHash)}</span>
              <button
                type="button"
                className="provenance-copy-btn"
                onClick={() => void copyHash(provenance.metadata.sourceHash, 'Source hash')}
                aria-label="Copy source hash"
              >
                {hashCopyState.status === 'copied' && hashCopyState.label === 'Source hash' ? 'Copied' : 'Copy'}
              </button>
            </span>
          </dd>
        </div>
        <div>
          <dt>Contract link</dt>
          <dd>
            {provenance.links.contract ? (
              <a href={provenance.links.contract} target="_blank" rel="noreferrer" title={provenance.verifier.contractId}>
                Open contract explorer
              </a>
            ) : (
              'Not available'
            )}
          </dd>
        </div>
      </dl>

      {hashCopyState.status !== 'idle' ? (
        <p className="provenance-copy-status" role="status" aria-live="polite">
          {hashCopyState.status === 'copied'
            ? `${hashCopyState.label} copied to clipboard.`
            : `Unable to copy ${hashCopyState.label.toLowerCase()}.`}
        </p>
      ) : null}

      <div className="provenance-actions" aria-label="Provenance export actions">
        <button type="button" onClick={() => void copyProvenance()} aria-label="Copy provenance JSON">
          Copy provenance JSON
        </button>
        <button type="button" onClick={exportProvenance} aria-label="Export provenance as file">
          Export as file
        </button>
      </div>

      {copyState !== 'idle' ? (
        <p className="provenance-copy-status" aria-live="polite">
          {copyState === 'copied' ? 'Provenance JSON copied to clipboard.' : 'Unable to copy provenance JSON.'}
        </p>
      ) : null}
    </article>
  )
}
