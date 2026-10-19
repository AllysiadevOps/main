import { useMemo, useState } from 'react'
import type { ProvenanceRecord } from './provenanceModel'

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

  const serialized = useMemo(() => JSON.stringify(provenance, null, 2), [provenance])
  const warningMessage = [mismatchSummary(provenance), stalenessSummary(provenance)]
    .filter(Boolean)
    .join(' ')

  async function copyProvenance() {
    try {
      await navigator.clipboard.writeText(serialized)
      setCopyState('copied')
    } catch {
      setCopyState('error')
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

      <dl className="provenance-grid">
        <div>
          <dt>Circuit</dt>
          <dd>
            {provenance.circuit.name} v{provenance.circuit.version}
          </dd>
        </div>
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
            {provenance.ledger.transactionHash && provenance.links.transaction ? (
              <a href={provenance.links.transaction} target="_blank" rel="noreferrer" title={provenance.ledger.transactionHash}>
                {shortValue(provenance.ledger.transactionHash)}
              </a>
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
            <span title={provenance.metadata.videoHash}>{shortValue(provenance.metadata.videoHash)}</span>
            <span title={provenance.metadata.metadataHash}>{shortValue(provenance.metadata.metadataHash)}</span>
            <span title={provenance.metadata.sourceHash}>{shortValue(provenance.metadata.sourceHash)}</span>
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
