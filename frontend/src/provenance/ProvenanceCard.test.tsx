import { render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { describe, expect, it, vi } from 'vitest'
import ProvenanceCard from './ProvenanceCard'
import { buildProvenanceRecord } from './provenanceModel'
import type { ProvenanceRecord } from './provenanceModel'
import type { ChainProofRecord, IdentityTier } from '../stellarTypes'

const MOCK_PROVENANCE: ProvenanceRecord = {
  circuit: {
    name: 'silent_witness',
    version: '1',
  },
  verifier: {
    contractId: 'C'.repeat(56),
    method: 'register_source',
  },
  network: {
    passphrase: 'Test Network Passphrase',
    rpcUrl: 'https://rpc.example.test',
    label: 'Stellar Testnet',
  },
  ledger: {
    transactionHash: 'f'.repeat(64),
    status: 1,
    createdAt: '2026-07-25T11:58:30.000Z',
  },
  metadata: {
    videoHash: 'a'.repeat(64),
    metadataHash: 'b'.repeat(64),
    sourceHash: 'c'.repeat(64),
  },
  links: {
    transaction: 'https://stellar.expert/explorer/testnet/tx/' + 'f'.repeat(64),
    contract: 'https://stellar.expert/explorer/testnet/contract/' + 'C'.repeat(56),
  },
  mismatches: [],
  staleness: { stale: false },
  disputes: { openCount: null },
  fetchedAt: '2026-07-25T12:00:00.000Z',
}

function mockClipboard(writeText: ReturnType<typeof vi.fn>) {
  Object.defineProperty(navigator, 'clipboard', {
    value: { writeText },
    configurable: true,
    writable: true,
  })
}

describe('ProvenanceCard hash copy buttons', () => {
  it('copies the full proof ID and shows confirmation', async () => {
    const user = userEvent.setup()
    const writeText = vi.fn().mockResolvedValue(undefined)
    mockClipboard(writeText)

    render(<ProvenanceCard provenance={MOCK_PROVENANCE} />)

    const copyBtn = screen.getByRole('button', { name: 'Copy proof ID' })
    await user.click(copyBtn)

    expect(writeText).toHaveBeenCalledWith(MOCK_PROVENANCE.metadata.metadataHash)
    expect(screen.getByText('Proof ID copied to clipboard.')).toBeInTheDocument()
  })

  it('copies the full video hash, source hash, and transaction hash', async () => {
    const user = userEvent.setup()
    const writeText = vi.fn().mockResolvedValue(undefined)
    mockClipboard(writeText)

    render(<ProvenanceCard provenance={MOCK_PROVENANCE} />)

    await user.click(screen.getByRole('button', { name: 'Copy video hash' }))
    expect(writeText).toHaveBeenCalledWith(MOCK_PROVENANCE.metadata.videoHash)
    expect(screen.getByText('Video hash copied to clipboard.')).toBeInTheDocument()

    await user.click(screen.getByRole('button', { name: 'Copy source hash' }))
    expect(writeText).toHaveBeenCalledWith(MOCK_PROVENANCE.metadata.sourceHash)
    expect(screen.getByText('Source hash copied to clipboard.')).toBeInTheDocument()

    await user.click(screen.getByRole('button', { name: 'Copy transaction hash' }))
    expect(writeText).toHaveBeenCalledWith(MOCK_PROVENANCE.ledger.transactionHash)
    expect(screen.getByText('Transaction hash copied to clipboard.')).toBeInTheDocument()
  })

  it('shows an error message when clipboard permission is denied', async () => {
    const user = userEvent.setup()
    const writeText = vi.fn().mockRejectedValue(new DOMException('Permission denied', 'NotAllowedError'))
    mockClipboard(writeText)

    render(<ProvenanceCard provenance={MOCK_PROVENANCE} />)

    const copyBtn = screen.getByRole('button', { name: 'Copy proof ID' })
    await user.click(copyBtn)

    expect(writeText).toHaveBeenCalledWith(MOCK_PROVENANCE.metadata.metadataHash)
    expect(screen.getByText('Unable to copy proof id.')).toBeInTheDocument()
  })

  it('omits the transaction copy button when transactionHash is null', () => {
    render(
      <ProvenanceCard
        provenance={{
          ...MOCK_PROVENANCE,
          ledger: { ...MOCK_PROVENANCE.ledger, transactionHash: null },
          links: { ...MOCK_PROVENANCE.links, transaction: null },
        }}
      />,
    )

    expect(screen.queryByRole('button', { name: 'Copy transaction hash' })).not.toBeInTheDocument()
    expect(screen.getByRole('button', { name: 'Copy video hash' })).toBeInTheDocument()
    expect(screen.getByRole('button', { name: 'Copy proof ID' })).toBeInTheDocument()
    expect(screen.getByRole('button', { name: 'Copy source hash' })).toBeInTheDocument()
  })
})

const MANIFEST = {
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

const CHAIN_PROOF: ChainProofRecord = {
  videoHash: MANIFEST.videoHash,
  metadataHash: MANIFEST.metadataHash,
  tier: 1,
  status: 1,
  createdAt: '2026-07-25T11:58:30.000Z',
  expiresAt: 0,
  source: null,
  issuer: null,
}

function renderCard(openDisputeCount: number | null | undefined) {
  const provenance = buildProvenanceRecord({
    manifest: MANIFEST,
    chainProof: CHAIN_PROOF,
    rpcUrl: 'https://rpc.example.test',
    transactionHash: 'f'.repeat(64),
    method: 'register_source',
    openDisputeCount,
    fetchedAt: new Date('2026-07-25T12:00:00.000Z'),
  })
  return render(<ProvenanceCard provenance={provenance} />)
}

describe('ProvenanceCard dispute notice', () => {
  it('shows an accessible "Under dispute" notice with the count when disputes are open', () => {
    renderCard(2)

    const notice = screen.getByTestId('provenance-dispute')
    expect(notice).toHaveAttribute('role', 'status')
    expect(notice).toHaveTextContent('Under dispute')
    expect(notice).toHaveTextContent('This proof has 2 open disputes recorded on chain.')
  })

  it('uses the singular form for a single dispute', () => {
    renderCard(1)

    expect(screen.getByTestId('provenance-dispute')).toHaveTextContent('1 open dispute recorded on chain.')
  })

  it('shows no notice when there are no open disputes', () => {
    renderCard(0)

    expect(screen.queryByTestId('provenance-dispute')).toBeNull()
    expect(screen.queryByText('Under dispute')).toBeNull()
  })

  it('shows no notice when the count is unknown (lookup pending or failed)', () => {
    renderCard(null)

    expect(screen.queryByTestId('provenance-dispute')).toBeNull()
  })

  it('does not fold the dispute into the verification warning', () => {
    renderCard(3)

    expect(screen.queryByText('Verification warning')).toBeNull()
  })
})
