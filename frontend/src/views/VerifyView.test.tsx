import { render, screen, fireEvent } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { describe, expect, it, vi } from 'vitest'
import { VerifyView } from './VerifyView'
import type { UseVerificationReturn } from '../hooks/useVerification'

vi.mock('../stellar', () => ({
  CONTRACT_NETWORK_PASSPHRASE: 'Test SDF Future Network ; October 2022',
  getProofByVideoHash: vi.fn(),
  WatchWalletChanges: vi.fn(),
  connectFreighter: vi.fn(),
  getWalletNetwork: vi.fn(),
}))

vi.mock('../components/ChainProofPanel', () => ({
  ChainProofPanel: () => <div data-testid="chain-proof-panel" />,
  formatProofExpiry: () => 'Never',
}))

vi.mock('../components/VerifierSetStatusPanel', () => ({
  VerifierSetStatusPanel: () => <div data-testid="verifier-set-status-panel" />,
}))

vi.mock('../provenance/ProvenanceCard', () => ({
  default: () => <div data-testid="provenance-card" />,
}))

function makeHook(overrides: Partial<UseVerificationReturn> = {}): UseVerificationReturn {
  const base: UseVerificationReturn = {
    verifyHash: '',
    verifyResult: '',
    events: [],
    chainProof: null,
    status: 'idle',
    errorCode: null,
    isVerifying: false,
    offline: false,
    setOffline: vi.fn(),
    verifyEvidence: vi.fn(),
    loadEvents: vi.fn(),
    loadSharedVerification: vi.fn(),
    cancel: vi.fn(),
    retry: vi.fn(),
    clear: vi.fn(),
  }
  return { ...base, ...overrides }
}

function renderView(overrides: Partial<UseVerificationReturn> = {}) {
  const verification = makeHook(overrides)
  return {
    verification,
    ...render(
      <VerifyView
        wallet=""
        networkMismatch={null}
        verification={verification}
        provenanceRecord={null}
      />,
    ),
  }
}

describe('VerifyView – offline local verification mode', () => {
  it('renders a mode toggle defaulting to online', () => {
    renderView()
    const toggle = screen.getByRole('button', { name: /offline local check/i })
    expect(toggle).toHaveAttribute('aria-pressed', 'false')
    expect(screen.getByText(/backend api, the neondb event feed/i)).toBeInTheDocument()
  })

  it('toggling calls setOffline with the opposite value', async () => {
    const user = userEvent.setup()
    const { verification } = renderView()
    await user.click(screen.getByRole('button', { name: /offline local check/i }))
    expect(verification.setOffline).toHaveBeenCalledWith(true)
  })

  it('disables the toggle while verifying', () => {
    renderView({ isVerifying: true })
    expect(screen.getByRole('button', { name: /offline local check/i })).toBeDisabled()
  })

  it('offline mode surfaces not-checked chain and events without network controls', () => {
    renderView({ offline: true })
    expect(screen.getByText(/runs fully local/i)).toBeInTheDocument()
    expect(screen.getByText(/not checked \(offline\)/i)).toBeInTheDocument()
    expect(screen.getByText(/on-chain status was not checked in offline mode/i)).toBeInTheDocument()
    expect(screen.getByText(/neondb events were not queried in offline mode/i)).toBeInTheDocument()
    // Online-only controls are hidden in offline mode
    expect(screen.queryByRole('button', { name: /refresh recent proofs/i })).not.toBeInTheDocument()
  })

  it('offline success shows the local result and hides the share link', () => {
    renderView({
      offline: true,
      status: 'success',
      verifyHash: 'a'.repeat(64),
      verifyResult: 'Locally verified: the artifact carries a valid Harpocrates metadata envelope.',
    })

    expect(screen.getByText(/locally verified/i)).toBeInTheDocument()
    expect(screen.getByText(/offline mode produces no shareable verification link/i)).toBeInTheDocument()
    expect(screen.queryByRole('button', { name: /copy shareable verification link/i })).not.toBeInTheDocument()
  })

  it('online success still offers the share link', () => {
    renderView({ status: 'success' })
    // share link is present but disabled when public fields are unavailable
    expect(screen.getByRole('button', { name: /copy shareable verification link/i })).toBeInTheDocument()
  })
})

// ─── Keyboard accessibility – dropzone (issue #288) ─────────────────────────

describe('VerifyView – dropzone keyboard accessibility', () => {
  it('dropzone label is rendered with role=button and tabIndex=0 when idle', () => {
    renderView()
    const dropzone = screen.getByRole('button', {
      name: /Drop or choose a received video/i,
    })
    expect(dropzone).toHaveAttribute('tabindex', '0')
  })

  it('dropzone aria-label includes keyboard instruction', () => {
    renderView()
    const dropzone = screen.getByRole('button', {
      name: /Drop or choose a received video/i,
    })
    expect(dropzone.getAttribute('aria-label')).toMatch(/press enter or space/i)
  })

  it('hidden file input has tabIndex=-1', () => {
    renderView()
    const fileInput = document.querySelector('input[type="file"]') as HTMLInputElement
    expect(fileInput).not.toBeNull()
    expect(fileInput.tabIndex).toBe(-1)
  })

  it('pressing Enter on the dropzone fires a click on the hidden input', () => {
    renderView()
    const dropzone = screen.getByRole('button', {
      name: /Drop or choose a received video/i,
    })
    const fileInput = document.querySelector('input[type="file"]') as HTMLInputElement
    let clicked = false
    fileInput.addEventListener('click', () => { clicked = true })

    fireEvent.keyDown(dropzone, { key: 'Enter', code: 'Enter' })

    expect(clicked).toBe(true)
  })

  it('pressing Space on the dropzone fires a click on the hidden input', () => {
    renderView()
    const dropzone = screen.getByRole('button', {
      name: /Drop or choose a received video/i,
    })
    const fileInput = document.querySelector('input[type="file"]') as HTMLInputElement
    let clicked = false
    fileInput.addEventListener('click', () => { clicked = true })

    fireEvent.keyDown(dropzone, { key: ' ', code: 'Space' })

    expect(clicked).toBe(true)
  })

  it('dropzone is not keyboard-focusable while verifying (tabIndex=-1)', () => {
    renderView({ isVerifying: true, status: 'verifying' })
    const dropzone = screen.getByRole('button', { name: /inspecting evidence/i })
    expect(dropzone).toHaveAttribute('tabindex', '-1')
  })

  it('dropzone has aria-disabled=true while verifying', () => {
    renderView({ isVerifying: true, status: 'verifying' })
    const dropzone = screen.getByRole('button', { name: /inspecting evidence/i })
    expect(dropzone).toHaveAttribute('aria-disabled', 'true')
  })

  it('Enter key is blocked while verifying (no click on input)', () => {
    renderView({ isVerifying: true, status: 'verifying' })
    const dropzone = screen.getByRole('button', { name: /inspecting evidence/i })
    const fileInput = document.querySelector('input[type="file"]') as HTMLInputElement
    let clicked = false
    fileInput.addEventListener('click', () => { clicked = true })

    fireEvent.keyDown(dropzone, { key: 'Enter', code: 'Enter' })

    expect(clicked).toBe(false)
  })
})

// ─── Portable Proof Manifest Loading ────────────────────────────────────────

describe('VerifyView – portable proof manifest loading', () => {
  const VALID_MANIFEST = {
    protocol: 'harpocrates',
    version: 2,
    proofId: '0x' + 'a'.repeat(64),
    tier: 'silent',
    network: 'Test SDF Network ; September 2015',
    contractId: 'CAAAAAAAAABCD1234567890ABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890',
    transactionRef: '0x' + 'b'.repeat(64),
    videoHash: '1111222233334444555566667777888811112222333344445555666677778888',
    metadataHash: 'aaaa222233334444555566667777888811112222333344445555666677778888',
    sourceHash: 'bbbb222233334444555566667777888811112222333344445555666677778888',
    timestamp: '2026-10-19T00:00:00Z',
    verifierScope: '0',
    epoch: 0,
  }

  const LEGACY_MANIFEST = {
    protocol: 'harpocrates',
    version: 1,
    proofId: '0x' + 'f'.repeat(64),
    tier: 'source',
    network: 'Test SDF Network ; September 2015',
    contractId: 'CBBBBBBBBABCD1234567890ABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890',
    transactionRef: '0x' + 'e'.repeat(64),
    videoHash: '2222333344445555666677778888999922223333444455556666777788889999',
    metadataHash: 'cccc222233334444555566667777888811112222333344445555666677778888',
    sourceHash: 'dddd222233334444555566667777888811112222333344445555666677778888',
    timestamp: '2025-01-01T00:00:00Z',
  }

  it('renders manifest dropzone and verification form inputs', () => {
    renderView()
    expect(screen.getByRole('button', { name: /proof manifest json upload/i })).toBeInTheDocument()
    expect(screen.getByLabelText(/video hash/i)).toBeInTheDocument()
    expect(screen.getByLabelText(/proof id/i)).toBeInTheDocument()
    expect(screen.getByRole('button', { name: /verify on-chain/i })).toBeInTheDocument()
  })

  it('valid v2 manifest populates the form and starts chain verification', async () => {
    const { verification } = renderView()
    const manifestFile = new File(
      [JSON.stringify(VALID_MANIFEST)],
      'proof-manifest.json',
      { type: 'application/json' },
    )

    const manifestInput = screen.getByLabelText(/drop or choose a proof manifest json/i) as HTMLInputElement
    fireEvent.change(manifestInput, { target: { files: [manifestFile] } })

    // Await async parsing
    await screen.findByDisplayValue(VALID_MANIFEST.videoHash)
    expect(screen.getByDisplayValue(VALID_MANIFEST.proofId)).toBeInTheDocument()
    expect(verification.loadSharedVerification).toHaveBeenCalledWith(
      expect.objectContaining({
        videoHash: VALID_MANIFEST.videoHash,
        proofId: VALID_MANIFEST.proofId,
      }),
    )
  })

  it('legacy v1 manifest populates the form and starts chain verification', async () => {
    const { verification } = renderView()
    const manifestFile = new File(
      [JSON.stringify(LEGACY_MANIFEST)],
      'legacy-receipt.json',
      { type: 'application/json' },
    )

    const manifestInput = screen.getByLabelText(/drop or choose a proof manifest json/i) as HTMLInputElement
    fireEvent.change(manifestInput, { target: { files: [manifestFile] } })

    await screen.findByDisplayValue(LEGACY_MANIFEST.videoHash)
    expect(screen.getByDisplayValue(LEGACY_MANIFEST.proofId)).toBeInTheDocument()
    expect(verification.loadSharedVerification).toHaveBeenCalledWith(
      expect.objectContaining({
        videoHash: LEGACY_MANIFEST.videoHash,
        proofId: LEGACY_MANIFEST.proofId,
      }),
    )
  })

  it('malformed JSON manifest shows clear error and does not start verification', async () => {
    const { verification } = renderView()
    const malformedFile = new File(['not valid json {{{'], 'bad.json', {
      type: 'application/json',
    })

    const manifestInput = screen.getByLabelText(/drop or choose a proof manifest json/i) as HTMLInputElement
    fireEvent.change(manifestInput, { target: { files: [malformedFile] } })

    const alert = await screen.findByRole('alert')
    expect(alert).toHaveTextContent(/invalid or malformed proof manifest json/i)
    expect(verification.loadSharedVerification).not.toHaveBeenCalled()
  })

  it('JSON with missing required protocol/hashes shows clear error', async () => {
    const { verification } = renderView()
    const invalidJson = JSON.stringify({ protocol: 'unknown', version: 1 })
    const invalidFile = new File([invalidJson], 'invalid.json', {
      type: 'application/json',
    })

    const manifestInput = screen.getByLabelText(/drop or choose a proof manifest json/i) as HTMLInputElement
    fireEvent.change(manifestInput, { target: { files: [invalidFile] } })

    const alert = await screen.findByRole('alert')
    expect(alert).toHaveTextContent(/invalid or malformed proof manifest json/i)
    expect(verification.loadSharedVerification).not.toHaveBeenCalled()
  })

  it('oversize manifest (>64 KB) shows clear error and does not parse', async () => {
    const { verification } = renderView()
    // Create payload larger than 64 KB (65536 bytes)
    const largeContent = 'x'.repeat(65 * 1024)
    const oversizeFile = new File([largeContent], 'oversized.json', {
      type: 'application/json',
    })

    const manifestInput = screen.getByLabelText(/drop or choose a proof manifest json/i) as HTMLInputElement
    fireEvent.change(manifestInput, { target: { files: [oversizeFile] } })

    const alert = await screen.findByRole('alert')
    expect(alert).toHaveTextContent(/exceeds the 64 KB size limit/i)
    expect(verification.loadSharedVerification).not.toHaveBeenCalled()
  })

  it('dropping a valid manifest onto the drop target populates the form', async () => {
    const { verification } = renderView()
    const manifestFile = new File(
      [JSON.stringify(VALID_MANIFEST)],
      'manifest.json',
      { type: 'application/json' },
    )

    const dropTarget = screen.getByRole('button', { name: /proof manifest json upload/i })
    fireEvent.drop(dropTarget, {
      dataTransfer: {
        files: [manifestFile],
      },
    })

    await screen.findByDisplayValue(VALID_MANIFEST.videoHash)
    expect(verification.loadSharedVerification).toHaveBeenCalled()
  })

  it('dropping a manifest onto the video dropzone delegates to manifest handler', async () => {
    const { verification } = renderView()
    const manifestFile = new File(
      [JSON.stringify(VALID_MANIFEST)],
      'manifest.json',
      { type: 'application/json' },
    )

    const videoDropzone = screen.getByRole('button', { name: /drop or choose a received video/i })
    fireEvent.drop(videoDropzone, {
      dataTransfer: {
        files: [manifestFile],
      },
    })

    await screen.findByDisplayValue(VALID_MANIFEST.videoHash)
    expect(verification.loadSharedVerification).toHaveBeenCalled()
  })

  describe('manifest dropzone keyboard accessibility', () => {
    it('manifest dropzone label has role=button and tabIndex=0 when idle', () => {
      renderView()
      const dropzone = screen.getByRole('button', {
        name: /proof manifest json upload/i,
      })
      expect(dropzone).toHaveAttribute('tabindex', '0')
    })

    it('manifest dropzone hidden input has tabIndex=-1', () => {
      renderView()
      const input = screen.getByLabelText(/drop or choose a proof manifest json/i) as HTMLInputElement
      expect(input.tabIndex).toBe(-1)
    })

    it('pressing Enter on manifest dropzone fires click on hidden input', () => {
      renderView()
      const dropzone = screen.getByRole('button', {
        name: /proof manifest json upload/i,
      })
      const input = screen.getByLabelText(/drop or choose a proof manifest json/i) as HTMLInputElement
      let clicked = false
      input.addEventListener('click', () => { clicked = true })

      fireEvent.keyDown(dropzone, { key: 'Enter', code: 'Enter' })
      expect(clicked).toBe(true)
    })

    it('pressing Space on manifest dropzone fires click on hidden input', () => {
      renderView()
      const dropzone = screen.getByRole('button', {
        name: /proof manifest json upload/i,
      })
      const input = screen.getByLabelText(/drop or choose a proof manifest json/i) as HTMLInputElement
      let clicked = false
      input.addEventListener('click', () => { clicked = true })

      fireEvent.keyDown(dropzone, { key: ' ', code: 'Space' })
      expect(clicked).toBe(true)
    })

    it('manifest dropzone is disabled and not focusable while verifying', () => {
      renderView({ isVerifying: true, status: 'verifying' })
      const dropzone = screen.getByRole('button', {
        name: /manifest upload disabled during verification/i,
      })
      expect(dropzone).toHaveAttribute('tabindex', '-1')
      expect(dropzone).toHaveAttribute('aria-disabled', 'true')
    })

    it('Enter key is blocked on manifest dropzone while verifying', () => {
      renderView({ isVerifying: true, status: 'verifying' })
      const dropzone = screen.getByRole('button', {
        name: /manifest upload disabled during verification/i,
      })
      const input = screen.getByLabelText(/drop or choose a proof manifest json/i) as HTMLInputElement
      let clicked = false
      input.addEventListener('click', () => { clicked = true })

      fireEvent.keyDown(dropzone, { key: 'Enter', code: 'Enter' })
      expect(clicked).toBe(false)
    })
  })
})