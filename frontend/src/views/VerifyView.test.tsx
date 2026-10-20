import { render, screen, fireEvent } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { describe, expect, it, vi } from 'vitest'
import { VerifyView } from './VerifyView'
import type { UseVerificationReturn } from '../hooks/useVerification'

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