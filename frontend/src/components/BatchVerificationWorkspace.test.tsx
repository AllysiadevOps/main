import React from 'react'
import { render, screen, fireEvent, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { describe, expect, it } from 'vitest'
import BatchVerificationWorkspace from './BatchVerificationWorkspace'

describe('BatchVerificationWorkspace UI Component', () => {
  it('renders idle workspace header and dropzone', () => {
    render(
      <BatchVerificationWorkspace
        apiBase="http://127.0.0.1:5050"
        contractId="CC123"
      />,
    )

    expect(screen.getByRole('heading', { level: 2, name: /Evidence Batch Verification Workspace/i })).toBeInTheDocument()
    expect(screen.getByText(/Drop evidence files or standalone JSON receipts/i)).toBeInTheDocument()
  })

  it('toggles pool settings configuration panel', () => {
    render(
      <BatchVerificationWorkspace
        apiBase="http://127.0.0.1:5050"
        contractId="CC123"
      />,
    )

    const toggleBtn = screen.getByRole('button', { name: /Pool Settings/i })
    fireEvent.click(toggleBtn)

    expect(screen.getByLabelText(/Concurrency \(Workers: 1-8\)/i)).toBeInTheDocument()
    expect(screen.getByLabelText(/Max Per-File Limit \(MB\)/i)).toBeInTheDocument()
  })

  it('handles adding files to workspace queue', async () => {
    render(
      <BatchVerificationWorkspace
        apiBase="http://127.0.0.1:5050"
        contractId="CC123"
      />,
    )

    const file1 = new File(['evidence sample content'], 'evidence1.mp4', { type: 'video/mp4' })
    const input = document.querySelector('input[type="file"]') as HTMLInputElement

    fireEvent.change(input, { target: { files: [file1] } })

    await waitFor(() => {
      expect(screen.getByRole('button', { name: /Verify Batch \(1\)/i })).toBeInTheDocument()
      expect(screen.getByText('evidence1.mp4')).toBeInTheDocument()
    })
  })

  // ─── Keyboard accessibility (issue #288) ───────────────────────────────────

  it('dropzone label is reachable via keyboard (tabIndex=0, role=button)', () => {
    render(
      <BatchVerificationWorkspace
        apiBase="http://127.0.0.1:5050"
        contractId="CC123"
      />,
    )

    const dropzone = screen.getByRole('button', {
      name: /Drop evidence files or standalone JSON receipts/i,
    })
    expect(dropzone).toHaveAttribute('tabindex', '0')
  })

  it('dropzone has an accessible aria-label', () => {
    render(
      <BatchVerificationWorkspace
        apiBase="http://127.0.0.1:5050"
        contractId="CC123"
      />,
    )

    const dropzone = screen.getByRole('button', {
      name: /Drop evidence files or standalone JSON receipts/i,
    })
    expect(dropzone).toHaveAttribute(
      'aria-label',
      'Drop evidence files or standalone JSON receipts. Press Enter or Space to open file picker',
    )
  })

  it('hidden file input has tabIndex=-1 so keyboard focus stays on the label', () => {
    render(
      <BatchVerificationWorkspace
        apiBase="http://127.0.0.1:5050"
        contractId="CC123"
      />,
    )

    // The actual <input type="file"> must be excluded from natural tab order
    const fileInput = document.querySelector('input[type="file"]') as HTMLInputElement
    expect(fileInput).not.toBeNull()
    expect(fileInput.tabIndex).toBe(-1)
  })

  it('pressing Enter on the dropzone label triggers file picker (click on hidden input)', async () => {
    const user = userEvent.setup()
    render(
      <BatchVerificationWorkspace
        apiBase="http://127.0.0.1:5050"
        contractId="CC123"
      />,
    )

    const dropzone = screen.getByRole('button', {
      name: /Drop evidence files or standalone JSON receipts/i,
    })
    // Spy on the hidden input's click so we can confirm keyboard activation
    const fileInput = document.querySelector('input[type="file"]') as HTMLInputElement
    let clicked = false
    fileInput.addEventListener('click', () => { clicked = true })

    await user.tab() // Tab into the dropzone
    // Fire Enter key directly on the label
    fireEvent.keyDown(dropzone, { key: 'Enter', code: 'Enter' })

    expect(clicked).toBe(true)
  })

  it('pressing Space on the dropzone label also triggers file picker', () => {
    render(
      <BatchVerificationWorkspace
        apiBase="http://127.0.0.1:5050"
        contractId="CC123"
      />,
    )

    const dropzone = screen.getByRole('button', {
      name: /Drop evidence files or standalone JSON receipts/i,
    })
    const fileInput = document.querySelector('input[type="file"]') as HTMLInputElement
    let clicked = false
    fileInput.addEventListener('click', () => { clicked = true })

    fireEvent.keyDown(dropzone, { key: ' ', code: 'Space' })

    expect(clicked).toBe(true)
  })

  it('keyboard activation is suppressed while a batch is running (aria-disabled)', async () => {
    render(
      <BatchVerificationWorkspace
        apiBase="http://127.0.0.1:5050"
        contractId="CC123"
      />,
    )

    // Queue a file and start the batch so isRunning becomes true
    const file1 = new File(['data'], 'clip.mp4', { type: 'video/mp4' })
    const input = document.querySelector('input[type="file"]') as HTMLInputElement
    fireEvent.change(input, { target: { files: [file1] } })

    await waitFor(() => screen.getByRole('button', { name: /Verify Batch \(1\)/i }))

    fireEvent.click(screen.getByRole('button', { name: /Verify Batch \(1\)/i }))

    // After start the dropzone should be aria-disabled
    await waitFor(() => {
      const dropzone = screen.getByRole('button', {
        name: /Drop evidence files or standalone JSON receipts/i,
      })
      expect(dropzone).toHaveAttribute('aria-disabled', 'true')
      expect(dropzone).toHaveAttribute('tabindex', '-1')
    })
  })
})
