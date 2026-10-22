import React from 'react'
import { act, fireEvent, render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { beforeEach, describe, expect, it, vi } from 'vitest'
import App from './App'
import BatchVerificationWorkspace from './components/BatchVerificationWorkspace'
import type { BatchItemResult, BatchOutcome, BatchProgress, BatchSummary } from './batchVerifier'
import {
  MANUAL_ONLY_RULES,
  expectNoA11yViolations,
  runAxe,
} from './test/axeA11y'

vi.mock('./components/EvilEye', () => ({
  default: () => <div data-testid="evil-eye" />,
}))

// The workspace only reaches its in-progress and completed states through
// BatchVerifier progress callbacks, so the suite doubles that module and
// scripts the callbacks instead of hashing media or calling the registry API.
const batchDouble = vi.hoisted(() => ({
  mode: 'idle' as 'idle' | 'in-progress' | 'completed',
  releaseBatch: null as null | (() => void),
}))

vi.mock('./batchVerifier', async (importOriginal) => {
  const actual = await importOriginal<typeof import('./batchVerifier')>()

  const progressOf = (overrides: Partial<BatchProgress>): BatchProgress => ({
    totalFiles: 1,
    completedFiles: 0,
    processedBytes: 0,
    totalBytes: 0,
    activeCount: 0,
    isCancelled: false,
    isDone: false,
    ...overrides,
  })

  const itemOf = (file: File, index: number, status: BatchOutcome): BatchItemResult => ({
    id: `axe-item-${index}`,
    file,
    fileName: file.name,
    fileSizeBytes: file.size,
    status,
    videoHash: status === 'error' ? null : '0123456789abcdef0123456789abcdef',
    metadataHash: null,
    sourceHash: null,
    tier: null,
    chainStatus: null,
    message: `Scripted ${status} outcome.`,
    events: [],
    chainProof: null,
    duplicateOf: status === 'duplicate' ? 'first-clip.mp4' : null,
    manifest: null,
    durationMs: 12,
    failureReason: status === 'error' ? 'Scripted verification failure.' : null,
  })

  const summaryOf = (items: BatchItemResult[], totalBytes: number): BatchSummary => ({
    totalFiles: items.length,
    confirmed: items.filter((i) => i.status === 'confirmed').length,
    revoked: items.filter((i) => i.status === 'revoked').length,
    unconfirmed: items.filter((i) => i.status === 'metadata-only').length,
    manifests: items.filter((i) => i.status === 'manifest-valid').length,
    duplicates: items.filter((i) => i.status === 'duplicate').length,
    errors: items.filter((i) => i.status === 'error').length,
    cancelled: 0,
    totalBytes,
    durationMs: 120,
  })

  class DoubledBatchVerifier {
    updateConfig(): void {}

    cancel(): void {}

    async runBatch(
      files: File[],
      onProgress?: (progress: BatchProgress, items: BatchItemResult[]) => void,
    ): Promise<{ items: BatchItemResult[]; summary: BatchSummary }> {
      const totalBytes = files.reduce((acc, file) => acc + file.size, 0)

      if (batchDouble.mode === 'in-progress') {
        onProgress?.(
          progressOf({
            totalFiles: files.length,
            completedFiles: 1,
            processedBytes: files[0].size,
            totalBytes,
            activeCount: files.length - 1,
          }),
          files.map((file, index) => itemOf(file, index, index === 0 ? 'confirmed' : 'processing')),
        )
        await new Promise<void>((resolve) => {
          batchDouble.releaseBatch = resolve
        })
      }

      const statuses: BatchOutcome[] = [
        'confirmed',
        'revoked',
        'metadata-only',
        'duplicate',
        'error',
        'manifest-valid',
      ]
      const items = files.map((file, index) =>
        itemOf(file, index, statuses[index % statuses.length]),
      )
      onProgress?.(
        progressOf({
          totalFiles: files.length,
          completedFiles: files.length,
          processedBytes: totalBytes,
          totalBytes,
          isDone: true,
        }),
        items,
      )
      return { items, summary: summaryOf(items, totalBytes) }
    }
  }

  return { ...actual, BatchVerifier: DoubledBatchVerifier }
})

const kibibytes = (size: number) => new Uint8Array(size * 1024)

async function renderBatchWorkspace(mode: 'idle' | 'in-progress' | 'completed', files: File[]) {
  batchDouble.mode = mode
  batchDouble.releaseBatch = null
  const utils = render(
    <BatchVerificationWorkspace apiBase="http://127.0.0.1:5050" contractId="CTESTID" wallet="GTEST" />,
  )

  if (mode === 'idle') return utils

  fireEvent.change(utils.container.querySelector('input[type="file"]') as HTMLInputElement, {
    target: { files },
  })
  const verifyButton = await waitFor(() =>
    screen.getByRole('button', { name: new RegExp(`Verify Batch \\(${files.length}\\)`, 'i') }),
  )
  fireEvent.click(verifyButton)

  const progressLabel =
    mode === 'in-progress' ? `Processing (1/${files.length})` : 'Batch Finished'
  await waitFor(() => expect(screen.getByText(progressLabel)).toBeInTheDocument())

  return utils
}

const brokenPage = () => {
  const root = document.createElement('div')
  document.body.appendChild(root)
  root.innerHTML = `
      <button><span aria-hidden="true">icon</span></button>
      <a href="/"><span aria-hidden="true">icon</span></a>
      <img src="fixture.png" />
      <input type="text" />
      <div role="img">graphic without alternative text</div>
    `
  return root
}

async function violationsFor(root: HTMLElement) {
  const results = await runAxe(root)
  return results.violations.map((v) => v.id)
}

describe('a11y.axe — WCAG 2.2 AA automated checks', () => {
  beforeEach(() => {
    vi.restoreAllMocks()
    batchDouble.mode = 'idle'
    batchDouble.releaseBatch = null
    Object.defineProperty(window, 'scrollTo', {
      configurable: true,
      value: vi.fn(),
    })
    window.history.replaceState(null, '', '/')
  })

  // ── Positive: every rendered view must be axe-clean ─────────────────────────

  it('landing view has no WCAG AA violations', async () => {
    const { container } = render(<App />)
    expectNoA11yViolations(await runAxe(container), 'landing view')
  })

  it('evidence studio (silent tier with secret inputs) has no WCAG AA violations', async () => {
    const user = userEvent.setup()
    const { container } = render(<App />)
    await user.click(screen.getByRole('button', { name: /begin evidence flow/i }))

    expect(screen.getByLabelText(/credential seed/i)).toBeInTheDocument()
    expect(screen.getByLabelText(/nullifier seed/i)).toBeInTheDocument()

    expectNoA11yViolations(await runAxe(container), 'evidence studio (silent tier)')
  })

  it('evidence studio (source tier without secret inputs) has no WCAG AA violations', async () => {
    const user = userEvent.setup()
    const { container } = render(<App />)
    await user.click(screen.getByRole('button', { name: /begin evidence flow/i }))
    await user.click(screen.getByRole('button', { name: /consistent source/i }))

    expect(screen.queryByLabelText(/credential seed/i)).not.toBeInTheDocument()
    expectNoA11yViolations(await runAxe(container), 'evidence studio (source tier)')
  })

  it('verify view has no WCAG AA violations', async () => {
    const user = userEvent.setup()
    const { container } = render(<App />)
    await user.click(screen.getByRole('button', { name: /^verify$/i }))

    expect(screen.getByLabelText(/drop or choose a received video/i)).toBeInTheDocument()
    expectNoA11yViolations(await runAxe(container), 'verify view')
  })

  it('batch verification workspace has no WCAG AA violations', async () => {
    const user = userEvent.setup()
    const { container } = render(<App />)
    await user.click(screen.getByRole('button', { name: /batch workspace/i }))

    expectNoA11yViolations(await runAxe(container), 'batch workspace view')
  })

  it('batch workspace (idle) has no WCAG AA violations', async () => {
    const { container } = await renderBatchWorkspace('idle', [])

    expectNoA11yViolations(await runAxe(container), 'batch workspace (idle)')
  })

  it('batch workspace (in progress) has no WCAG AA violations', async () => {
    const { container } = await renderBatchWorkspace('in-progress', [
      new File([kibibytes(2)], 'first-clip.mp4', { type: 'video/mp4' }),
      new File([kibibytes(3)], 'second-clip.mp4', { type: 'video/mp4' }),
      new File([kibibytes(4)], 'third-clip.mp4', { type: 'video/mp4' }),
    ])

    expectNoA11yViolations(await runAxe(container), 'batch workspace (in progress)')

    // Let the scripted batch finish so no state update lands after cleanup.
    await act(async () => {
      batchDouble.releaseBatch?.()
      await new Promise((resolve) => setTimeout(resolve, 0))
    })
  })

  it('batch workspace (completed) has no WCAG AA violations', async () => {
    const { container } = await renderBatchWorkspace('completed', [
      new File([kibibytes(2)], 'first-clip.mp4', { type: 'video/mp4' }),
      new File([kibibytes(3)], 'second-clip.mov', { type: 'video/quicktime' }),
      new File([kibibytes(4)], 'third-clip.webm', { type: 'video/webm' }),
      new File([kibibytes(1)], 'fourth-clip.mp4', { type: 'video/mp4' }),
      new File([kibibytes(1)], 'broken-clip.mp4', { type: 'video/mp4' }),
      new File([kibibytes(1)], 'manifest.json', { type: 'application/json' }),
    ])

    expectNoA11yViolations(await runAxe(container), 'batch workspace (completed)')
  })

  // ── Negative: the harness must still flag real defects ─────────────────────

  it('flags the negative fixture the same way a browser reporter would', async () => {
    const root = brokenPage()
    try {
      const ids = await violationsFor(root)
      expect(ids).toEqual(
        expect.arrayContaining(['button-name', 'link-name', 'image-alt', 'label', 'role-img-alt']),
      )
    } finally {
      root.remove()
    }
  })

  it('regression: keeps the accessible workflow diagram labelling', async () => {
    const { container } = render(<App />)
    const svg = container.querySelector('svg[role="img"]')
    expect(svg).not.toBeNull()
    expect(svg).toHaveAttribute('aria-labelledby')
    const titleId = svg?.getAttribute('aria-labelledby')
    expect(container.querySelector(`#${titleId}`)).toHaveTextContent(/harpocrates protocol workflow/i)
  })

  // ── Boundary: an empty tree is clean and incomplete rules are disciplined ──

  it('reports no violations for an empty tree', async () => {
    const root = document.createElement('div')
    document.body.appendChild(root)
    try {
      const results = await runAxe(root)
      expect(results.violations).toHaveLength(0)
      expect(results.incomplete).toHaveLength(0)
    } finally {
      root.remove()
    }
  })

  it('accepts only the documented jsdom-limited color-contrast rule as incomplete', async () => {
    const root = document.createElement('div')
    document.body.appendChild(root)
    root.innerHTML = `<p style="color:#333;background:#fff">plain text</p><input type="text" aria-label="named field" />`
    try {
      const results = await runAxe(root)
      expect(results.violations).toHaveLength(0)
      const incompleteIds = results.incomplete.map((r) => r.id)
      expect(incompleteIds).toContain('color-contrast')
      expect(incompleteIds.filter((id) => !(id in MANUAL_ONLY_RULES))).toEqual([])
    } finally {
      root.remove()
    }
  })

  it('fail-closed: rejects an incomplete rule that is not documented as manual-only', () => {
    const fakeResults = {
      violations: [] as never[],
      incomplete: [{ id: 'totally-new-layout-rule', help: '…', nodes: [] } as never],
    } as unknown as Parameters<typeof expectNoA11yViolations>[0]

    expect(() => expectNoA11yViolations(fakeResults, 'test')).toThrow(
      /totally-new-layout-rule/,
    )
  })
})