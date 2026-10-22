import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { renderHook, waitFor } from '@testing-library/react'
import { getOpenDisputeCount } from '../stellar'
import { useOpenDisputeCount } from './useOpenDisputeCount'

vi.mock('../stellar', () => ({
  getOpenDisputeCount: vi.fn(),
}))

const mockedGetOpenDisputeCount = vi.mocked(getOpenDisputeCount)

const CONTRACT_ID = `C${'A'.repeat(55)}`
const PROOF_ID = 'd'.repeat(64)
const SOURCE = `G${'B'.repeat(55)}`

let warnSpy: ReturnType<typeof vi.spyOn>

beforeEach(() => {
  mockedGetOpenDisputeCount.mockReset()
  warnSpy = vi.spyOn(console, 'warn').mockImplementation(() => {})
})

afterEach(() => {
  warnSpy.mockRestore()
})

describe('useOpenDisputeCount', () => {
  it('returns the registry count for the proof', async () => {
    mockedGetOpenDisputeCount.mockResolvedValue(2)

    const { result } = renderHook(() =>
      useOpenDisputeCount({ proofId: PROOF_ID, sourceAddress: SOURCE, contractId: CONTRACT_ID }),
    )

    expect(result.current).toBeNull()
    await waitFor(() => expect(result.current).toBe(2))
    expect(mockedGetOpenDisputeCount).toHaveBeenCalledWith(CONTRACT_ID, PROOF_ID, SOURCE)
  })

  it('returns null and logs a scrubbed warning when the RPC read fails', async () => {
    mockedGetOpenDisputeCount.mockRejectedValue(new TypeError(`simulation failed for ${PROOF_ID}`))

    const { result } = renderHook(() =>
      useOpenDisputeCount({ proofId: PROOF_ID, contractId: CONTRACT_ID }),
    )

    await waitFor(() => expect(warnSpy).toHaveBeenCalled())
    expect(result.current).toBeNull()
    const logged = JSON.stringify(warnSpy.mock.calls)
    expect(logged).toContain('provenance.dispute_count_unavailable')
    expect(logged).toContain('TypeError')
    expect(logged).not.toContain(PROOF_ID)
  })

  it('returns null when the registry gives no usable answer', async () => {
    mockedGetOpenDisputeCount.mockResolvedValue(null)

    const { result } = renderHook(() =>
      useOpenDisputeCount({ proofId: PROOF_ID, contractId: CONTRACT_ID }),
    )

    await waitFor(() => expect(mockedGetOpenDisputeCount).toHaveBeenCalled())
    expect(result.current).toBeNull()
  })

  it('does not query without a proof id or contract id', () => {
    renderHook(() => useOpenDisputeCount({ proofId: null, contractId: CONTRACT_ID }))
    renderHook(() => useOpenDisputeCount({ proofId: PROOF_ID, contractId: '' }))

    expect(mockedGetOpenDisputeCount).not.toHaveBeenCalled()
  })

  it('drops a stale answer when the proof changes', async () => {
    mockedGetOpenDisputeCount.mockResolvedValueOnce(5).mockResolvedValueOnce(0)

    const { result, rerender } = renderHook(
      ({ proofId }) => useOpenDisputeCount({ proofId, contractId: CONTRACT_ID }),
      { initialProps: { proofId: PROOF_ID } },
    )
    await waitFor(() => expect(result.current).toBe(5))

    rerender({ proofId: 'e'.repeat(64) })
    expect(result.current).toBeNull()
    await waitFor(() => expect(result.current).toBe(0))
  })
})
