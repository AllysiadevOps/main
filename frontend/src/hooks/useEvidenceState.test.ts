import { act, renderHook } from '@testing-library/react'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { CheckpointStorage } from '../checkpointStorage'
import { useEvidenceState } from './useEvidenceState'

describe('useEvidenceState', () => {
  beforeEach(() => {
    vi.restoreAllMocks()
    localStorage.clear()
  })

  afterEach(() => {
    vi.restoreAllMocks()
    localStorage.clear()
  })

  it('initializes with default idle state and checkpoint status', () => {
    const { result } = renderHook(() => useEvidenceState())

    expect(result.current.state.stage).toBe('idle')
    expect(result.current.state.tier).toBe('silent')
    expect(result.current.hasCheckpoint).toBe(false)
  })

  it('updates state through a full happy-path sequence via send', () => {
    const { result } = renderHook(() => useEvidenceState())

    act(() => {
      result.current.send({
        type: 'START',
        tier: 'silent',
        fileName: 'record.mp4',
      })
    })
    expect(result.current.state.stage).toBe('hashing')
    expect(result.current.state.fileName).toBe('record.mp4')

    act(() => {
      result.current.send({
        type: 'HASHED',
        sourceHash: 'source-hash-123',
      })
    })
    expect(result.current.state.stage).toBe('embedding')
    expect(result.current.state.sourceHash).toBe('source-hash-123')

    act(() => {
      result.current.send({
        type: 'EMBEDDED',
        videoHash: 'video-hash-123',
        metadataHash: 'meta-hash-123',
        proofId: 'proof-id-123',
        timestamp: '2026-10-18T12:00:00Z',
      })
    })
    expect(result.current.state.stage).toBe('proving')

    act(() => {
      result.current.send({
        type: 'PROVED',
        silentWitness: {
          credentialRoot: 'root-1',
          nullifier: 'nullifier-1',
          proof: 'proof-data',
          publicInputs: 'pub-inputs',
          proofBytes: 64,
          publicInputBytes: 32,
        },
      })
    })
    expect(result.current.state.stage).toBe('ready')

    act(() => {
      result.current.send({ type: 'REGISTERING' })
    })
    expect(result.current.state.stage).toBe('registering')

    act(() => {
      result.current.send({
        type: 'REGISTERED',
        txHash: 'tx-hash-123',
      })
    })
    expect(result.current.state.stage).toBe('registered')
    expect(result.current.state.txHash).toBe('tx-hash-123')
    expect(result.current.state.txStatus).toBe('confirmed')
  })

  it('ignores invalid transitions and preserves the current state', () => {
    const { result } = renderHook(() => useEvidenceState())

    const initialState = result.current.state

    // REGISTERING is not allowed from idle stage
    act(() => {
      result.current.send({ type: 'REGISTERING' })
    })

    expect(result.current.state).toBe(initialState)
    expect(result.current.state.stage).toBe('idle')

    // Transition to hashing
    act(() => {
      result.current.send({
        type: 'START',
        tier: 'source',
        fileName: 'record.mp4',
      })
    })
    expect(result.current.state.stage).toBe('hashing')
    const hashingState = result.current.state

    // REGISTERED is invalid while hashing
    act(() => {
      result.current.send({
        type: 'REGISTERED',
        txHash: 'invalid-tx',
      })
    })

    expect(result.current.state).toBe(hashingState)
    expect(result.current.state.stage).toBe('hashing')
  })

  it('resets state back to idle stage upon RESET event', () => {
    const { result } = renderHook(() => useEvidenceState())

    act(() => {
      result.current.send({
        type: 'START',
        tier: 'source',
        fileName: 'record.mp4',
      })
    })
    expect(result.current.state.stage).toBe('hashing')

    act(() => {
      result.current.send({ type: 'RESET' })
    })

    expect(result.current.state.stage).toBe('idle')
    expect(result.current.state.fileName).toBeUndefined()
  })

  it('wires setPassword to the underlying state machine', () => {
    const { result } = renderHook(() => useEvidenceState())

    // Ensure setPassword does not throw and executes successfully
    act(() => {
      result.current.setPassword('secret-passphrase')
    })
  })

  it('loads checkpoint and clears checkpoint via storage helpers', async () => {
    const mockState = {
      stage: 'ready' as const,
      tier: 'silent' as const,
      updatedAt: Date.now(),
    }
    vi.spyOn(CheckpointStorage, 'hasCheckpoint').mockReturnValue(true)
    vi.spyOn(CheckpointStorage, 'load').mockResolvedValue(mockState)
    const clearSpy = vi.spyOn(CheckpointStorage, 'clear').mockImplementation(() => {})

    const { result } = renderHook(() => useEvidenceState())
    expect(result.current.hasCheckpoint).toBe(true)

    let loadResult = false
    await act(async () => {
      loadResult = await result.current.loadCheckpoint('pass123')
    })

    expect(loadResult).toBe(true)
    expect(result.current.state.stage).toBe('ready')
    expect(result.current.hasCheckpoint).toBe(false)

    act(() => {
      result.current.clearCheckpoint()
    })

    expect(clearSpy).toHaveBeenCalled()
    expect(result.current.hasCheckpoint).toBe(false)
  })
})
