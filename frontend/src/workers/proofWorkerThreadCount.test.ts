import { describe, expect, it, vi, afterEach, beforeEach } from 'vitest'
import { resolveThreadCount } from './threadCount'

const originalCrossOriginIsolated = Object.getOwnPropertyDescriptor(
  typeof globalThis !== 'undefined' ? globalThis : {},
  'crossOriginIsolated',
)
const originalHardwareConcurrency = Object.getOwnPropertyDescriptor(navigator, 'hardwareConcurrency')

function setCrossOriginIsolated(value: boolean | undefined) {
  Object.defineProperty(self, 'crossOriginIsolated', {
    configurable: true,
    enumerable: true,
    get: () => value,
  })
}

function setHardwareConcurrency(value: number) {
  Object.defineProperty(navigator, 'hardwareConcurrency', {
    configurable: true,
    enumerable: true,
    get: () => value,
  })
}

describe('resolveThreadCount', () => {
  beforeEach(() => {
    vi.restoreAllMocks()
    setCrossOriginIsolated(undefined)
    setHardwareConcurrency(4)
  })

  afterEach(() => {
    vi.restoreAllMocks()
    // Restore original descriptors
    if (originalCrossOriginIsolated) {
      Object.defineProperty(self, 'crossOriginIsolated', originalCrossOriginIsolated)
    } else {
      delete (self as { crossOriginIsolated?: boolean }).crossOriginIsolated
    }
    if (originalHardwareConcurrency) {
      Object.defineProperty(navigator, 'hardwareConcurrency', originalHardwareConcurrency)
    }
  })

  it('returns 1 when crossOriginIsolated is not true (single-threaded fallback)', () => {
    setCrossOriginIsolated(false)
    expect(resolveThreadCount()).toBe(1)

    setCrossOriginIsolated(undefined)
    expect(resolveThreadCount()).toBe(1)
  })

  it('returns hardwareConcurrency when isolated (capped at 8)', () => {
    setCrossOriginIsolated(true)
    setHardwareConcurrency(8)
    expect(resolveThreadCount()).toBe(8)
  })

  it('clamps hardwareConcurrency above 8 down to 8', () => {
    setCrossOriginIsolated(true)
    setHardwareConcurrency(16)
    expect(resolveThreadCount()).toBe(8)
  })

  it('clamps hardwareConcurrency of 0 up to 1', () => {
    setCrossOriginIsolated(true)
    setHardwareConcurrency(0)
    expect(resolveThreadCount()).toBe(1)
  })

  it('returns 1 when hardwareConcurrency is 1', () => {
    setCrossOriginIsolated(true)
    setHardwareConcurrency(1)
    expect(resolveThreadCount()).toBe(1)
  })

  it('returns 4 when isolated with 4 cores', () => {
    setCrossOriginIsolated(true)
    setHardwareConcurrency(4)
    expect(resolveThreadCount()).toBe(4)
  })
})
