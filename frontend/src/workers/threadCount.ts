/**
 * Resolve the bb.js WASM thread count based on cross-origin isolation.
 *
 * When `crossOriginIsolated` is true, SharedArrayBuffer is available and
 * multithreaded proving can use `navigator.hardwareConcurrency` threads
 * (clamped to 1–8). When not isolated, the prover falls back to a single
 * thread so non-isolated environments continue to work.
 */
export function resolveThreadCount(): number {
  if (typeof self.crossOriginIsolated === 'boolean' && self.crossOriginIsolated) {
    const hwc = typeof navigator !== 'undefined' ? navigator.hardwareConcurrency : 0
    return Math.max(1, Math.min(hwc || 1, 8))
  }
  return 1
}
