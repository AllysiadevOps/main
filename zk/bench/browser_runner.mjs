#!/usr/bin/env node
/**
 * Browser-equivalent (Node + bb.js) prove/verify timing harness.
 *
 * Emits a privacy-safe JSON summary on stdout. Never prints proof hex,
 * public-input hex, witnesses, or credential/nullifier secrets.
 *
 * Usage (from repo root, after `cd frontend && npm ci` and circuit build):
 *   node zk/bench/browser_runner.mjs
 *   node zk/bench/browser_runner.mjs --cold 1 --warm 2
 *   node zk/bench/browser_runner.mjs --mode main
 *
 * --mode selects which prover runtime the sample stands in for:
 *   worker  — the Web Worker path (default)
 *   main    — the non-worker fallback path (explicit limits enforced here so
 *             drift in the fallback bounds is caught by the bench, not by users)
 *
 * When ACIR artifacts are missing, exits 3 with a structured stderr signal
 * (same convention as the Python harness).
 */
import { readFile, access, stat } from 'node:fs/promises'
import { performance } from 'node:perf_hooks'
import { fileURLToPath } from 'node:url'
import { dirname, join } from 'node:path'
import os from 'node:os'
import process from 'node:process'

const ROOT = join(dirname(fileURLToPath(import.meta.url)), '..', '..')
const HELPER = join(ROOT, 'zk/noir/silent_witness_helper/target/silent_witness_helper.json')
const MAIN = join(ROOT, 'zk/noir/silent_witness/target/silent_witness.json')
const BENCH_LOCK = join(ROOT, 'zk/bench/bench.lock.json')

const PUBLIC_INPUTS_LEN = 160
const MIN_PROOF_BYTES = 64
const MAX_PROOF_BYTES = 65536
const textEncoder = new TextEncoder()

// Explicit non-worker fallback limits, kept in lockstep with
// frontend/src/workers/proofWorkerClient.ts and
// frontend/src/noirClient.ts. The bench enforces the same ceilings so a
// fixture cannot mask fallback-limit drift.
const FALLBACK_MAX_SECRET_BYTES = 256
const FALLBACK_MAX_CONCURRENCY = 1
const RUNTIME_MODES = ['worker', 'main']
function signal(event, fields = {}) {
  console.error(JSON.stringify({ event, ...fields }))
}

function parseArgs(argv) {
  const out = { cold: 1, warm: 2, discard: 1, timeoutMs: 180_000, mode: 'worker', threads: FALLBACK_MAX_CONCURRENCY }
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i]
    if (a === '--cold') out.cold = Number(argv[++i])
    else if (a === '--warm') out.warm = Number(argv[++i])
    else if (a === '--discard') out.discard = Number(argv[++i])
    else if (a === '--timeout-ms') out.timeoutMs = Number(argv[++i])
    else if (a === '--mode') out.mode = argv[++i]
    else if (a === '--threads') out.threads = Number(argv[++i])
    else if (a === '--help') out.help = true
  }
  return out
}

function percentile(sorted, pct) {
  if (!sorted.length) throw new Error('empty samples')
  const rank = Math.max(1, Math.round((pct / 100) * sorted.length))
  return sorted[rank - 1]
}

function summarize(samples) {
  const ordered = [...samples].sort((a, b) => a - b)
  return {
    p50: percentile(ordered, 50),
    p95: percentile(ordered, 95),
    p99: percentile(ordered, 99),
    min: ordered[0],
    max: ordered.at(-1),
    mean: ordered.reduce((a, b) => a + b, 0) / ordered.length,
    count: ordered.length,
  }
}

async function loadBenchLimits() {
  const raw = JSON.parse(await readFile(BENCH_LOCK, 'utf8'))
  if (raw.format !== 'harpocrates.zk-bench-lock' || raw.version !== 1) {
    const err = new Error('unsupported bench lock')
    err.code = 'unsupported_bench_lock'
    throw err
  }
  return raw.limits
}

function reject(code) {
  const err = new Error(code)
  err.code = code
  throw err
}

async function readJsonBounded(path, maxBytes) {
  const info = await stat(path)
  if (info.size > maxBytes) reject('memory_limit_exceeded')
  const text = await readFile(path, 'utf8')
  const rawBytes = Buffer.byteLength(text, 'utf8')
  if (rawBytes > maxBytes) reject('memory_limit_exceeded')
  return { value: JSON.parse(text), rawBytes }
}

function boundedByteLength(value, limit, seen = new WeakSet()) {
  if (value == null) return 0
  if (typeof value === 'string') return textEncoder.encode(value).byteLength
  if (typeof value === 'number') return Number.isFinite(value) ? 8 : null
  if (typeof value === 'bigint') return 32
  if (typeof value === 'boolean') return 1
  if (value instanceof ArrayBuffer) return value.byteLength
  if (ArrayBuffer.isView(value)) return value.byteLength
  if (typeof value !== 'object') return null
  if (seen.has(value)) return 0
  seen.add(value)

  let total = 0
  const add = (next) => {
    if (next === null) return false
    total += next
    return total <= limit
  }
  if (value instanceof Map) {
    for (const [key, item] of value.entries()) {
      if (!add(boundedByteLength(key, limit - total, seen))) return null
      if (!add(boundedByteLength(item, limit - total, seen))) return null
    }
    return total
  }
  if (value instanceof Set || Array.isArray(value)) {
    for (const item of value.values()) {
      if (!add(boundedByteLength(item, limit - total, seen))) return null
    }
    return total
  }
  for (const [key, item] of Object.entries(value)) {
    if (!add(textEncoder.encode(key).byteLength)) return null
    if (!add(boundedByteLength(item, limit - total, seen))) return null
  }
  return total
}

function assertMemoryBudget({ artifactBytes = 0, witnessBytes = 0, proofBytes = 0, publicInputBytes = 0 }, limits) {
  if (artifactBytes > limits.max_witness_bytes) reject('memory_limit_exceeded')
  if (witnessBytes == null || witnessBytes > limits.max_witness_bytes) reject('memory_limit_exceeded')
  if (proofBytes > limits.max_proof_bytes) reject('memory_limit_exceeded')
  if (publicInputBytes > limits.max_public_input_bytes) reject('memory_limit_exceeded')
  const runtimeCap =
    limits.max_witness_bytes +
    limits.max_proof_bytes +
    limits.max_public_input_bytes +
    artifactBytes
  if (artifactBytes + witnessBytes + proofBytes + publicInputBytes > runtimeCap) {
    reject('memory_limit_exceeded')
  }
}

async function exists(path) {
  try {
    await access(path)
    return true
  } catch {
    return false
  }
}

async function withTimeout(promise, ms) {
  let timer
  try {
    return await Promise.race([
      promise,
      new Promise((_, reject) => {
        timer = setTimeout(() => reject(Object.assign(new Error('timeout'), { code: 'dependency-failure' })), ms)
      }),
    ])
  } finally {
    clearTimeout(timer)
  }
}

async function measureOnce({
  Noir,
  UltraHonkBackend,
  helperCircuit,
  mainCircuit,
  artifactBytes,
  limits,
  cold,
}) {
  const videoHash = '1111111111111111111111111111111122222222222222222222222222222222'
  // Synthetic fixture only — never real media or production secrets.
  const baseInputs = {
    credential_secret: '123456789',
    nullifier_secret: '987654321',
    video_hash_hi: BigInt(`0x${videoHash.slice(0, 32)}`).toString(10),
    video_hash_lo: BigInt(`0x${videoHash.slice(32)}`).toString(10),
  }
  // Enforce the explicit non-worker fallback bound on secret sizes.
  const credBytes = new TextEncoder().encode(baseInputs.credential_secret).length
  const nullBytes = new TextEncoder().encode(baseInputs.nullifier_secret).length
  if (credBytes > FALLBACK_MAX_SECRET_BYTES || nullBytes > FALLBACK_MAX_SECRET_BYTES) {
    const err = new Error('secret input exceeds explicit fallback limit')
    err.code = 'fallback_limit_exceeded'
    throw err
  }

  const t0 = performance.now()
  const helperResult = await new Noir(helperCircuit).execute(baseInputs)
  const [credentialRoot, nullifier] = helperResult.returnValue
  const mainInputs = {
    ...baseInputs,
    credential_root: credentialRoot,
    nullifier,
  }
  const { witness } = await new Noir(mainCircuit).execute(mainInputs)
  const witnessBytes = boundedByteLength(witness, limits.max_witness_bytes + 1)
  assertMemoryBudget({ artifactBytes, witnessBytes }, limits)
  const backend = new UltraHonkBackend(mainCircuit.bytecode)
  try {
    const proofData = await backend.generateProof(witness, { keccak: true })
    const proveMs = performance.now() - t0
    const proofBytes = proofData.proof.length
    if (proofBytes < MIN_PROOF_BYTES || proofBytes > MAX_PROOF_BYTES) {
      const err = new Error('proof size out of bounds')
      err.code = proofBytes > MAX_PROOF_BYTES ? 'oversized' : 'malformed'
      throw err
    }
    assertMemoryBudget({
      artifactBytes,
      witnessBytes,
      proofBytes,
      publicInputBytes: PUBLIC_INPUTS_LEN,
    }, limits)
    const v0 = performance.now()
    const verified = await backend.verifyProof(proofData, { keccak: true })
    const verifyMs = performance.now() - v0
    if (!verified) {
      const err = new Error('verification failed')
      err.code = 'malformed'
      throw err
    }
    return {
      prove_ms: proveMs,
      verify_ms: verifyMs,
      proof_bytes: proofBytes,
      public_input_bytes: PUBLIC_INPUTS_LEN,
      witness_bytes: witnessBytes,
      peak_rss_bytes: process.memoryUsage().rss,
      cold,
    }
  } finally {
    await backend.destroy()
  }
}

async function main() {
  const args = parseArgs(process.argv.slice(2))
  if (args.help) {
    console.log('browser_runner.mjs [--cold N] [--warm N] [--discard N] [--timeout-ms MS] [--mode worker|main] [--threads N]')
    process.exit(0)
  }

  if (!RUNTIME_MODES.includes(args.mode)) {
    signal('bench.fatal', {
      code: 'unknown_mode',
      detail: `--mode must be one of: ${RUNTIME_MODES.join(', ')}`,
    })
    process.exit(3)
  }

  if (args.mode === 'main' && args.timeoutMs < 1) {
    signal('bench.fatal', { code: 'invalid_timeout', detail: '--timeout-ms must be positive' })
    process.exit(3)
  }

  if (!(await exists(MAIN)) || !(await exists(HELPER))) {
    signal('bench.fatal', { code: 'dependency-failure', detail: 'compile circuits first' })
    process.exit(3)
  }
  const limits = await loadBenchLimits()

  // Dynamic import so the Python unit CI path does not require node_modules.
  let Noir
  let UltraHonkBackend
  try {
    ;({ Noir } = await import('@noir-lang/noir_js'))
    ;({ UltraHonkBackend } = await import('@aztec/bb.js'))
  } catch {
    // Resolve from frontend/node_modules when run from repo root.
    const frontendModules = join(ROOT, 'frontend/node_modules')
    ;({ Noir } = await import(join(frontendModules, '@noir-lang/noir_js/lib/esm/index.js')))
    ;({ UltraHonkBackend } = await import(join(frontendModules, '@aztec/bb.js/dest/node/index.js')))
  }

  const helperArtifact = await readJsonBounded(HELPER, limits.max_witness_bytes)
  const mainArtifact = await readJsonBounded(MAIN, limits.max_witness_bytes)
  const helperCircuit = helperArtifact.value
  const mainCircuit = mainArtifact.value
  const artifactBytes = helperArtifact.rawBytes + mainArtifact.rawBytes
  assertMemoryBudget({ artifactBytes }, limits)

  signal('bench.start', {
    target: 'browser',
    fixture_id: 'silent_witness.synthetic.v1',
    mode: args.mode,
    threads: args.threads,
  })

  const proveSamples = []
  const verifySamples = []
  let sizes = null
  let memory = null

  const runSample = async (cold) => {
    const sample = await withTimeout(
      measureOnce({
        Noir,
        UltraHonkBackend,
        helperCircuit,
        mainCircuit,
        artifactBytes,
        limits,
        cold,
      }),
      args.timeoutMs,
    )
    proveSamples.push(sample.prove_ms)
    verifySamples.push(sample.verify_ms)
    sizes = {
      proof_bytes: sample.proof_bytes,
      public_input_bytes: sample.public_input_bytes,
      witness_bytes: sample.witness_bytes,
    }
    memory = { peak_rss_bytes: sample.peak_rss_bytes }
    signal('bench.sample', {
      target: 'browser',
      mode: args.mode,
      threads: args.threads,
      state: 'ok',
      elapsed_ms: sample.prove_ms,
    })
  }

  try {
    for (let i = 0; i < args.cold; i++) await runSample(true)
    for (let i = 0; i < args.discard; i++) await runSample(false)
    // Discard warm-up samples from aggregates by resetting after discard.
    proveSamples.length = args.cold
    verifySamples.length = args.cold
    for (let i = 0; i < args.warm; i++) await runSample(false)
  } catch (err) {
    const code = err?.code || 'fatal'
    signal('bench.fatal', { code, reason: 'browser_runner_failed' })
    process.exit(code === 'timeout' ? 3 : 3)
  }

  const report = {
    format: 'harpocrates.zk-bench',
    version: 1,
    target: 'browser',
    fixture_id: 'silent_witness.synthetic.v1',
    circuit: 'silent_witness',
    // The prover runtime this run stands in for: 'worker' or 'main' (fallback).
    mode: args.mode,
    runtime: {
      os: os.platform(),
      arch: os.arch(),
      node_version: process.version,
      cpu_count: os.cpus()?.length ?? 0,
      ci: Boolean(process.env.CI || process.env.GITHUB_ACTIONS),
      threading: { max_concurrency: args.threads, requested_threads: args.threads },
    },
    phases: [
      {
        phase: 'prove',
        percentiles: summarize(proveSamples),
        samples_ms: proveSamples,
        sizes,
        memory,
      },
      {
        phase: 'verify',
        percentiles: summarize(verifySamples),
        samples_ms: verifySamples,
        sizes,
        memory,
      },
    ],
    outcome: 'ok',
    generated_at_unix: Math.floor(Date.now() / 1000),
  }

  signal('bench.done', { target: 'browser', outcome: 'ok' })
  console.log(JSON.stringify(report))
}

main().catch((err) => {
  signal('bench.fatal', { code: 'unhandled', reason: 'browser_runner_crashed' })
  process.exit(3)
})
