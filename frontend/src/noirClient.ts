import { UltraHonkBackend } from '@aztec/bb.js'
import { Noir } from '@noir-lang/noir_js'
import type { CompiledCircuit } from '@noir-lang/types'
import { encodeFieldToBytes32Hex, encodePublicInputs, EXPECTED_CIRCUIT_VERSION } from './verifierInputs'
import { assertArtifactPair, assertProofOutput, CircuitInputError, prepareSilentWitnessInputs, PUBLIC_FRAMES } from './circuitInputSchema'
import type { SilentWitnessInput } from './circuitInputSchema'
import {
  assertProofWorkerMemoryBudget,
  byteLengthOfProofWorkerValue,
  readBoundedCircuitArtifact,
} from './proofWorkerMemory'

const MAX_AGGREGATION_SIZE = 8
const AGGREGATED_PUBLIC_INPUT_BYTES = 32 + (MAX_AGGREGATION_SIZE * 128)

import {
  checkAggregationBatchSize,
  encodeFieldToBytes32Hex,
  encodePublicInputs,
  MAX_AGGREGATION_SIZE,
  MIN_AGGREGATION_SIZE,
} from './verifierInputs'

export type SilentWitnessProof = {
  credentialRoot: string
  nullifier: string
  /** 32-byte hex domain tag, present only when the circuit exposes one. */
  domainTag?: string
  proof: string
  /** Hex-encoded public frame: four published-browser, five unscoped, or eight scoped fields. */
  publicInputs: string
  proofBytes: number
  publicInputBytes: number
}

export type AggregatedProof = {
  protocol: string
  version: number
  type: string
  batchId: string
  batchSize: number
  maxBatchSize: number
  videoHashes: string[]
  proof: string
  publicInputs: string
  proofBytes: number
  publicInputBytes: number
}

type GenerateAggregatedProofInput = {
  videoHashes: string[]
  credentialSecret: string
  nullifierSecret: string
}

type LoadedCircuit = {
  circuit: CompiledCircuit
  rawBytes: number
}

let helperCircuitPromise: Promise<LoadedCircuit> | null = null
let mainCircuitPromise: Promise<LoadedCircuit> | null = null
let aggregatorCircuitPromise: Promise<LoadedCircuit> | null = null
let aggregatorHelperCircuitPromise: Promise<LoadedCircuit> | null = null

async function loadCircuit(path: string): Promise<CompiledCircuit> {
  const response = await fetch(path, { cache: 'no-store' })
  if (!response.ok) {
    throw new Error(`Unable to load Noir circuit artifact: ${path}`)
  }
  return (await response.json()) as CompiledCircuit
}

async function loadHelperCircuit(): Promise<CompiledCircuit> {
  helperCircuitPromise ??= loadCircuit('/noir/silent_witness_helper.json')
  return helperCircuitPromise
}

async function loadMainCircuit(): Promise<CompiledCircuit> {
  mainCircuitPromise ??= loadCircuit('/noir/silent_witness.json')
  return mainCircuitPromise
}

async function loadAggregatorCircuit(): Promise<CompiledCircuit> {
  aggregatorCircuitPromise ??= loadCircuit('/noir/silent_witness_aggregator.json')
  return aggregatorCircuitPromise
}

async function loadAggregatorHelperCircuit(): Promise<CompiledCircuit> {
  aggregatorHelperCircuitPromise ??= loadCircuit('/noir/silent_witness_aggregator_helper.json')
  return aggregatorHelperCircuitPromise
}

function bytesToHex(bytes: Uint8Array): string {
  return Array.from(bytes, (byte) => byte.toString(16).padStart(2, '0')).join('')
}

/**
 * Generate a Silent Witness Noir/UltraHonk proof.
 *
 * The published browser helper computes (credential_root, nullifier). Newer
 * helper artifacts may also return a domain_tag that binds the proof to the
 * protocol and network. The browser never fabricates a missing domain tag.
 *
 * @param threadCount – number of WASM threads to use. When `crossOriginIsolated`
 *   is true the caller may pass `navigator.hardwareConcurrency`; otherwise pass 1
 *   (single-threaded fallback). Defaults to 1.
 */
export async function generateSilentWitnessProof(
  input: SilentWitnessInput,
  options?: { threadCount?: number },
): Promise<SilentWitnessProof> {
  const threadCount = options?.threadCount ?? 1
  const prepared = prepareSilentWitnessInputs(input)
  try {
    const [helperCircuit, mainCircuit] = await Promise.all([loadHelperCircuit(), loadMainCircuit()])
    const artifactBytes = helperCircuit.rawBytes + mainCircuit.rawBytes
    assertProofWorkerMemoryBudget({ artifactBytes })
    const frame = await assertArtifactPair(helperCircuit.circuit, mainCircuit.circuit)
    if (frame !== 'scoped_v2' && (prepared.verifier_scope !== '0' || prepared.epoch !== '0')) {
      throw new CircuitInputError('unsupported_input_schema')
    }

    const helperInputs = frame === 'scoped_v2' ? prepared : {
      credential_secret: prepared.credential_secret,
      nullifier_secret: prepared.nullifier_secret,
      video_hash_hi: prepared.video_hash_hi,
      video_hash_lo: prepared.video_hash_lo,
    }
    const helperResult = await new Noir(helperCircuit.circuit).execute(helperInputs)
    const returned = helperResult.returnValue
    if (!Array.isArray(returned) || returned.length !== (frame === 'browser_v1' ? 2 : 3)) {
      throw new CircuitInputError('invalid_proof_output')
    }
    const [credentialRoot, nullifier, domainTag] = returned as string[]
    const { witness } = await new Noir(mainCircuit.circuit).execute({
      ...helperInputs,
      credential_root: credentialRoot,
      nullifier,
      ...(domainTag === undefined ? {} : { domain_tag: domainTag }),
      ...(circuitVersion === null ? {} : { circuit_version: circuitVersion }),
    })
    const witnessBytes = byteLengthOfProofWorkerValue(witness)
    assertProofWorkerMemoryBudget({ artifactBytes, witnessBytes })

    const backend = new UltraHonkBackend(mainCircuit.circuit.bytecode, { threads: threadCount })
    try {
      const proofData = await backend.generateProof(witness, { keccak: true })
      assertProofOutput(proofData.proof.length, proofData.publicInputs, {
        video_hash_hi: prepared.video_hash_hi,
        video_hash_lo: prepared.video_hash_lo,
        credential_root: credentialRoot,
        nullifier,
        verifier_scope: prepared.verifier_scope,
        epoch: prepared.epoch,
        ...(domainTag === undefined ? {} : { domain_tag: domainTag }),
        ...(circuitVersion === null ? {} : { circuit_version: circuitVersion }),
      }, frame)
      const publicInputHex = encodePublicInputs(proofData.publicInputs, PUBLIC_FRAMES[frame])
      assertProofWorkerMemoryBudget({
        artifactBytes,
        witnessBytes,
        proofBytes: proofData.proof.length,
        publicInputBytes: publicInputHex.length / 2,
      })
      return {
        credentialRoot: encodeFieldToBytes32Hex(credentialRoot, 'credential_root'),
        nullifier: encodeFieldToBytes32Hex(nullifier, 'nullifier'),
        ...(domainTag === undefined ? {} : { domainTag: encodeFieldToBytes32Hex(domainTag, 'domain_tag') }),
        proof: bytesToHex(proofData.proof),
        publicInputs: publicInputHex,
        proofBytes: proofData.proof.length,
        publicInputBytes: publicInputHex.length / 2,
      }
    } finally {
      await backend.destroy()
    }
  } catch (error) {
    if (error instanceof CircuitInputError) throw error
    throw new CircuitInputError('proof_generation_failed')
  }
}

export async function generateAggregatedProof({
  videoHashes,
  credentialSecret,
  nullifierSecret,
}: GenerateAggregatedProofInput): Promise<AggregatedProof> {
  if (!Array.isArray(videoHashes)) throw new CircuitInputError('invalid_input')
  const batchSize = videoHashes.length
  if (batchSize < 1 || batchSize > MAX_AGGREGATION_SIZE) {
    throw new CircuitInputError('invalid_input')
  }

  for (const vh of videoHashes) {
    prepareSilentWitnessInputs({ videoHash: vh, credentialSecret, nullifierSecret })
  }

  try {
    const [helperCircuit, aggCircuit] = await Promise.all([
      loadAggregatorHelperCircuit(),
      loadAggregatorCircuit(),
    ])
    const artifactBytes = helperCircuit.rawBytes + aggCircuit.rawBytes
    assertProofWorkerMemoryBudget({ artifactBytes })

    // Build helper circuit inputs
    const helperInputs: Record<string, string> = {
      credential_secret: credentialSecret,
      nullifier_secret: nullifierSecret,
    }
    for (let i = 0; i < MAX_AGGREGATION_SIZE; i++) {
      if (i < batchSize) {
        const vh = videoHashes[i]
        helperInputs[`video_hash_hi_${i}`] = BigInt(`0x${vh.slice(0, 32)}`).toString(10)
        helperInputs[`video_hash_lo_${i}`] = BigInt(`0x${vh.slice(32)}`).toString(10)
      } else {
        helperInputs[`video_hash_hi_${i}`] = '0'
        helperInputs[`video_hash_lo_${i}`] = '0'
      }
    }

    // Run helper circuit to derive batch public inputs
    const helperResult = await new Noir(helperCircuit.circuit).execute(helperInputs)
    const batchResults = helperResult.returnValue as [string, string][]

    // Build aggregator circuit inputs
    const aggInputs: Record<string, string> = {
      credential_secret: credentialSecret,
      nullifier_secret: nullifierSecret,
    }
    for (let i = 0; i < MAX_AGGREGATION_SIZE; i++) {
      const vh = i < batchSize ? videoHashes[i] : '0000000000000000000000000000000000000000000000000000000000000000'
      const credentialRoot = batchResults[i][0]
      const nullifier = batchResults[i][1]

      aggInputs[`video_hash_hi_${i}`] = BigInt(`0x${vh.slice(0, 32)}`).toString(10)
      aggInputs[`video_hash_lo_${i}`] = BigInt(`0x${vh.slice(32)}`).toString(10)
      aggInputs[`credential_root_${i}`] = credentialRoot
      aggInputs[`nullifier_${i}`] = nullifier
    }

    // Generate the aggregated UltraHonk proof
    const { witness } = await new Noir(aggCircuit.circuit).execute(aggInputs)
    const witnessBytes = byteLengthOfProofWorkerValue(witness)
    assertProofWorkerMemoryBudget({ artifactBytes, witnessBytes })

    const backend = new UltraHonkBackend(aggCircuit.circuit.bytecode)
    try {
      const proofData = await backend.generateProof(witness, { keccak: true })
      const proofHex = bytesToHex(proofData.proof)
      const publicInputHex = encodePublicInputs(proofData.publicInputs)
      assertProofWorkerMemoryBudget({
        artifactBytes,
        witnessBytes,
        proofBytes: proofData.proof.length,
        publicInputBytes: publicInputHex.length / 2,
        publicInputLimitBytes: AGGREGATED_PUBLIC_INPUT_BYTES,
      })

      // Generate deterministic batch ID from the video hashes
      const batchId = await sha256(videoHashes.join(':'))

      return {
        protocol: 'harpocrates',
        version: 1,
        type: 'aggregated_batch',
        batchId,
        batchSize,
        maxBatchSize: MAX_AGGREGATION_SIZE,
        videoHashes: videoHashes.map((vh) => vh.toLowerCase()),
        proof: proofHex,
        publicInputs: publicInputHex,
        proofBytes: proofData.proof.length,
        publicInputBytes: publicInputHex.length / 2,
      }
    } finally {
      await backend.destroy()
    }
  } catch (error) {
    if (error instanceof CircuitInputError) throw error
    throw new CircuitInputError('proof_generation_failed')
  }
}

async function loadHelperCircuit() {
  helperCircuitPromise ??= loadCircuit('/noir/silent_witness_helper.json')
  return helperCircuitPromise
}

async function loadMainCircuit() {
  mainCircuitPromise ??= loadCircuit('/noir/silent_witness.json')
  return mainCircuitPromise
}

async function loadAggregatorCircuit() {
  aggregatorCircuitPromise ??= loadCircuit('/noir/silent_witness_aggregator.json')
  return aggregatorCircuitPromise
}

async function loadAggregatorHelperCircuit() {
  aggregatorHelperCircuitPromise ??= loadCircuit('/noir/silent_witness_aggregator_helper.json')
  return aggregatorHelperCircuitPromise
}

async function loadCircuit(path: string) {
  // Load the artifact manifest (once per page load)
  const manifest = await (async () => {
    const resp = await fetch('/zk/browser.artifacts.manifest.json', { cache: 'no-store' })
    if (!resp.ok) throw new CircuitInputError('manifest_load_failed')
    return resp.json() as Promise<any>
  })()

  // Find the manifest entry for this artifact path
  const entry = manifest.artifacts?.find((a: any) => a.path.replace('frontend/', '/') === path)
  const expectedSha = entry?.normalized_sha256 ?? entry?.raw_sha256

  // Helper to compute SHA-256 of a Uint8Array
  async function computeSha256(buf: Uint8Array): Promise<string> {
    const hash = await crypto.subtle.digest('SHA-256', buf)
    return Array.from(new Uint8Array(hash)).map(b => b.toString(16).padStart(2, '0')).join('')
  }

  // Attempt to serve from Cache Storage if available
  if (typeof caches !== 'undefined') {
    const cache = await caches.open('artifact-cache')
    const cachedResp = await cache.match(path)
    if (cachedResp) {
      const cachedArray = new Uint8Array(await cachedResp.arrayBuffer())
      const cachedHash = await computeSha256(cachedArray)
      if (expectedSha && cachedHash !== expectedSha) {
        // Invalidate mismatched cache entry
        await cache.delete(path)
      } else {
        // Return cached artifact
        const json = JSON.parse(new TextDecoder().decode(cachedArray)) as CompiledCircuit
        return { circuit: json, rawBytes: cachedArray.byteLength }
      }
    }
  }

  // Fallback: fetch from network
  const response = await fetch(path, { cache: 'no-store' })
  if (!response.ok) throw new CircuitInputError('circuit_load_failed')
  const { value, rawBytes } = await readBoundedCircuitArtifact<CompiledCircuit>(response, path)

  // Store the fetched artifact in Cache Storage for future loads
  if (typeof caches !== 'undefined') {
    const cache = await caches.open('artifact-cache')
    const respClone = response.clone()
    await cache.put(path, respClone)
  }

  return { circuit: value, rawBytes }
}

function bytesToHex(bytes: Uint8Array) {
  return Array.from(bytes, (byte) => byte.toString(16).padStart(2, '0')).join('')
}

async function sha256(input: string): Promise<string> {
  const bytes = new TextEncoder().encode(input)
  const hash = await crypto.subtle.digest('SHA-256', bytes)
  return bytesToHex(new Uint8Array(hash))
}

async function loadHelperCircuit() {
  helperCircuitPromise ??= loadCircuit('/noir/silent_witness_helper.json')
  return helperCircuitPromise
}

async function loadMainCircuit() {
  mainCircuitPromise ??= loadCircuit('/noir/silent_witness.json')
  return mainCircuitPromise
}

async function loadCircuit(path: string) {
  const response = await fetch(path, { cache: 'no-store' })
  if (!response.ok) {
    throw new Error(`Unable to load Noir circuit artifact: ${path}`)
  }
  return (await response.json()) as CompiledCircuit
}

function bytesToHex(bytes: Uint8Array) {
  return Array.from(bytes, (byte) => byte.toString(16).padStart(2, '0')).join('')
}
