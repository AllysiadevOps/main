import { UltraHonkBackend } from '@aztec/bb.js'
import { Noir } from '@noir-lang/noir_js'
import type { CompiledCircuit } from '@noir-lang/types'
import {
  assertProofWorkerMemoryBudget,
  byteLengthOfProofWorkerValue,
  readBoundedCircuitArtifact,
} from './proofWorkerMemory'
import { encodeFieldToBytes32Hex } from './verifierInputs'
import { CircuitInputError } from './circuitInputSchema'

export const REDACTED_ANCESTRY_ARTIFACT_VERSION = 'redacted_ancestry/v1'
export const REDACTED_ANCESTRY_PUBLIC_FIELDS = [
  'parent_commitment',
  'derivative_digest',
  'parameters_digest',
  'operation_type',
  'ancestry_root',
  'nullifier',
  'depth',
  'domain_tag',
] as const

const WITNESS_FIELDS = [
  'parent_hash_hi',
  'parent_hash_lo',
  'parent_blinding',
  'mask_commitment',
  'redaction_seed',
  'credential_secret',
  'nullifier_secret',
] as const

export type RedactedAncestryWitness = Record<(typeof WITNESS_FIELDS)[number], string> & {
  depth: number
}

export type RedactedAncestryProof = {
  artifactVersion: typeof REDACTED_ANCESTRY_ARTIFACT_VERSION
  proof: string
  publicInputs: string
  proofBytes: number
  publicInputBytes: number
}

let helperPromise: Promise<{ circuit: CompiledCircuit; rawBytes: number }> | null = null
let mainPromise: Promise<{ circuit: CompiledCircuit; rawBytes: number }> | null = null

async function loadArtifact(path: string): Promise<{ circuit: CompiledCircuit; rawBytes: number }> {
  const response = await fetch(path, { cache: 'no-store' })
  if (!response.ok) throw new CircuitInputError('circuit_load_failed')
  return readBoundedCircuitArtifact<CompiledCircuit>(response, path)
}

function loadHelper() {
  helperPromise ??= loadArtifact('/noir/redacted_ancestry_helper.json')
  return helperPromise
}

function loadMain() {
  mainPromise ??= loadArtifact('/noir/redacted_ancestry.json')
  return mainPromise
}

function validateWitness(input: RedactedAncestryWitness): Record<string, string> {
  if (!input || !Number.isInteger(input.depth) || input.depth < 1 || input.depth > 4) {
    throw new CircuitInputError('invalid_input')
  }
  const fields: Record<string, string> = { depth: String(input.depth) }
  for (const field of WITNESS_FIELDS) {
    const value = input[field]
    if (typeof value !== 'string' || !/^[0-9]{1,78}$/.test(value)) {
      throw new CircuitInputError('invalid_input')
    }
    try {
      fields[field] = encodeFieldToBytes32Hex(value, field)
        ? BigInt(value).toString(10)
        : '0'
    } catch {
      throw new CircuitInputError('invalid_input')
    }
  }
  return fields
}

function bytesToHex(bytes: Uint8Array): string {
  return Array.from(bytes, (byte) => byte.toString(16).padStart(2, '0')).join('')
}

function encodePublicFrame(fields: string[]): string {
  if (fields.length !== REDACTED_ANCESTRY_PUBLIC_FIELDS.length) {
    throw new CircuitInputError('invalid_proof_output')
  }
  return fields
    .map((value, index) => encodeFieldToBytes32Hex(value, REDACTED_ANCESTRY_PUBLIC_FIELDS[index]))
    .join('')
}

/** Generate and locally verify an opt-in redacted ancestry proof. */
export async function generateRedactedAncestryProof(
  input: RedactedAncestryWitness,
): Promise<RedactedAncestryProof> {
  const witnessInputs = validateWitness(input)
  let backend: UltraHonkBackend | null = null
  try {
    const [helper, main] = await Promise.all([loadHelper(), loadMain()])
    const artifactBytes = helper.rawBytes + main.rawBytes
    assertProofWorkerMemoryBudget({ artifactBytes })

    const helperResult = await new Noir(helper.circuit).execute(witnessInputs)
    if (!Array.isArray(helperResult.returnValue) || helperResult.returnValue.length !== 7) {
      throw new CircuitInputError('invalid_proof_output')
    }
    const [parentCommitment, derivativeDigest, parametersDigest, ancestryRoot, nullifier, depth, domainTag] =
      helperResult.returnValue as string[]
    const mainInputs = {
      ...witnessInputs,
      parent_commitment: parentCommitment,
      derivative_digest: derivativeDigest,
      parameters_digest: parametersDigest,
      operation_type: '0x726564616374',
      ancestry_root: ancestryRoot,
      nullifier,
      depth,
      domain_tag: domainTag,
    }
    const { witness } = await new Noir(main.circuit).execute(mainInputs)
    const witnessBytes = byteLengthOfProofWorkerValue(witness)
    assertProofWorkerMemoryBudget({ artifactBytes, witnessBytes })

    backend = new UltraHonkBackend(main.circuit.bytecode)
    const proofData = await backend.generateProof(witness, { keccak: true })
    const publicInputs = encodePublicFrame(proofData.publicInputs)
    const expectedPublicInputs = encodePublicFrame([
      parentCommitment,
      derivativeDigest,
      parametersDigest,
      BigInt('0x726564616374').toString(10),
      ancestryRoot,
      nullifier,
      depth,
      domainTag,
    ])
    if (publicInputs !== expectedPublicInputs) throw new CircuitInputError('invalid_proof_output')
    const proof = bytesToHex(proofData.proof)
    const publicInputFields = proofData.publicInputs
    const locallyVerified = await backend.verifyProof({
      proof: proofData.proof,
      publicInputs: publicInputFields,
    }, { keccak: true })
    if (!locallyVerified) throw new CircuitInputError('proof_generation_failed')

    assertProofWorkerMemoryBudget({
      artifactBytes,
      witnessBytes,
      proofBytes: proofData.proof.length,
      publicInputBytes: publicInputs.length / 2,
    })
    return {
      artifactVersion: REDACTED_ANCESTRY_ARTIFACT_VERSION,
      proof,
      publicInputs,
      proofBytes: proofData.proof.length,
      publicInputBytes: publicInputs.length / 2,
    }
  } catch (error) {
    if (error instanceof CircuitInputError) throw error
    throw new CircuitInputError('proof_generation_failed')
  } finally {
    await backend?.destroy()
  }
}

/** Verify a published ancestry proof locally using the pinned browser artifact. */
export async function verifyRedactedAncestryProof(proof: RedactedAncestryProof): Promise<boolean> {
  if (
    proof?.artifactVersion !== REDACTED_ANCESTRY_ARTIFACT_VERSION ||
    !/^(?:[0-9a-f]{2})+$/i.test(proof.proof) ||
    proof.publicInputs.length !== REDACTED_ANCESTRY_PUBLIC_FIELDS.length * 64 ||
    !/^[0-9a-f]+$/i.test(proof.publicInputs)
  ) {
    throw new CircuitInputError('invalid_input')
  }
  const { circuit } = await loadMain()
  const fields = Array.from({ length: REDACTED_ANCESTRY_PUBLIC_FIELDS.length }, (_, index) => {
    const hex = proof.publicInputs.slice(index * 64, (index + 1) * 64)
    const decimal = BigInt(`0x${hex}`).toString(10)
    if (encodeFieldToBytes32Hex(decimal, REDACTED_ANCESTRY_PUBLIC_FIELDS[index]) !== hex.toLowerCase()) {
      throw new CircuitInputError('invalid_input')
    }
    return decimal
  })
  const backend = new UltraHonkBackend(circuit.bytecode)
  try {
    return await backend.verifyProof({
      proof: Uint8Array.from(proof.proof.match(/.{2}/g) ?? [], (byte) => Number.parseInt(byte, 16)),
      publicInputs: fields,
    }, { keccak: true })
  } finally {
    await backend.destroy()
  }
}