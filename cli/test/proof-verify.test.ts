import { createHash } from 'node:crypto'
import { mkdtemp, rm, writeFile } from 'node:fs/promises'
import { join } from 'node:path'
import { afterEach, beforeEach, describe, expect, it } from 'vitest'

import {
  PROOF_VERIFY_EXIT_CODES,
  ProofVerifyError,
  verifyProofOffline,
  type ProofVerifier,
} from '../src/proof-verify.js'

interface Fixture {
  proof: Buffer
  publicInputs: Buffer
  artifact: Buffer
}

function sha256(bytes: Buffer): string {
  return createHash('sha256').update(bytes).digest('hex')
}

function constantVerifier(expectedProof: Buffer, expectedInputs: Buffer): ProofVerifier {
  return {
    async verify(proof, publicInputs) {
      return Buffer.from(proof).equals(expectedProof) && Buffer.from(publicInputs).equals(expectedInputs)
    },
  }
}

describe('verifyProofOffline', () => {
  let dir: string
  let fixtures: Fixture
  let manifestPath: string
  let artifactPath: string
  let proofPath: string
  let inputsPath: string

  beforeEach(async () => {
    dir = await mkdtemp('proof-verify-')
    fixtures = {
      proof: Buffer.from('silent-witness-proof-v2'),
      publicInputs: Buffer.from('public-inputs-v2'),
      artifact: Buffer.from('silent-witness-artifact-v2'),
    }
    manifestPath = join(dir, 'manifest.json')
    artifactPath = join(dir, 'silent_witness.json')
    proofPath = join(dir, 'proof.bin')
    inputsPath = join(dir, 'public_inputs.bin')
    await Promise.all([
      writeFile(proofPath, fixtures.proof),
      writeFile(inputsPath, fixtures.publicInputs),
      writeFile(artifactPath, fixtures.artifact),
      writeFile(
        manifestPath,
        JSON.stringify({
          version: '2',
          artifacts: {
            'silent_witness.json': {
              name: 'silent_witness.json',
              version: '2',
              sha256: sha256(fixtures.artifact),
            },
          },
        }),
      ),
    ])
  })

  afterEach(async () => {
    await rm(dir, { recursive: true, force: true })
  })

  it('verifies a valid fixture offline', async () => {
    const result = await verifyProofOffline({
      proofPath,
      publicInputsPath: inputsPath,
      artifactPath,
      manifestPath,
      circuitVersion: '2',
      verifier: constantVerifier(fixtures.proof, fixtures.publicInputs),
    })
    expect(result.ok).toBe(true)
    expect(result.circuitVersion).toBe('2')
    expect(typeof result.artifactSha256).toBe('string')
  })

  it('rejects a tampered proof with PROOF_INVALID', async () => {
    await writeFile(proofPath, Buffer.from('tampered-proof'))
    await expect(
      verifyProofOffline({
        proofPath,
        publicInputsPath: inputsPath,
        artifactPath,
        manifestPath,
        verifier: constantVerifier(fixtures.proof, fixtures.publicInputs),
      }),
    ).rejects.toMatchObject({
      code: 'PROOF_INVALID',
      exitCode: PROOF_VERIFY_EXIT_CODES.PROOF_INVALID,
    })
  })

  it('rejects a tampered artifact with ARTIFACT_HASH_MISMATCH', async () => {
    await writeFile(artifactPath, Buffer.from('tampered-artifact'))
    await expect(
      verifyProofOffline({
        proofPath,
        publicInputsPath: inputsPath,
        artifactPath,
        manifestPath,
        verifier: constantVerifier(fixtures.proof, fixtures.publicInputs),
      }),
    ).rejects.toMatchObject({
      code: 'ARTIFACT_HASH_MISMATCH',
      exitCode: PROOF_VERIFY_EXIT_CODES.ARTIFACT_HASH_MISMATCH,
    })
  })

  it('rejects unknown circuit versions with a stable code', async () => {
    await expect(
      verifyProofOffline({
        proofPath,
        publicInputsPath: inputsPath,
        artifactPath,
        manifestPath,
        circuitVersion: '999',
        verifier: constantVerifier(fixtures.proof, fixtures.publicInputs),
      }),
    ).rejects.toMatchObject({
      code: 'ARTIFACT_UNKNOWN_VERSION',
      exitCode: PROOF_VERIFY_EXIT_CODES.ARTIFACT_UNKNOWN_VERSION,
    })
  })

  it('rejects oversized inputs with INPUT_TOO_LARGE', async () => {
    await expect(
      verifyProofOffline({
        proofPath,
        publicInputsPath: inputsPath,
        artifactPath,
        manifestPath,
        maxInputBytes: 4,
        verifier: constantVerifier(fixtures.proof, fixtures.publicInputs),
      }),
    ).rejects.toMatchObject({
      code: 'INPUT_TOO_LARGE',
      exitCode: PROOF_VERIFY_EXIT_CODES.INPUT_TOO_LARGE,
    })
  })

  it('reports missing files with FILE_NOT_FOUND', async () => {
    await expect(
      verifyProofOffline({
        proofPath: join(dir, 'missing.bin'),
        publicInputsPath: inputsPath,
        artifactPath,
        manifestPath,
        verifier: constantVerifier(fixtures.proof, fixtures.publicInputs),
      }),
    ).rejects.toMatchObject({
      code: 'FILE_NOT_FOUND',
      exitCode: PROOF_VERIFY_EXIT_CODES.FILE_NOT_FOUND,
    })
  })

  it('surfaces ProofVerifyError type for callers', async () => {
    await writeFile(proofPath, Buffer.from('tampered-proof'))
    await expect(
      verifyProofOffline({
        proofPath,
        publicInputsPath: inputsPath,
        artifactPath,
        manifestPath,
        verifier: constantVerifier(fixtures.proof, fixtures.publicInputs),
      }),
    ).rejects.toBeInstanceOf(ProofVerifyError)
  })
})
