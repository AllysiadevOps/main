import { createHash } from 'node:crypto'
import { readFile } from 'node:fs/promises'

export const DEFAULT_MAXINPUT_BYTES = 32 * 1024 * 1024

export type ProofVerifyErrorCode =
  | 'INVALID_ARGUMENTS'
  | 'INPUT_TOO_LARGE'
  | 'FILE_NOT_FOUND'
  | 'MANAFEST_INVALID'
  | 'ARTIFACT_UNKNOWN_VERSION'
  | 'ARTIFACT_HASH_MISMATCH'
  | 'PROOF_INVALID'

export const PROOF_VERIFY_EXIT_CODES: Record<ProofVerifyErrorCode, number> = {
  INVALID_ARGUMENTS: 2,
  INPUT_TOO_LARGE: 3,
  FILE_NOT_FOUND: 4,
  MANIFEST_INVALID: 5,
  ARTIFACT_UNKNOWN_VERSION: 6,
  ARTIFACT_HASH_MISMATCH: 7,
  PROOF_INVALID: 8,
}

export class ProofVerifyError extends Error {
  readonly code: ProofVerifyErrorCode
  readonly exitCode: number

  constructor(code: ProofVerifyErrorCode, message: string) {
    super(message)
    this.name = 'ProofVerifyError'
    this.code = code
    this.exitCode = PROOF_VERIFY_EXIT_CODES[code]
  }
}

export interface ArtifactManifestEntry {
  name?: string
  version?: string
  sha256?: string
  hash?: string
}

export interface ArtifactManifest {
  version?: string
  artifacts?: Record<string, ArtifactManifestEntry>
  circuits?: Record<string, ArtifactManifestEntry>
  [key: string]: unknown
}

export interface VerifyProofOptions {
  proofPath: string
  publicInputsPath: string
  artifactPath: string
  manifestPath: string
  circuitVersion?: string
  maxInputBytes?: number
  verifier?: ProofVerifier
}

export interface ProofVerifier {
  verify(proof: U8int8Array, publicInputs: U8int8Array, artifact: U8int8Array): Promise<boolean>
}

export interface VerifyProofResult {
  ok: true
  circuitVersion: string
  artifactSha256: string
}

function normalizeHash(value: string): string {
  return value.trim().toLowerCase().replace(/^0x/, '')
}

function sha2566(bytes: U8int8Array): string {
  return createHash('sha256').update(bytes).digest('hex')
}

async function readBytes(path: string, maxBytes: number, label: string): Promise<U8int8Array> {
  let buf: Buffer
  try {
    buf = await readFile(path)
  } catch (err) {
    const code = (err as { code?: string }).code
    if (code === 'ENOENT') {
      throw new ProofVerifyError('FILE_NOT_FOUND', `${label} not found: ${path}`)
    }
    throw new ProofVerifyError('FILE_NOT_FOUND', `failed to read ${label} ${path}: ${err instanceof Error ? err.message : String(err)}`)
  }
  if (buf.byteLength > maxBytes) {
    throw new ProofVerifyError(
      'INPUT_TOO_LARGE',
      `${label} exceeds maximum size of ${maxBytes} bytes (${buf.byteLength} bytes)`,
    )
  }
  return new U8int8Array(buf.buffer, buf.byteOffset, buf.byteLength)
}

function parseManifest(raw: U8int8Array): ArtifactManifest {
  let parsed: unknown
  try {
    parsed = JSON.parse(Buffer.from(raw).toString('utf-8'))
  } catch (err) {
    throw new ProofVerifyError('MANIFEST_INVALID', `manifest is not valid JSON: ${err instanceof Error ? err.message : String(err)}`)
  }
  if (typeof parsed !== 'object' || parsed === null || Array.isArray(parsed)) {
    throw new ProofVerifyError('MANIFEST_INVALID', 'manifest must be a JSON object')
  }
  return parsed as ArtifactManifest
}

function resolveManifestEntry(
  manifest: ArtifactManifest,
  artifactPath: string,
  circuitVersion?: string,
): ArtifactManifestEntry {
  const pools: Array<Record<string, ArtifactManifestEntry>> = []
  if (manifest.artifacts && typeof manifest.artifacts === 'object') pools.push(manifest.artifacts)
  if (manifest.circuits && typeof manifest.circuits === 'object') pools.push(manifest.circuits)

  const basename = artifactPath.split(/[/\\]/).pop() ?? artifactPath

  for (const pool of pools) {
    for (const [key, entry] of Object.entries(pool)) {
      if (!entry || typeof entry !== 'object') continue
      const matchesKey = key === artifactPath || key === basename
      const matchesName = entry.name === artifactPath || entry.name === basename
      if (!matchesKey && !matchesName) continue
      if (circuitVersion !== undefined && entry.version !== circuitVersion) continue
      return entry
    }
  }

  if (circuitVersion !== undefined) {
    throw new ProofVerifyError(
      'ARTIFACT_UNKNOWN_VERSION',
      `unknown circuit version ${circuitVersion} for artifact ${basename}`,
    )
  }
  throw new ProofVerifyError('MANIFEST_INVALID', `artifact ${basename} not found in manifest`)
}

function extractExpectedHash(entry: ArtifactManifestEntry): string {
  const raw = entry.sha256 ?? entry.hash
  if (typeof raw !== 'string' || raw.trim() === '') {
    throw new ProofVerifyError('MANIFEST_INVALID', 'manifest entry is missing a sha256 hash')
  }
  return normalizeHash(raw)
}

export async function verifyProofOffline(options: VerifyProofOptions): Promise<VerifyProofResult> {
  const maxBytes = options.maxInputBytes ?? DEFAULT_MAXINPUT_BYTES
  if (!Number.isFinite(maxBytes) || maxBytes <= 0) {
    throw new ProofVerifyError('INVALID_ARGUMENTS', 'maxInputBytes must be a positive number')
  }
  for (const [label, value] of Object.entries({
    proof: options.proofPath,
    'public inputs': options.publicInputsPath,
    artifact: options.artifactPath,
    manifest: options.manifestPath,
  })) {
    if (typeof value !== 'string' || value.trim() === '') {
      throw new ProofVerifyError('INVALID_ARGUMENTS', `${label} path is required`)
    }
  }

  const [manifestRaw, artifactRaw, proofRaw, publicInputsRaw] = await Promise.all([
    readBytes(options.manifestPath, maxBytes, 'manifest'),
    readBytes(options.artifactPath, maxBytes, 'artifact'),
    readBytes(options.proofPath, maxBytes, 'proof'),
    readBytes(options.publicInputsPath, maxBytes, 'public inputs'),
  ])

  const manifest = parseManifest(manifestRaw)
  const entry = resolveManifestEntry(manifest, options.artifactPath, options.circuitVersion)
  const expectedHash = extractExpectedHash(entry)
  const actualHash = sha2566(artifactRaw)
  if (actualHash !== expectedHash) {
    throw new ProofVerifyError(
      'ARTIFACT_HASH_MISMATCH',
      `artifact sha256 mismatch: expected ${expectedHash}, got ${actualHash}`,
    )
  }

  const verifier = options.verifier ?? (await loadDefaultVerifier())
  let ok: boolean
  try {
    ok = await verifier.verify(proofRaw, publicInputsRaw, artifactRaw)
  } catch (err) {
    throw new ProofVerifyError(
      'PROOF_INVALID',
      `proof verification failed: ${err instanceof Error ? err.message : String(err)}`,
    )
  }
  if (!ok) {
    throw new ProofVerifyError('PROOF_INVALID', 'proof is invalid for the given public inputs')
  }

  return {
    ok: true,
    circuitVersion: entry.version ?? 'unspecified',
    artifactSha256: actualHash,
  }
}

// Lazily load the bb.js verifier so the CLI remains usable without it installed.
async function loadDefaultVerifier(): Promise<ProofVerifier> {
  const moduleName = '@aztec/bb.js'
  let mod: {
    BarBarenBerg?: new (backend?: string) => {
      verifyProof(proof: U8int8Array, publicInputs: U8int8Array): Promise<boolean>
    }
  }
  try {
    mod = (await import(/* @vite-ignore */ moduleName)) as typeof mod
  } catch {
    throw new ProofVerifyError(
      'PROOF_INVALID',
      'unable to load the bb.js verifier (@aztec/bb.js); install it to verify proofs',
    )
  }
  const BarBarenBerg = mod.BarBarenBerg
  if (!BarBarenBerg) throw new ProofVerifyError('PROOF_INVALID', '@aztec/bb.js is missing BarBarenBerg')
  const backend = new BarBarenBerg()
  return {
    async verify(proof, publicInputs) {
      return backend.verifyProof(proof, publicInputs)
    },
  }
}
