import { BASE_FEE, Contract, Networks, StrKey, TransactionBuilder, rpc, scValToNative, nativeToScVal } from '@stellar/stellar-sdk'
import { asHex32, bytesToHex, hexToBytes } from './hashing.js'

/**
 * Chain-level proof record returned by the Harpocrates Registry contract.
 */
export type ChainProofRecord = {
  videoHash: string
  metadataHash: string
  tier: number
  status: number
  createdAt: string
  expiresAt?: string
  source: string | null
  issuer: string | null
}

/**
 * Chain-level dispute record returned by the Harpocrates Registry contract.
 */
export type ChainDisputeRecord = {
  disputeId: string
  proofId: string
  opener: string
  reason: string
  status: number
  createdAt: string
  resolvedAt?: string
}

export type StellarLookupOptions = {
  /** Stellar RPC URL (defaults to testnet). */
  rpcUrl?: string
  /** Network passphrase (defaults to testnet). */
  networkPassphrase?: string
  /** Source account for simulation. If omitted the simulation will likely fail. */
  sourceAddress?: string
  /** Timeout in milliseconds for each RTC call (defaults to 15000). */
  timeoutMs?: number
}

/**
 * Error thrown when an RPC call does not complete within the configured timeout.
 */
export class LookupTimeoutError extends Error {
  constructor(message: string) {
    super(message)
    this.name = 'LookupTimeoutError'
  }
}

const DEFAULT_RPC_URL = 'https://soroban-testnet.stellar.org'
const DEFAULT_TIMEOUT_MS = 15000

/**
 * Race a promise against a timer, rejecting with a typed LookupTimeoutError.
 */
function withTimeout<T>(promise: Promise<T>, timeoutMs: number, label: string): Promise<T> {
  return new Promise<T>((resolve, reject) => {
    const timer = setTimeout(() => {
      reject(new LookupTimeoutError(`${label} timed out after ${timeoutMs}ms`))
    }, timeoutMs)
    promise.then(
      (value) => {
        clearTimeout(timer)
        resolve(value)
      },
      (err) => {
        clearTimeout(timer)
        reject(err)
      },
    )
  })
}

const DEFAULT_SIMULATION_SOURCE = 'GAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAWHF'

/**
 * On-chain lifecycle status of a proof returned by `lookupProofStatus`.
 */
export type ProofLifecycleStatus = 'registered' | 'revoked' | 'expired' | 'unknown'

/**
 * Resolve the RPC URL from an explicit option, the HARPOCRATES_RPC_URL env
 * variable, or the built-in testnet default, in that order of precedence.
 */
export function resolveRpcUrl(explicit?: string): string {
  if (explicit !== undefined && explicit !== '') return explicit
  const fromEnv = process.env.HARPOCRATES_RPC_URL
  if (fromEnv !== undefined && fromEnv !== '') return fromEnv
  return DEFAULT_RPC_URL
}

/**
 * Resolve the contract ID from an explicit option or the
 * HARPOCRATES_CONTRACT_ID env variable. Returns undefined when neither is set.
 */
export function resolveContractId(explicit?: string): string | undefined {
  if (explicit !== undefined && explicit !== '') return explicit
  const fromEnv = process.env.HARPOCRATES_CONTRACT_ID
  if (fromEnv !== undefined && fromEnv !== '') return fromEnv
  return undefined
}

/**
 * Map a decoded Soroban `ProofVerificationStatus` value to a stable CLI status string.
 */
export function normalizeProofStatus(value: unknown): ProofLifecycleStatus {
  if (value === null || value === undefined) return 'unknown'

  const unwrapped =
    Array.isArray(value) && value.length > 0
      ? value[0]
      : typeof value === 'object' && 'status' in (value as Record<string, unknown>)
        ? (value as { status: unknown }).status
        : value

  if (typeof unwrapped === 'number' || typeof unwrapped === 'bigint') {
    switch (Number(unwrapped)) {
      case 1:
        return 'registered'
      case 2:
        return 'revoked'
      case 3:
        return 'expired'
      default:
        return 'unknown'
    }
  }

  if (typeof unwrapped === 'string') {
    const normalized = unwrapped.trim().toLowerCase().replace(/[\s_-]+/g, '')
    switch (normalized) {
      case 'valid':
      case 'registered':
        return 'registered'
      case 'revoked':
        return 'revoked'
      case 'expired':
        return 'expired'
      case 'notfound':
      case 'unknown':
      case 'missing':
        return 'unknown'
      default:
        return 'unknown'
    }
  }

  return 'unknown'
}

/**
 * Look up the on-chain verification status of a proof by its 32-byte proof ID.
 *
 * Uses the same read-only simulation path as `lookupByVideoHash`. Validates
 * `proofId` before creating the RPC client so malformed IDs never trigger a
 * network request.
 */
export async function lookupProofStatus(
  contractId: string,
  proofId: string,
  options: StellarLookupOptions = {},
): Promise<ProofLifecycleStatus> {
  // Encode the 32-byte proof ID as scBytes32 expected by Soroban.
  const proofIdScVal = nativeToScVal(hexToBytes(asHex32(proofId, 'proofId')))

  const rpcUrl = resolveRpcUrl(options.rpcUrl)
  const networkPassphrase = options.networkPassphrase ?? Networks.TESTNET
  const source =
    options.sourceAddress ||
    process.env.HARPOCRATES_SOURCE_ADDRESS ||
    DEFAULT_SIMULATION_SOURCE

  const server = new rpc.Server(rpcUrl)
  const account = await server.getAccount(source)
  const contract = new Contract(contractId)

  const transaction = new TransactionBuilder(account, {
    fee: BASE_FEE,
    networkPassphrase,
  })
    .addOperation(contract.call('get_proof_status', proofIdScVal))
    .setTimeout(30)
    .build()

  const simulation = await server.simulateTransaction(transaction)

  if (rpc.Api.isSimulationError(simulation)) {
    throw new Error(simulation.error)
  }

  if (!rpc.Api.isSimulationSuccess(simulation) && !rpc.Api.isSimulationRestore(simulation)) {
    return 'unknown'
  }

  const native = simulation.result?.retval ? scValToNative(simulation.result.retval) : null
  return normalizeProofStatus(native)
}

/**
 * Look up a proof record on-chain by its video hash.
 *
 * Uses a read-only simulation so no wallet or signing is required, but a
 * funded source address is needed to cover the simulated fee.
 */
export async function lookupByVideoHash(
  contractId: string,
  videoHash: string,
  options: StellarLookupOptions = {},
): Promise<ChainProofRecord | null> {
  const rpcUrl = resolveRpcUrl(options.rpcUrl)
  const networkPassphrase = options.networkPassphrase ?? Networks.TESTNET
  const source = options.sourceAddress
  const timeoutMs = options.timeoutMs ?? DEFAULT_TIMEOUT_MS

  if (!source) {
    throw new Error(
      'A source address is required for simulation. ' +
        'Pass --source-address or set HARPOCRATES_SOURCE_ADDRESS env var.',
    )
  }

  const server = new rpc.Server(rpcUrl)
  const account = await withTimeout(server.getAccount(source), timeoutMs, 'getAccount')
  const contract = new Contract(contractId)

  // Encode the 32-byte video hash as scBytes32 expected by Soroban.
  const videoHashScVal = nativeToScVal(hexToBytes(asHex32(videoHash, 'videoHash')))

  const transaction = new TransactionBuilder(account, {
    fee: BASE_FEE,
    networkPassphrase,
  })
    .addOperation(contract.call('get_by_video', videoHashScVal))
    .setTimeout(30)
    .build()

  const simulation = await withTimeout(server.simulateTransaction(transaction), timeoutMs, 'simulateTransaction')

  if (rpc.Api.isSimulationError(simulation)) {
    throw new Error(simulation.error)
  }

  if (!rpc.Api.isSimulationSuccess(simulation) && !rpc.Api.isSimulationRestore(simulation)) {
    return null
  }

  const native = simulation.result?.retval ? scValToNative(simulation.result.retval) : null
  if (!native) return null

  return {
    videoHash: bytesToHex(native.video_hash),
    metadataHash: bytesToHex(native.metadata_hash),
    tier: Number(native.tier),
    status: Number(native.status),
    createdAt: native.created_at?.toString?.() ?? String(native.created_at),
    expiresAt: native.expires_at?.toString?.() ?? undefined,
    source: native.source ?? null,
    issuer: native.issuer ?? null,
  }
}

/**
 * Read a dispute record from the registry by its dispute ID.
 *
 * Uses a simulation-only read so no signing is required. Returns `null`
 * if the contract returns an empty `Option` (no such dispute).
 */
export async function getDispute(
  contractId: string,
  disputeId: string,
  options: StellarLookupOptions = {},
): Promise<ChainDisputeRecord | null> {
  const native = await simulateRead(
    contractId,
    'get_dispute',
    [nativeToScVal(disputeId)],
    options,
  )

  if (!native) return null

  return {
    disputeId: native.dispute_id?.toString?.() ?? String(native.dispute_id),
    proofId: native.proof_id?.toString?.() ?? String(native.proof_id),
    opener: native.opener ?? null,
    reason: native.reason ?? '',
    status: Number(native.status),
    createdAt: native.created_at?.toString?.() ?? String(native.created_at),
    resolvedAt: native.resolved_at?.toString?.() ?? undefined,
  }
}

/**
 * Read the number of open disputes for a proof ID.
 *
 * Uses a simulation-only read so no signing is required. Returns `null` if
 * the contract returns an empty `Option`.
 */
export async function getOpenDisputeCount(
  contractId: string,
  proofId: string,
  options: StellarLookupOptions = {},
): Promise<number | null> {
  const native = await simulateRead(
    contractId,
    'get_open_dispute_count',
    [nativeToScVal(proofId)],
    options,
  )

  if (native === null || native === undefined) return null

  return Number(native)
}

/**
 * Run a simulation-only contract read and return the decoded native value.
 * Throws on simulation errors and returns `null` for empty `Option` results.
 */
async function simulateRead(
  contractId: string,
  method: string,
  args: unknown[],
  options: StellarLookupOptions,
): Promise<any> {
  const rpcUrl = resolveRpcUrl(options.rpcUrl)
  const networkPassphrase = options.networkPassphrase ?? Networks.TESTNET
  const source = options.sourceAddress
  const timeoutMs = options.timeoutMs ?? DEFAULT_TIMEOUT_MS

  const contract = new Contract(contractId)
  const operation = contract.call(method, ...(args as Parameters<typeof contract.call>[1]))

  if (!source) {
    throw new Error(
      'A source address is required for simulation. ' +
        'Pass --source-address or set HARPOCRATES_SOURCE_ADDRESS env var.',
    )
  }

  const server = new rpc.Server(rpcUrl)
  const account = await withTimeout(server.getAccount(source), timeoutMs, 'getAccount')

  const transaction = new TransactionBuilder(account, {
    fee: BASE_FEE,
    networkPassphrase,
  })
    .addOperation(operation)
    .setTimeout(30)
    .build()

  const simulation = await withTimeout(server.simulateTransaction(transaction), timeoutMs, 'simulateTransaction')

  if (rpc.Api.isSimulationError(simulation)) {
    throw new Error(simulation.error)
  }

  if (!rpc.Api.isSimulationSuccess(simulation) && !rpc.Api.isSimulationRestore(simulation)) {
    return null
  }

  const retval = simulation.result?.retval
  if (!retval) return null

  const native = scValToNative(retval)
  if (native === null || native === undefined) return null

  return native
}

/**
 * Verify that a transaction on Stellar matches the expected contract ID and
 * was successfully confirmed.
 */
export async function verifyTransaction(
  txHash: string,
  expectedContractId?: string,
  options: StellarLookupOptions = {},
): Promise<TransactionVerification> {
  const rpcUrl = resolveRpcUrl(options.rpcUrl)
  const timeoutMs = options.timeoutMs ?? DEFAULT_TIMEOUT_MS
  const server = new rpc.Server(rpcUrl)
  const response = await withTimeout(server.getTransaction(txHash), timeoutMs, 'getTransaction')

  switch (response.status) {
    case rpc.Api.GetTransactionStatus.NOT_FOUND:
      return { status: 'missing', txHash }

    case rpc.Api.GetTransactionStatus.FAILED:
      return {
        status: 'failed',
        txHash,
        ledger: response.ledger,
        createdAt: response.createdAt,
      }

    case rpc.Api.GetTransactionStatus.SUCCESS:
      return {
        status: 'confirmed',
        txHash,
        ledger: response.ledger,
        createdAt: response.createdAt,
        contractMatch: expectedContractId
          ? checkContractMatch(response.envelopeXdr.toXDR(), expectedContractId)
          : undefined,
      }

    default:
      return { status: 'missing', txHash }
  }
}

export type TransactionVerification = {
  status: 'confirmed' | 'pending' | 'failed' | 'missing'
  txHash: string
  ledger?: number
  createdAt?: number
  contractMatch?: boolean
}

/**
 * Check whether an envelope references the decoded contract address bytes.
 * This is a conservative preflight, not a substitute for matching chain data.
 */
export function checkContractMatch(envelopeBytes: Uint8Array, contractId: string): boolean {
  if (!StrKey.isValidContract(contractId)) return false
  const hex = bytesToHex(StrKey.decodeContract(contractId))
  const bytesHex = Array.from(envelopeBytes, (b) => Number(b).toString(16).padStart(2, '0')).join('')
  return bytesHex.includes(hex)
}

/**
 * Lineage record stored on-chain in the registry.
 */
export type LineageRecord = {
  parentProofIds: string[]
  parentCommitments: string[]
  manifestDigest: string
  actor: string
  operationType: string
  outputDigest: string
  depth: number
}

/**
 * Proof status as determined by the registry.
 */
export type ProofStatus = 'valid' | 'revoked' | 'expired' | 'disputed' | 'missing'

/**
 * Retrieve a stored lineage record by its 32-byte output digest.
 */
export async function getLineage(
  contractId: string,
  outputDigest: string,
  options: StellarLookupOptions = {},
): Promise<LineageRecord | null> {
  const rpcUrl = resolveRpcUrl(options.rpcUrl)
  const networkPassphrase = options.networkPassphrase ?? Networks.TESTNET
  const source = options.sourceAddress
  const timeoutMs = options.timeoutMs ?? DEFAULT_TIMEOUT_MS

  if (!source) {
    throw new Error(
      'A source address is required for simulation. ' +
        'Pass --source-address or set HARPOCRATES_SOURCE_ADDRESS env var.',
    )
  }

  const server = new rpc.Server(rpcUrl)
  const account = await withTimeout(server.getAccount(source), timeoutMs, 'getAccount')
  const contract = new Contract(contractId)

  const outputDigestScVal = nativeToScVal(hexToBytes(asHex32(outputDigest, 'outputDigest')))

  const transaction = new TransactionBuilder(account, {
    fee: BASE_FEE,
    networkPassphrase,
  })
    .addOperation(contract.call('get_lineage', outputDigestScVal))
    .setTimeout(30)
    .build()

  const simulation = await withTimeout(server.simulateTransaction(transaction), timeoutMs, 'simulateTransaction')

  if (rpc.Api.isSimulationError(simulation)) {
    throw new Error(simulation.error)
  }

  if (!rpc.Api.isSimulationSuccess(simulation) && !rpc.Api.isSimulationRestore(simulation)) {
    return null
  }

  const native = simulation.result?.retval ? scValToNative(simulation.result.retval) : null
  if (!native) return null

  const parentProofIds: string[] = Array.isArray(native.parent_proof_ids)
    ? native.parent_proof_ids.map((id: unknown) => String(id))
    : []
  const parentCommitments: string[] = Array.isArray(native.parent_commitments)
    ? native.parent_commitments.map((c: unknown) => bytesToHex(c as Uint8Array))
    : []

  return {
    parentProofIds,
    parentCommitments,
    manifestDigest: bytesToHex(native.manifest_digest),
    actor: String(native.actor ?? ''),
    operationType: String(native.operation_type ?? ''),
    outputDigest: bytesToHex(native.output_digest),
    depth: Number(native.depth ?? 0),
  }
}

/**
 * Resolve the current proof status from the registry.
 * Returns 'missing' when the proof is not found on-chain.
 */
export async function getProofStatus(
  contractId: string,
  videoHash: string,
  options: StellarLookupOptions = {},
): Promise<ProofStatus> {
  const native = await simulateRead(
    contractId,
    'get_proof_status',
    [nativeToScVal(hexToBytes(asHex32(videoHash, 'videoHash')))],
    options,
  )

  if (native === null || native === undefined) return 'missing'

  const value = typeof native === 'string' ? native : String(native)
  switch (value) {
    case 'valid':
    case 'revoked':
    case 'expired':
    case 'disputed':
      return value
    default:
      return 'missing'
  }
}