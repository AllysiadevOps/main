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
}

const DEFAULT_RPC_URL = 'https://soroban-testnet.stellar.org'

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

  if (!source) {
    throw new Error(
      'A source address is required for simulation. ' +
        'Pass --source-address or set HARPOCRATES_SOURCE_ADDRESS env var.',
    )
  }

  const server = new rpc.Server(rpcUrl)
  const account = await server.getAccount(source)
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

  const simulation = await server.simulateTransaction(transaction)

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
  const rpcUrl = options.rpcUrl ?? DEFAULT_RPC_URL
  const networkPassphrase = options.networkPassphrase ?? Networks.TESTNET
  const source = options.sourceAddress

  if (!source) {
    throw new Error(
      'A source address is required for simulation. ' +
        'Pass --source-address or set HARPOCRATES_SOURCE_ADDRESS env var.',
    )
  }

  const server = new rpc.Server(rpcUrl)
  const account = await server.getAccount(source)
  const contract = new Contract(contractId)

  const transaction = new TransactionBuilder(account, {
    fee: BASE_FEE,
    networkPassphrase,
  })
    .addOperation(contract.call(method, ...args))
    .setTimeout(30)
    .build()

  const simulation = await server.simulateTransaction(transaction)

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
  const server = new rpc.Server(rpcUrl)
  const response = await server.getTransaction(txHash)

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
  const rpcUrl = options.rpcUrl ?? DEFAULT_RPC_URL
  const networkPassphrase = options.networkPassphrase ?? Networks.TESTNET
  const source = options.sourceAddress

  if (!source) {
    throw new Error(
      'A source address is required for simulation. ' +
        'Pass --source-address or set HARPOCRATES_SOURCE_ADDRESS env var.',
    )
  }

  const server = new rpc.Server(rpcUrl)
  const account = await server.getAccount(source)
  const contract = new Contract(contractId)

  const outputDigestScVal = nativeToScVal(hexToBytes(asHex32(outputDigest, 'outputDigest')))

  const transaction = new TransactionBuilder(account, {
    fee: BASE_FEE,
    networkPassphrase,
  })
    .addOperation(contract.call('get_lineage', outputDigestScVal))
    .setTimeout(30)
    .build()

  const simulation = await server.simulateTransaction(transaction)

  if (rpc.Api.isSimulationError(simulation)) {
    throw new Error(simulation.error)
  }

  if (!rpc.Api.isSimulationSuccess(simulation) && !rpc.Api.isSimulationRestore(simulation)) {
    return null
  }

  const native = simulation.result?.retval ? scValToNative(simulation.result.retval) : null
  if (!native) return null

  const parentProofIds: string[] = Array.isArray(native.parent_proof_ids)
    ? native.parent_proof_ids.map((id: Uint8Array | Buffer | string) =>
        typeof id === 'string' ? id.toLowerCase() : bytesToHex(id),
      )
    : []

  const parentCommitments: string[] = Array.isArray(native.parent_commitments)
    ? native.parent_commitments.map((c: Uint8Array | Buffer | string) =>
        typeof c === 'string' ? c.toLowerCase() : bytesToHex(c),
      )
    : []

  return {
    parentProofIds,
    parentCommitments,
    manifestDigest: typeof native.manifest_digest === 'string' ? native.manifest_digest.toLowerCase() : bytesToHex(native.manifest_digest),
    actor: native.actor?.toString?.() ?? String(native.actor),
    operationType: String(native.operation_type),
    outputDigest: typeof native.output_digest === 'string' ? native.output_digest.toLowerCase() : bytesToHex(native.output_digest),
    depth: Number(native.depth),
  }
}

/**
 * Retrieve the status of a registered proof ID, checking both proof status and open disputes.
 */
export async function getProofStatus(
  contractId: string,
  proofId: string,
  options: StellarLookupOptions = {},
): Promise<ProofStatus> {
  const rpcUrl = options.rpcUrl ?? DEFAULT_RPC_URL
  const networkPassphrase = options.networkPassphrase ?? Networks.TESTNET
  const source = options.sourceAddress

  if (!source) {
    throw new Error(
      'A source address is required for simulation. ' +
        'Pass --source-address or set HARPOCRATES_SOURCE_ADDRESS env var.',
    )
  }

  const server = new rpc.Server(rpcUrl)
  const account = await server.getAccount(source)
  const contract = new Contract(contractId)

  const proofIdScVal = nativeToScVal(hexToBytes(asHex32(proofId, 'proofId')))

  // Simulate get_proof_status
  const txStatus = new TransactionBuilder(account, {
    fee: BASE_FEE,
    networkPassphrase,
  })
    .addOperation(contract.call('get_proof_status', proofIdScVal))
    .setTimeout(30)
    .build()

  const simStatus = await server.simulateTransaction(txStatus)
  if (rpc.Api.isSimulationError(simStatus)) {
    throw new Error(simStatus.error)
  }

  let status: ProofStatus = 'missing'
  if (rpc.Api.isSimulationSuccess(simStatus) || rpc.Api.isSimulationRestore(simStatus)) {
    const native = simStatus.result?.retval ? scValToNative(simStatus.result.retval) : null
    if (native !== null && native !== undefined) {
      const raw = String(native).toLowerCase()
      if (raw === 'valid' || raw === '0') {
        status = 'valid'
      } else if (raw === 'revoked' || raw === '1') {
        status = 'revoked'
      } else if (raw === 'expired' || raw === '2') {
        status = 'expired'
      } else if (raw === 'notfound' || raw === '3') {
        status = 'missing'
      }
    }
  }

  if (status !== 'valid') {
    return status
  }

  // Check if there are any open disputes
  try {
    const txDispute = new TransactionBuilder(account, {
      fee: BASE_FEE,
      networkPassphrase,
    })
      .addOperation(contract.call('get_open_dispute_count', proofIdScVal))
      .setTimeout(30)
      .build()

    const simDispute = await server.simulateTransaction(txDispute)
    if (rpc.Api.isSimulationSuccess(simDispute) || rpc.Api.isSimulationRestore(simDispute)) {
      const nativeCount = simDispute.result?.retval ? scValToNative(simDispute.result.retval) : null
      if (nativeCount !== null && nativeCount !== undefined && Number(nativeCount) > 0) {
        return 'disputed'
      }
    }
  } catch {
    // If get_open_dispute_count fails or is unsupported, keep the status from get_proof_status
  }

  return status
}

