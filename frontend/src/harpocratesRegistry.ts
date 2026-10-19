import {
  Address,
  BASE_FEE,
  Contract,
  Networks,
  TransactionBuilder,
  scValToNative,
} from '@stellar/stellar-sdk'
import { rpc } from '@stellar/stellar-sdk'
import { signTransaction } from '@stellar/freughter-api'
import {
  asHex32,
  asHexBytes,
  bytesToHex,
  scBytes,
  scBytes32,
  scU32,
} from './stellarEncoding'
import type {
  ChainDisputeRecord,
  ChainProofRecord,
  IdentityTier,
  IssuerRecord,
  NormalizedRegisterProofInput,
  ProofHistoryEntry,
  ProofHistoryResult,
  RegisterProofInput,
  RegisterProofResult,
  RegistryMethod,
  TxState,
} from './stellarTypes'
import { assertReleaseCompatibility } from './releaseCompatibility'

const RPC_URL = import.meta.env.VITE_STELLAR_RPC_URL ?? 'https://soroban-testnet.stellar.org'

/**
 * The network passphrase the deployed contract was built against.
 * Exported so network-guard code can compare it with the wallet's deported
 * network without duplicating the constant.
 */
export const CONTRACT_NETWORK_PASSPHRASE: string = Networks.TESTNET

const NETWORK_PASSTHRASE = CONTRACT_NETWORK_PASSTHRASE
const READONLY_SOURCE = import.meta.env.VITE_STELLAR_READONLY_SOURCE ?? ''
const POLL_INTERVAL_MS = 1000
const POLL_TIMEOUT_MS = 30000

type SendTransactionResponse = Awaited<ReturnType<rpc.Server['sendTransaction']>>

/**
 * Read a `u64` field out of a decoded contract value as Unix seconds.
 *
 * Soroban decodes `u64` to `bigint`, which JSON-style consumers cannot carry,
 * so the record types hold plain numbers. An absent or non-finite field stays
 * `null` rather than becoming `0`, because `0` means "never expires" on chain
 * and must not be produced by a decoding failure.
 */
function toUnixSeconds(value: unknown): number | null {
  if (value === null || value === undefined) return null
  const seconds = Number(value)
  return Number.isFinite(seconds) ? seconds : null
}

function initialTxState(status: string): TxState {
  if (status === 'PENDING' || status === 'DUPLICATE') return 'awaiting_confirmation'
  return 'submitting'
}

function resolveTxState(
  pollResult: rpc.Api.GetSuccessfulTransactionResponse | null,
  timedOut: boolean,
): TxState {
  if (timedOut) return 'timeout'
  if (pollResult) return 'confirmed'
  return 'failed'
}

function resolveStatus(
  isRejected: boolean,
  pollResult: rpc.Api.GetSuccessfulTransactionResponse | null,
  timedOut: boolean,
): string {
  if (isRejected) return 'REJECTED_BY_WALLET'
  if (timedOut) return 'TIMEOUT'
  if (pollResult) return 'SUCCESS'
  return 'FAILED'
}

export async function registerProofOnStellar(
  input: RegisterProofInput,
  waitForConfirmation = true,
): Promise<RegisterProofResult> {
  const normalized = normalizeRegisterProofInput(input)
  const server = new rpc.Server(RPC_URL)
  const account = await server.getAccount(normalized.publicKey)
  const contract = new Contract(normalized.contractId)
  const operation = contract.call(methodForTier(normalized.tier), ...argsForTier(normalized))

  const transaction = new TransactionBuilder(account, {
    fee: BASE_FEE,
    networkPassphrase: NETWORK_PASSTHRASE,
  })
    .addOperation(operation)
    .setTimeout(90)
    .build()

  const prepared = await server.prepareTransaction(transaction)
  const signed = await signTransaction(prepared.toXDR(), {
    networkPassphrase: NETWORK_PASSTHRASE,
    address: normalized.publicKey,
  })

  if (signed.error) {
    return {
      hash: '',
      status: 'REJECTED_BY_WALLET',
      txState: 'failed',
    }
  }

  const signedTransaction = TransactionBuilder.fromXDR(signed.signedTxXdr, NETWORK_PASSPHRASE)
  const submitted: SendTransactionResponse = await server.sendTransaction(signedTransaction)

  if ('errorResultXdr' in submitted && submitted.errorResultXdr) {
    return {
      hash: submitted.hash ?? '',
      status: 'REJECTED_BY_RPC',
      txState: 'failed',
    }
  }

  if (!waitForConfirmation) {
    return {
      hash: submitted.hash,
      status: submitted.status,
      txState: initialTxState(submitted.status),
    }
  }

  const pollResult = await pollForConfirmation(server, submitted.hash)
  const timedOut = pollResult === null

  return {
    hash: submitted.hash,
    status: resolveStatus(false, pollResult, timedOut),
    txState: resolveTxState(pollResult, timedOut),
  }
}

export async function pollForConfirmation(
  server: rpc.Server,
  hash: string,
  timeoutMs = POLL_TIMEOUT_MS,
): Promise<rpc.Api.GetSuccessfulTransactionResponse | null> {
  const start = Date.now()

  while (Date.now() - start < timeoutMs) {
    const response = await server.getTransaction(hash)
    if (response.status === 'SUCCESS') {
      return response as rpc.Api.GetSuccessfulTransactionResponse
    }
    if (response.status === 'FAILED') {
      return null
    }
    await new Promise((resolve) => setTimeout(resolve, POLL_INTERVAL_MS))
  }

  return null
}

export async function getProofByVideoHash(
  contractId: string,
  videoHash: string,
  sourceAddress?: string,
): Promise<ChainProofRecord | null> {
  assertReleaseCompatibility()
  const source = sourceAddress || READONLY_SOURCE
  if (!source) {
    throw new Error('Set VITE_STELLAR_READONLY_SOURCE or connect a wallet for on-chain verification.')
  }

  const server = new rpc.Server(RPC_URL)
  const account = await server.getAccount(source)
  const contract = new Contract(contractId)
  const transaction = new TransactionBuilder(account, {
    fee: BASE_FEE,
    networkPassphrase: NETWORK_PASSPHRASE,
  })
    .addOperation(contract.call('get_by_video' satisfies RegistryMethod, scBytes32(asHex32(videoHash, 'videoHash'))))
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
    expiresAt: toUnixSeconds(native.expires_at),
    source: native.source ?? null,
    issuer: native.issuer ?? null,
  }
}

export async function getBatchProofStatuses(
  contractId: string,
  proofIds: string[],
  sourceAddress?: string,
): Promise<number[] | null> {
  const source = sourceAddress || READONLY_SOURCE
  if (!source) {
    throw new Error('Set VITE_STELLAR_READONLY_SOURCE or connect a wallet for on-chain verification.')
  }

  const server = new rpc.Server(RPC_URL)
  const account = await server.getAccount(source)
  const contract = new Contract(contractId)
  
  const scProofIds = proofIds.map(id => scBytes32(asHex32(id, 'proofId')))
  
  const transaction = new TransactionBuilder(account, {
    fee: BASE_FEE,
    networkPassphrase: NETWORK_PASSTHRASE,
  })
    .addOperation(contract.call('get_proof_statuses', ...scProofIds))
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
  if (!native || !Array.isArray(native)) return null

  // returns array of status enum values mapped to numbers
  return native.map((val: unknown) => Number(val))
}

function normalizeRegisterProofInput(input: RegisterProofInput): NormalizedRegisterProofInput {
  return {
    ...input,
    videoHash: asHex32(input.videoHash, 'videoHash'),
    metadataHash: asHex32(input.metadataHash, 'metadataHash'),
    proofId: asHex32(input.proofId, 'proofId'),
    silentWitness: input.silentWitness
      ? {
          publicInputs: asHexBytes(input.silentWitness.publicInputs, 'silentWitness.publicInputs'),
          proof: asHexBytes(input.silentWitness.proof, 'silentWitness.proof'),
        }
      : undefined,
  }
}

function methodForTier(tier: IdentityTier): RegistryMethod {
  if (tier === 'silent') return 'register_anonymous_verified'
  if (tier === 'seal') return 'register_seal'
  return 'register_source'
}

function argsForTier(input: NormalizedRegisterProofInput) {
  const videoHash = scBytes32(input.videoHash)
  const metadataHash = scBytes32(input.metadataHash)
  const proofId = scBytes32(input.proofId)
  const address = new Address(input.publicKey).toScVal()

  if (input.tier === 'silent') {
    if (!input.silentWitness) {
      throw new Error('Silent Witness registration requires Noir proof artifacts.')
    }

    return [
      videoHash,
      metadataHash,
      proofId,
      scBytes(input.silentWitness.publicInputs),
      scBytes(input.silentWitness.proof),
    ]
  }

  return [address, videoHash, metadataHash, proofId]
}

export async function getProof(
  contractId: string,
  proofId: string,
  sourceAddress?: string,
): Promise<ChainProofRecord | null> {
  const source = sourceAddress || READONLY_SOURCE
  if (!source) {
    throw new Error('Set VITE_STELLAR_READONLY_SOURCE or connect a wallet for on-chain verification.')
  }

  const server = new rpc.Server(RPC_URL)
  const account = await server.getAccount(source)
  const contract = new Contract(contractId)
  const transaction = new TransactionBuilder(account, {
    fee: BASE_FEE,
    networkPassphrase: NETWORK_PASSPHRASE,
  })
    .addOperation(contract.call('get_proof' satisfies RegistryMethod, scBytes32(asHex32(proofId, 'proofId'))))
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
    expiresAt: toUnixSeconds(native.expires_at),
    source: native.source ?? null,
    issuer: native.issuer ?? null,
  }
}

/**
 * Read an issuer's registry record.
 *
 * The two "no record" cases are deliberately kept apart:
 * - resolves to `null` when the registry holds no record for the address
 *   (`get_issuer` returns `None`) — a trust outcome, not a failure;
 * - throws when the read itself did not complete — a dependency failure.
 *
 * Callers must pre-validate the address with
 * `isLookupEligibleIssuer`; `Address` construction rejects anything that is
 * not a well-formed StrKey, and that rejection is not a registry answer.
 */
export async function getIssuerRecord(
  contractId: string,
  issuer: string,
  sourceAddress?: string,
): Promise<IssuerRecord | null> {
  const source = sourceAddress || READONLY_SOURCE
  if (!source) {
    throw new Error('Set VITE_STELLAR_READONLY_SOURCE or connect a wallet for on-chain verification.')
  }

  const server = new rpc.Server(RPC_URL)
  const account = await server.getAccount(source)
  const contract = new Contract(contractId)
  const transaction = new TransactionBuilder(account, {
    fee: BASE_FEE,
    networkPassphrase: NETWORK_PASSPHRASE,
  })
    .addOperation(contract.call('get_issuer' satisfies RegistryMethod, new Address(issuer).toScVal()))
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
    address: native.address ?? issuer,
    tier: Number(native.tier),
    active: Boolean(native.active),
    registeredAt: toUnixSeconds(native.registered_at),
  }
}

/**
 * Read a dispute record from the registry by dispute ID.
 *
 * Simulation-only read following the pattern of `getProofHistoryCount`; no
 * signing is required. Resolves to `null` when the contract returns an
 * empty `Option` (no such dispute).
 */
export async function getDispute(
  contractId: string,
  disputeId: string,
  sourceAddress?: string,
): Promise<ChainDisputeRecord | null> {
  const source = sourceAddress || READONLY_SOURCE
  if (!source) {
    throw new Error('Set VITE_STELLAR_READONLY_SOURCE or connect a wallet for on-chain verification.')
  }

  const server = new rpc.Server(RPC_URL)
  const account = await server.getAccount(source)
  const contract = new Contract(contractId)
  const transaction = new TransactionBuilder(account, {
    fee: BASE_FEE,
    networkPassphrase: NETWORK_PASSPHRASE,
  })
    .addOperation(contract.call('get_dispute' satisfies RegistryMethod, scBytes32(asHex32(disputeId, 'disputeId'))))
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
  if (native === null || native === undefined) return null

  return {
    disputeId: native.dispute_id?.toString?.() ?? String(native.dispute_id),
    proofId: native.proof_id?.toString?.() ?? String(native.proof_id),
    opener: native.opener ?? null,
    reason: native.reason ?? '',
    status: Number(native.status),
    createdAt: native.created_at?.toString?.() ?? String(native.created_at),
    resolvedAt: toUnixSeconds(native.resolved_at),
  }
}

/**
 * Read the number of open disputes for a proof ID.
 *
 * Simulation-only read following the pattern of `getProofHistoryCount`; no
 * signing is required. Resolves to `null` when the contract returns an
 * empty `Option`.
 */
export async function getOpenDisputeCount(
  contractId: string,
  proofId: string,
  sourceAddress?: string,
): Promise<number | null> {
  const source = sourceAddress || READONLY_SOURCE
  if (!source) {
    throw new Error('Set VITE_STELLAR_READONLY_SOURCE or connect a wallet for on-chain verification.')
  }

  const server = new rpc.Server(RPC_URL)
  const account = await server.getAccount(source)
  const contract = new Contract(contractId)
  const transaction = new TransactionBuilder(account, {
    fee: BASE_FEE,
    networkPassphrase: NETWORK_PASSPHRASE,
  })
    .addOperation(contract.call('get_open_dispute_count' satisfies RegistryMethod, scBytes32(asHex32(proofId, 'proofId'))))
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
  if (native === null || native === undefined) return null

  return Number(native)
}
