import { getNetwork, requestAccess, WatchWalletChanges } from '@stellar/freighter-api'

export type {
  ChainProofRecord,
  IdentityTier,
  ProofHistoryEntry,
  ProofHistoryResult,
  RegisterProofInput,
  RegisterProofResult,
  TxState,
} from './stellarTypes'
export { describeTxState } from './stellarTypes'
export {
  correctProof,
  expireProof,
  getProofByVideoHash,
  getProofHistory,
  getProofHistoryAt,
  getProofHistoryCount,
  getOpenDisputeCount,
  registerProofOnStellar,
  verifyProof,
  getVerifierState,
  CONTRACT_NETWORK_PASSPHRASE,
} from './harpocratesRegistry'
// Re-export for use by wallet hook and guard code.
export { WatchWalletChanges }
export { checkNetworkMatch } from './networkGuard'

export async function connectFreighter() {
  const result = await requestAccess()
  if (result.error) {
    throw new Error(result.error.message)
  }
  return result.address
}

/**
 * Return the network passphrase that the connected Freighter wallet is
 * currently pointed at. Returns an empty string when the extension is
 * unavailable or returns an error so the caller can handle both cases
 * uniformly.
 */
export async function getWalletNetwork(): Promise<string> {
  const result = await getNetwork()
  if (result.error) {
    return ''
  }
  return result.networkPassphrase ?? ''
}
