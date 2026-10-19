export type StellarNetwork = 'testnet' | 'public'

const EXPLORER_BASE: Record<StellarNetwork, string> = {
  testnet: 'https://stellar.expert/explorer/testnet',
  public: 'https://stellar.expert/explorer/public',
}

const PUBLIC_PASSPHRASE = 'Public Global Stellar Network ; February 2016'
const TESTNET_PASSPHRASE = 'Test Stellar Network ; September 2015'

/**
 * Map a network passphrase to the stellar.expert network segment.
 * Returns null for unrecognized passphrases (Futurenet, local standalone,
 * garbage) so callers can hide explorer links instead of linking to a
 * broken testnet explorer page.
 */
export function networkFromPassphrase(passphrase: string): StellarNetwork | null {
  if (passphrase === PUBLIC_PASSPHRASE) return 'public'
  if (passphrase === TESTNET_PASSPHRASE) return 'testnet'
  return null
}

export function transactionExplorerUrl(network: StellarNetwork, txHash: string): string {
  return `${EXPLORER_BASE[network]}/tx/${txHash}`
}

export function contractExplorerUrl(network: StellarNetwork, contractId: string): string {
  return `${EXPLORER_BASE[network]}/contract/${contractId}`
}

export function accountExplorerUrl(network: StellarNetwork, publicKey: string): string {
  return `${EXPLORER_BASE[network]}/account/${publicKey}`
}
