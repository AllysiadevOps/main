/**
 * useWallet — manages Freighter wallet connection and network validation.
 *
 * Network guard behaviour:
 *   1. On initial connect: `checkNetworkMatch` is called; mismatch sets
 *      `networkMismatch` and re-throws so the caller can surface a banner.
 *   2. While connected: `WatchWalletChanges` polls every 3 s and re-validates
 *      network/account changes. On a mid-session network switch the mismatch
 *      banner is raised and the wallet address is cleared until the user
 *      reconnects on the correct network.
 *
 * Privacy notes:
 *   - `networkMismatch` contains only human-readable network names (e.g.
 *     "Mainnet", "Testnet"); wallet addresses, private keys, and proof bytes
 *     are never included in the mismatch message.
 *   - The watcher is stopped on unmount and on disconnect.
 */

import { useCallback, useEffect, useRef, useState } from 'react'

export type UseWalletReturn = {
  wallet: string
  networkMismatch: string | null
  connectWallet: () => Promise<void>
  disconnectWallet: () => void
}

const WATCHER_UNAVAILABLE_MESSAGE =
  'Freighter became unavailable. Unlock the extension and reconnect your wallet.'
const WATCHER_ADDRESS_UNAVAILABLE_MESSAGE =
  'Freighter did not return a wallet address. Unlock the extension and reconnect.'

type WalletChangeEvent = {
  address: string
  networkPassphrase: string
  error?: unknown
}

type WalletWatcher = {
  stop: () => void
  watch: (callback: (event: WalletChangeEvent) => void) => unknown
}

export function useWallet(): UseWalletReturn {
  const [wallet, setWallet] = useState('')
  const [networkMismatch, setNetworkMismatch] = useState<string | null>(null)

  // Keep refs for the active watcher and connection attempt so callbacks from
  // an old wallet session cannot mutate the current session.
  const watcherRef = useRef<WalletWatcher | null>(null)
  const connectionAttemptRef = useRef(0)
  const mountedRef = useRef(true)

  const stopWatcher = useCallback(() => {
    watcherRef.current?.stop()
    watcherRef.current = null
  }, [])

  const disconnectWallet = useCallback(() => {
    connectionAttemptRef.current += 1
    stopWatcher()
    setWallet('')
    setNetworkMismatch(null)
  }, [stopWatcher])

  async function connectWallet() {
    const attempt = ++connectionAttemptRef.current
    stopWatcher()
    setWallet('')
    setNetworkMismatch(null)

    const isCurrentAttempt = () =>
      mountedRef.current && connectionAttemptRef.current === attempt

    try {
      const stellar = await import('../stellar')
      const { connectFreighter, getWalletNetwork, CONTRACT_NETWORK_PASSPHRASE, WatchWalletChanges } = stellar
      const { checkNetworkMatch } = await import('../networkGuard')

      const publicKey = await connectFreighter()
      if (!isCurrentAttempt()) return

      // Store the address before the network check so the existing UI can show
      // a truncated address while presenting a mismatch remediation message.
      setWallet(publicKey)

      const walletPassphrase = await getWalletNetwork()
      if (!isCurrentAttempt()) return

      const check = checkNetworkMatch(walletPassphrase, CONTRACT_NETWORK_PASSPHRASE)
      if (!check.ok) {
        setNetworkMismatch(`${check.reason} ${check.remediation}`)
        throw new Error(check.reason)
      }

      let watcher: WalletWatcher | null = null
      try {
        watcher = new WatchWalletChanges(3000) as WalletWatcher
        const activeWatcher = watcher
        watcherRef.current = activeWatcher
        activeWatcher.watch(({ address, networkPassphrase, error }) => {
          // Ignore callbacks from a stopped watcher or a superseded connection
          // attempt. Freighter may deliver one final event during teardown.
          if (!isCurrentAttempt() || watcherRef.current !== activeWatcher) return

          if (error) {
            setNetworkMismatch(WATCHER_UNAVAILABLE_MESSAGE)
            setWallet('')
            return
          }

          const result = checkNetworkMatch(networkPassphrase, CONTRACT_NETWORK_PASSPHRASE)
          if (!result.ok) {
            setNetworkMismatch(`${result.reason} ${result.remediation}`)
            setWallet('')
            return
          }

          if (!address) {
            setNetworkMismatch(WATCHER_ADDRESS_UNAVAILABLE_MESSAGE)
            setWallet('')
            return
          }

          // The wallet is healthy again. Restore the address and clear the
          // banner without requiring a full page reload or manual reconnect.
          setWallet(address)
          setNetworkMismatch(null)
        })
      } catch (error) {
        if (watcherRef.current === watcher) watcherRef.current = null
        throw error
      }
    } catch (error) {
      // Preserve the original Freighter error for callers while ensuring a
      // superseded attempt cannot surface stale state or a new error message.
      if (isCurrentAttempt()) throw error
    }
  }

  // Stop the watcher when the hook unmounts (component teardown).
  useEffect(() => {
    mountedRef.current = true
    return () => {
      mountedRef.current = false
      connectionAttemptRef.current += 1
      stopWatcher()
    }
  }, [stopWatcher])

  return { wallet, networkMismatch, connectWallet, disconnectWallet }
}
