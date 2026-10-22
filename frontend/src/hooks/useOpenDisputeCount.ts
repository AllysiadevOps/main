import { useEffect, useState } from 'react'
import { getOpenDisputeCount } from '../stellar'
import { emitScrubbedTelemetry } from '../telemetry'

const REGISTRY_CONTRACT_ID = import.meta.env.VITE_HARPOCRATES_REGISTRY_ID ?? ''

type Settled = {
  key: string
  count: number | null
}

const EMPTY: Settled = { key: '', count: null }

type Options = {
  proofId: string | null | undefined
  sourceAddress?: string
  contractId?: string
}

/**
 * Open dispute count for a proof, read from the registry.
 *
 * Resolves to `null` while loading, when there is nothing to look up, and
 * when the read fails. A failed read is logged through the telemetry
 * scrubber (error class only, never the proof id or RPC payload) and the
 * caller simply omits the dispute notice.
 */
export function useOpenDisputeCount({
  proofId,
  sourceAddress,
  contractId = REGISTRY_CONTRACT_ID,
}: Options): number | null {
  const [settled, setSettled] = useState(EMPTY)
  const lookupKey = proofId && contractId
    ? `${contractId}|${proofId}|${sourceAddress ?? ''}`
    : ''

  useEffect(() => {
    if (!lookupKey || !proofId) return

    let cancelled = false
    void (async () => {
      let count: number | null = null
      try {
        count = await getOpenDisputeCount(contractId, proofId, sourceAddress)
      } catch (error) {
        emitScrubbedTelemetry('warn', 'provenance.dispute_count_unavailable', {
          reason: error instanceof Error ? error.name : 'unknown',
        })
      }

      if (!cancelled) setSettled({ key: lookupKey, count })
    })()

    return () => {
      cancelled = true
    }
  }, [lookupKey, proofId, contractId, sourceAddress])

  if (!lookupKey || settled.key !== lookupKey) return null
  return settled.count
}
