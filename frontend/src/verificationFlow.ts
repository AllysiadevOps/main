import type { ChainProofRecord } from './stellar'
import { fetchProofEventsByVideo } from './services/verificationService'

export type VerificationEvent = {
  id: number
  event_type: string
  file_name: string | null
  video_hash: string | null
  proof_id: string | null
  tier: string | null
  tx_hash?: string | null
  tx_status?: string | null
  created_at: string
}

export type VerificationOutcome =
  | 'confirmed'
  | 'metadata-only'
  | 'database-only'
  | 'revoked'
  | 'malformed'
  | 'unavailable'

export type VerificationResult = {
  outcome: VerificationOutcome
  message: string
  events: VerificationEvent[]
  chainProof: ChainProofRecord | null
}

type VerifyArtifactInput = {
  apiBase: string
  contractId: string
  file: File
  videoHash: string
  wallet?: string
  signal?: AbortSignal
}

class MalformedEvidenceError extends Error {}
const REVOKED_CHAIN_STATUS = 2

export async function verifyArtifact({
  apiBase,
  contractId,
  file,
  videoHash,
  wallet,
  signal,
}: VerifyArtifactInput): Promise<VerificationResult> {
  try {
    const metadata = await extractMetadata(apiBase, file)
    const [events, chainProof] = await Promise.all([
      fetchProofEventsByVideo(videoHash, signal, apiBase),
      fetchChainProof(contractId, videoHash, wallet),
    ])

    return classifyVerification(metadata, events, chainProof)
  } catch (error) {
    if (error instanceof MalformedEvidenceError) {
      return {
        outcome: 'malformed',
        message:
          'Malformed evidence: embedded metadata could not be parsed. Do not treat this artifact as verified.',
        events: [],
        chainProof: null,
      }
    }

    return {
      outcome: 'unavailable',
      message: 'Verification services are unavailable. No trust decision was made.',
      events: [],
      chainProof: null,
    }
  }
}

async function extractMetadata(_apiBase: string, file: File): Promise<unknown> {
  const { extractMetadata: extractMetadataLocal, MalformedEvidenceError: StegoError } = await import('./stego')
  try {
    return await extractMetadataLocal(file)
  } catch (err) {
    if (err instanceof StegoError) {
      throw new MalformedEvidenceError()
    }
    throw err
  }
}

async function fetchChainProof(contractId: string, videoHash: string, wallet?: string) {
  if (!contractId) return null

  const { getProofByVideoHash } = await import('./stellar')
  return getProofByVideoHash(contractId, videoHash, wallet)
}

function classifyVerification(
  metadata: unknown,
  events: VerificationEvent[],
  chainProof: ChainProofRecord | null,
): VerificationResult {
  const hasMetadata =
    !!metadata &&
    typeof metadata === 'object' &&
    (metadata as { protocol?: unknown }).protocol === 'harpocrates'

  if (chainProof?.status === REVOKED_CHAIN_STATUS) {
    return {
      outcome: 'revoked',
      message:
        'Revoked: the chain record for this artifact has been revoked. Do not trust it as valid evidence.',
      events,
      chainProof,
    }
  }

  if (hasMetadata && events.length > 0 && chainProof) {
    return {
      outcome: 'confirmed',
      message:
        'Confirmed: embedded Harpocrates metadata is corroborated by database and active chain records.',
      events,
      chainProof,
    }
  }

  if (hasMetadata) {
    return {
      outcome: 'metadata-only',
      message:
        'Metadata only: embedded Harpocrates metadata lacks complete database and chain confirmation. Treat this artifact as unconfirmed.',
      events,
      chainProof,
    }
  }

  if (events.length > 0) {
    return {
      outcome: 'database-only',
      message:
        'Database record only: no valid embedded Harpocrates metadata or chain record was found. Treat this artifact as unconfirmed.',
      events,
      chainProof,
    }
  }

  return {
    outcome: 'metadata-only',
    message:
      'No verification evidence found: metadata, database, and chain records did not confirm this artifact. Treat it as unverified.',
    events,
    chainProof,
  }
}
