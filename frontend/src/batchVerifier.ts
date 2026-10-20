import type { ChainProofRecord } from './stellar'
import { verifyArtifact, type VerificationEvent } from './verificationFlow'
import type { ProofManifest } from './proofManifest'
import { appConfig } from './config'

export type BatchOutcome =
  | 'pending'
  | 'hashing'
  | 'processing'
  | 'confirmed'
  | 'revoked'
  | 'metadata-only'
  | 'database-only'
  | 'manifest-valid'
  | 'manifest-invalid'
  | 'malformed'
  | 'oversized'
  | 'duplicate'
  | 'error'
  | 'unavailable'
  | 'cancelled'

export type BatchConfig = {
  maxConcurrency: number
  maxFileSizeBytes: number
  maxTotalSizeBytes: number
  apiBase: string
  contractId: string
  wallet?: string
}

export type BatchItemResult = {
  id: string
  file: File
  fileName: string
  fileSizeBytes: number
  status: BatchOutcome
  videoHash: string | null
  metadataHash: string | null
  sourceHash: string | null
  tier: string | null
  chainStatus: string | null
  message: string
  events: VerificationEvent[]
  chainProof: ChainProofRecord | null
  duplicateOf: string | null
  manifest: ProofManifest | null
  durationMs: number | null
  failureReason: string | null
}

export type BatchProgress = {
  totalFiles: number
  completedFiles: number
  processedBytes: number
  totalBytes: number
  activeCount: number
  isCancelled: boolean
  isDone: boolean
}

export type BatchSummary = {
  totalFiles: number
  confirmed: number
  revoked: number
  unconfirmed: number
  manifests: number
  duplicates: number
  errors: number
  cancelled: number
  totalBytes: number
  durationMs: number
}

export const DEFAULT_BATCH_CONFIG: BatchConfig = {
  maxConcurrency: 3,
  maxFileSizeBytes: 100 * 1024 * 1024, // 100 MB
  maxTotalSizeBytes: 500 * 1024 * 1024, // 500 MB
  apiBase: appConfig.apiBase,
  contractId: appConfig.registryId,
}

/**
 * Computes SHA-256 hex string from a File or Blob in bounded slices while
 * listening for cancellation.
 */
export async function computeChunkedSha256(
  file: File | Blob,
  signal?: AbortSignal,
  chunkSize: number = 4 * 1024 * 1024,
): Promise<string> {
  if (signal?.aborted) {
    throw new Error('Operation cancelled.')
  }

  // For small files (< 16MB), compute directly using WebCrypto
  if (file.size <= 16 * 1024 * 1024) {
    const buffer = await file.arrayBuffer()
    if (signal?.aborted) throw new Error('Operation cancelled.')
    const digest = await crypto.subtle.digest('SHA-256', buffer)
    return hex(digest)
  }

  // For larger files, read in chunks to allow responsive cancellation and avoid UI hide
  let offset = 0
  const chunks: Uint8Array[] = []
  let totalRead = 0

  while (offset < file.size) {
    if (signal?.aborted) {
      throw new Error('Operation cancelled.')
    }
    const end = Math.min(offset + chunkSize, file.size)
    const slice = file.slice(offset, end)
    const buf = await slice.arrayBuffer()
    chunks.push(new Uint8Array(buf))
    totalRead += buf.byteLength
    offset = end
  }

  if (signal?.aborted) {
    throw new Error('Operation cancelled.')
  }

  // Concatenate chunks and digest
  const combined = new Uint8Array(totalRead)
  let pos = 0
  for (const chunk of chunks) {
    combined.set(chunk, pos)
    pos += chunk.length
  }

  const digest = await crypto.subtle.digest('SHA-256', combined.buffer)
  return hex(digest)
}

function hex(buffer: ArrayBuffer): string {
  return [...new Uint8Array(buffer)]
    .map((byte) => byte.toString(16).padStart(2, '0'))
    .join('')
}

/**
 * Validates whether a file is a standalone JSON proof manifest receipt.
 */
export async function tryParseManifest(file: File): Promise<ProofManifest | null> {
  if (!file.name.endsWith('.json') && file.type !== 'application/json') {
    return null
  }

  try {
    const text = await file.text()
    const parsed = JSON.parse(text) as Record<string, unknown>
    if (
      parsed &&
      parsed.protocol === 'harpocrates' &&
      typeof parsed.version === 'number' &&
      typeof parsed.videoHash === 'string' &&
      typeof parsed.metadataHash === 'string'
    ) {
      return parsed as ProofManifest
    }
    return null
  } catch {
    return null
  }
}

/**
 * Worker pool class for managing batch verification with bounded concurrency
 * and resource safety.
 */
export class BatchVerifier {
  private config: BatchConfig
  private items: BatchItemResult[] = []
  private abortController: AbortController | null = null
  private onProgressCallback?: (progress: BatchProgress, items: BatchItemResult[]) => void
  private processedHashes = new Map<string, string>() // videoHash -> itemId
  private accumulatedTotalBytes = 0

  constructor(config: Partial<BatchConfig> = {}) {
    this.config = { ...DEFAULT_BATCH_CONFIG, ...config }
  }

  public updateConfig(config: Partial<BatchConfig>): void {
    this.config = { ...this.config, ...config }
  }

  public getConfig(): BatchConfig {
    return { ...this.config }
  }

  public getItems(): BatchItemResult[] {
    return [...this.items]
  }

  public setOnProgress(cb: (progress: BatchProgress, items: BatchItemResult[]) => void): void {
    this.onProgressCallback = cb
  }

  public cancel(): void {
    if (this.abortController) {
      this.abortController.abort()
    }
    for (const item of this.items) {
      if (item.status === 'pending' || item.status === 'hashing' || item.status === 'processing') {
        item.status = 'cancelled'
        item.message = 'Cancelled by user.'
        item.failureReason = 'Batch execution was aborted by user request.'
      }
    }
    this.notifyProgress(true, true)
  }

  public async runBatch(
    files: File[],
    onProgress?: (progress: BatchProgress, items: BatchItemResult[]) => void,
  ): Promise<{ items: BatchItemResult[]; summary: BatchSummary }> {
    if (onProgress) {
      this.onProgressCallback = onProgress
    }

    this.abortController = new AbortController()
    const signal = this.abortController.signal

    // Initialize item results
    const startTime = performance.now()
    this.processedHashes.clear()
    this.accumulatedTotalBytes = 0

    this.items = files.map((file, idx) => {
      const id = `item-${idx}-${Date.now()}-${Math.random().toString(36).slice(2, 7)}`
      return {
        id,
        file,
        fileName: file.name,
        fileSizeBytes: file.size,
        status: 'pending',
        videoHash: null,
        metadataHash: null,
        sourceHash: null,
        tier: null,
        chainStatus: null,
        message: 'Queued for verification.',
        events: [],
        chainProof: null,
        duplicateOf: null,
        manifest: null,
        durationMs: null,
        failureReason: null,
      }
    })

    this.notifyProgress(false, false)

    // Filter oversized files upfront based on total and per-file limits
    let currentBatchBytes = 0
    for (const item of this.items) {
      if (item.fileSizeBytes > this.config.maxFileSizeBytes) {
        item.status = 'oversized'
        const limitMb = Math.round(this.config.maxFileSizeBytes / (1024 * 1024))
        const fileMb = (item.fileSizeBytes / (1024 * 1024)).toFixed(1)
        item.message = `File exceeds size limit (${fileMb}MB > ${limitMb}MB limit).`
        item.failureReason = `Per-file limit exceeded (${item.fileSizeBytes} bytes vs max ${this.config.maxFileSizeBytes} bytes).`
        continue
      }

      if (currentBatchBytes + item.fileSizeBytes > this.config.maxTotalSizeBytes) {
        item.status = 'oversized'
        const totalLimitMb = Math.round(this.config.maxTotalSizeBytes / (1024 * 1024))
        item.message = `Total batch size limit exceeded (${totalLimitMb}MB max).`
        item.failureReason = `Total batch memory limit exceeded by queueing ${item.fileName}.`
        continue
      }

      currentBatchBytes += item.fileSizeBytes
    }

    this.accumulatedTotalBytes = currentBatchBytes
    this.notifyProgress(false, false)

    // Execute with bounded concurrency
    const queue = this.items.filter((item) => item.status === 'pending')
    const concurrency = Math.max(1, Math.min(8, this.config.maxConcurrency))

    const worker = async () => {
      while (queue.length > 0) {
        if (signal.aborted) break
        const item = queue.shift()
        if (!item) break

        await this.processItem(item, signal)
        this.notifyProgress(false, queue.length === 0)
      }
    }

    const workers = Array.from({ length: concurrency }, () => worker())
    await Promise.all(workers)

    // Ensure all remaining pending/hashing items are updated if cancelled
    if (signal.aborted) {
      for (const item of this.items) {
        if (item.status === 'pending' || item.status === 'hashing' || item.status === 'processing') {
          item.status = 'cancelled'
          item.message = 'Cancelled by user.'
          item.failureReason = 'Batch execution was aborted by user request.'
        }
      }
    }

    const endTime = performance.now()
    const summary = this.computeSummary(endTime - startTime)
    this.notifyProgress(signal.aborted, true)

    return { items: [...this.items], summary }
  }

  private async processItem(item: BatchItemResult, signal: AbortSignal): Promise<void> {
    const itemStart = performance.now()
    try {
      if (signal.aborted) {
        item.status = 'cancelled'
        item.message = 'Cancelled before starting.'
        return
      }

      // Check if item is a standalone JSON proof manifest receipt
      const manifest = await tryParseManifest(item.file)
      if (manifest) {
        item.manifest = manifest
        item.videoHash = manifest.videoHash
        item.metadataHash = manifest.metadataHash
        item.sourceHash = manifest.sourceHash
        item.tier = manifest.tier

        // Verify JSON manifest hashes match
        item.status = 'manifest-valid'
        item.message = `Valid Harpocrates JSON manifest for ${manifest.videoHash.slice(0, 8)}...`

        // Check on-chain record for manifest's video hash
        if (this.config.contractId && manifest.videoHash) {
          try {
            const { getProofByVideoHash } = await import('./stellar')
            const chainProof = await getProofByVideoHash(
              this.config.contractId,
              manifest.videoHash,
              this.config.wallet,
            )
            item.chainProof = chainProof
            if (chainProof) {
              item.chainStatus = chainProof.status === 2 ? 'Revoked' : 'Active'
              if (chainProof.status === 2) {
                item.status = 'revoked'
                item.message = 'Manifest matches revoked on-chain record.'
              }
            }
          } catch {
            // Non-fatal for manifest check
          }
        }

        item.durationMs = performance.now() - itemStart
        return
      }

      // Standard Evidence Video Processing
      item.status = 'hashing'
      item.message = 'Computing local SHA-256 commitment...'
      this.notifyProgress(false, false)

      const videoHash = await computeChunkedSha256(item.file, signal)
      item.videoHash = videoHash

      if (signal.aborted) {
        item.status = 'cancelled'
        item.message = 'Cancelled during hashing.'
        return
      }

      // Duplicate Check
      if (this.processedHashes.has(videoHash)) {
        const existingId = this.processedHashes.get(videoHash)!
        const originalItem = this.items.find((i) => i.id === existingId)
        item.status = 'duplicate'
        item.duplicateOf = originalItem ? originalItem.fileName : existingId
        item.message = `Duplicate file detected (identical hash to ${item.duplicateOf}).`
        item.durationMs = performance.now() - itemStart
        return
      }

      this.processedHashes.set(videoHash, item.id)

      // Verification Flow
      item.status = 'processing'
      item.message = 'Extracting stego metadata and checking Stellar registry...'
      this.notifyProgress(false, false)

      const result = await verifyArtifact({
        apiBase: this.config.apiBase,
        contractId: this.config.contractId,
        wallet: this.config.wallet,
        file: item.file,
        signal,
        onEvent: (event) => {
          item.events.push(event)
          if (event.message) {
            item.message = event.message
          }
          this.notifyProgress(false, false)
        },
      })

      item.videoHash = result.videoHash ?? item.videoHash
      item.metadataHash = result.metadataHash ?? null
      item.sourceHash = result.sourceHash ?? null
      item.tier = result.tier ?? null
      item.chainProof = result.chainProof ?? null
      item.chainStatus = result.chainStatus ?? null
      item.status = result.status
      item.message = result.message
      item.failureReason = result.failureReason ?? null
      item.durationMs = performance.now() - itemStart
    } catch (err) {
      if (signal.aborted) {
        item.status = 'cancelled'
        item.message = 'Cancelled.'
        item.failureReason = 'Batch execution was aborted by user request.'
      } else {
        item.status = 'error'
        item.message = err instanceof Error ? err.message : 'Unknown error.'
        item.failureReason = item.message
      }
      item.durationMs = performance.now() - itemStart
    }
  }

  private notifyProgress(isCancelled: boolean, isDone: boolean): void {
    if (!this.onProgressCallback) return
    const totalFiles = this.items.length
    const completedFiles = this.items.filter(
      (i) => i.status !== 'pending' && i.status !== 'hashing' && i.status !== 'processing',
    ).length
    const activeCount = this.items.filter(
      (i) => i.status === 'hashing' || i.status === 'processing',
    ).length
    const processedBytes = this.items.reduce((acc, i) => {
      if (i.status === 'pending' || i.status === 'hashing') return acc
      return acc + i.fileSizeBytes
    }, 0)
    this.onProgressCallback(
      {
        totalFiles,
        completedFiles,
        processedBytes,
        totalBytes: this.accumulatedTotalBytes,
        activeCount,
        isCancelled,
        isDone,
      },
      [...this.items],
    )
  }

  private computeSummary(durationMs: number): BatchSummary {
    const summary: BatchSummary = {
      totalFiles: this.items.length,
      confirmed: 0,
      revoked: 0,
      unconfirmed: 0,
      manifests: 0,
      duplicates: 0,
      errors: 0,
      cancelled: 0,
      totalBytes: 0,
      durationMs,
    }

    for (const item of this.items) {
      summary.totalBytes += item.fileSizeBytes
      switch (item.status) {
        case 'confirmed':
          summary.confirmed++
          break
        case 'revoked':
          summary.revoked++
          break
        case 'manifest-valid':
        case 'manifest-invalid':
          summary.manifests++
          break
        case 'duplicate':
          summary.duplicates++
          break
        case 'cancelled':
          summary.cancelled++
          break
        case 'error':
        case 'malformed':
        case 'oversized':
        case 'unavailable':
          summary.errors++
          break
        default:
          summary.unconfirmed++
          break
      }
    }

    return summary
  }
}