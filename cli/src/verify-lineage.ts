import type { LineageRecord, ProofStatus } from './stellar-lookup.js'

export const MAX_LINEAGE_DEPTH = 4
export const MAX_LINEAGE_FANOUT = 4

export type LineageNode = {
  digest: string
  type: 'derivative' | 'original'
  status?: ProofStatus
  operationType?: string
  depth: number
  parents: LineageNode[]
  error?: string
}

export type LineageTreeResult = {
  root: LineageNode
  success: boolean
  failureReason?: string
  revokedCount: number
  expiredCount: number
  disputedCount: number
  missingCount: number
  cycleDetected: boolean
}

export interface LineageFetcher {
  getLineage(outputDigest: string): Promise<LineageRecord | null>
  getProofStatus(proofId: string): Promise<ProofStatus>
}

/**
 * Recursively verify a derivative's full lineage back to registered originals.
 */
export async function verifyLineageTree(
  outputDigest: string,
  fetcher: LineageFetcher,
  options: {
    maxDepth?: number
    maxFanout?: number
  } = {},
): Promise<LineageTreeResult> {
  const maxDepth = options.maxDepth ?? MAX_LINEAGE_DEPTH
  const maxFanout = options.maxFanout ?? MAX_LINEAGE_FANOUT

  const normalizedRoot = outputDigest.toLowerCase()
  let revokedCount = 0
  let expiredCount = 0
  let disputedCount = 0
  let missingCount = 0
  let cycleDetected = false

  async function walk(
    currentDigest: string,
    currentDepth: number,
    ancestorPath: Set<string>,
  ): Promise<LineageNode> {
    const digest = currentDigest.toLowerCase()

    if (ancestorPath.has(digest)) {
      cycleDetected = true
      return {
        digest,
        type: 'derivative',
        depth: currentDepth,
        parents: [],
        error: 'cycle detected',
      }
    }

    if (currentDepth > maxDepth) {
      return {
        digest,
        type: 'derivative',
        depth: currentDepth,
        parents: [],
        error: `depth bound exceeded (> ${maxDepth})`,
      }
    }

    // Try fetching lineage record for this digest
    let lineage: LineageRecord | null
    try {
      lineage = await fetcher.getLineage(digest)
    } catch (err) {
      // If fetching lineage fails with an error, record error
      return {
        digest,
        type: 'derivative',
        depth: currentDepth,
        parents: [],
        error: `failed to query lineage: ${err instanceof Error ? err.message : String(err)}`,
      }
    }

    if (!lineage) {
      // It's a leaf / original proof. Look up its proof status.
      let status: ProofStatus
      try {
        status = await fetcher.getProofStatus(digest)
      } catch {
        status = 'missing'
      }

      if (status === 'revoked') revokedCount++
      else if (status === 'expired') expiredCount++
      else if (status === 'disputed') disputedCount++
      else if (status === 'missing') missingCount++

      return {
        digest,
        type: 'original',
        status,
        depth: currentDepth,
        parents: [],
      }
    }

    // It's a derivative
    const parents = lineage.parentProofIds ?? []
    if (parents.length > maxFanout) {
      return {
        digest,
        type: 'derivative',
        operationType: lineage.operationType,
        depth: currentDepth,
        parents: [],
        error: `fan-out bound exceeded (${parents.length} > ${maxFanout})`,
      }
    }

    const nextAncestorPath = new Set(ancestorPath)
    nextAncestorPath.add(digest)

    const childNodes: LineageNode[] = []
    for (const parentId of parents) {
      const childNode = await walk(parentId, currentDepth + 1, nextAncestorPath)
      childNodes.push(childNode)
    }

    return {
      digest,
      type: 'derivative',
      operationType: lineage.operationType,
      depth: currentDepth,
      parents: childNodes,
    }
  }

  const root = await walk(normalizedRoot, 0, new Set())

  // Determine if overall verification passed
  // Exit non-zero if any ancestor is revoked, expired, disputed, missing, or if cycle / bound error occurred
  let hasError = false
  function checkErrors(node: LineageNode): void {
    if (node.error) hasError = true
    if (node.status && node.status !== 'valid') hasError = true
    for (const p of node.parents) {
      checkErrors(p)
    }
  }
  checkErrors(root)

  const success = !hasError && !cycleDetected && revokedCount === 0 && expiredCount === 0 && disputedCount === 0 && missingCount === 0

  let failureReason: string | undefined
  if (!success) {
    const reasons: string[] = []
    if (cycleDetected) reasons.push('cycle detected in lineage graph')
    if (revokedCount > 0) reasons.push(`${revokedCount} ancestor(s) revoked`)
    if (expiredCount > 0) reasons.push(`${expiredCount} ancestor(s) expired`)
    if (disputedCount > 0) reasons.push(`${disputedCount} ancestor(s) disputed`)
    if (missingCount > 0) reasons.push(`${missingCount} ancestor(s) missing or unregistered`)
    if (hasError && reasons.length === 0) reasons.push('lineage tree contains errors or bound violations')
    failureReason = reasons.join('; ')
  }

  return {
    root,
    success,
    failureReason,
    revokedCount,
    expiredCount,
    disputedCount,
    missingCount,
    cycleDetected,
  }
}

/**
 * Format a lineage tree into human-readable text representation.
 * Guarantees no metadata contents are printed, only digests, types, and status.
 */
export function formatLineageTree(root: LineageNode): string {
  const lines: string[] = []

  function renderNode(node: LineageNode, prefix: string, isLast: boolean, isRoot: boolean): void {
    const branch = isRoot ? '' : isLast ? '└── ' : '├── '
    const nextPrefix = isRoot ? '' : prefix + (isLast ? '    ' : '│   ')

    let details =
      node.type === 'derivative'
        ? `(derivative: ${node.operationType ?? 'unknown'})`
        : `(original: ${node.status ?? 'unknown'})`

    if (node.error) {
      details += ` [ERROR: ${node.error}]`
    }

    lines.push(`${prefix}${branch}${node.digest} ${details}`)

    for (let i = 0; i < node.parents.length; i++) {
      const child = node.parents[i]
      const last = i === node.parents.length - 1
      renderNode(child, nextPrefix, last, false)
    }
  }

  renderNode(root, '', true, true)
  return lines.join('\n')
}
