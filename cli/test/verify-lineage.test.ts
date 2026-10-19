import { describe, it, expect, vi } from 'vitest'
import {
  verifyLineageTree,
  formatLineageTree,
  type LineageFetcher,
  MAX_LINEAGE_DEPTH,
  MAX_LINEAGE_FANOUT,
} from '../src/verify-lineage.js'
import type { LineageRecord, ProofStatus } from '../src/stellar-lookup.js'

describe('verifyLineageTree', () => {
  it('correctly verifies a multi-level lineage fixture back to registered originals', async () => {
    // Tree topology:
    // root (derivative)
    //   -> mid1 (derivative)
    //        -> leaf1 (original, valid)
    //        -> leaf2 (original, valid)
    //   -> mid2 (derivative)
    //        -> leaf3 (original, valid)
    const lineages: Record<string, LineageRecord> = {
      root_digest: {
        parentProofIds: ['mid1_digest', 'mid2_digest'],
        parentCommitments: ['c1', 'c2'],
        manifestDigest: 'm_root',
        actor: 'GACTOR',
        operationType: 'compose',
        outputDigest: 'root_digest',
        depth: 2,
      },
      mid1_digest: {
        parentProofIds: ['leaf1_proof', 'leaf2_proof'],
        parentCommitments: ['c3', 'c4'],
        manifestDigest: 'm_mid1',
        actor: 'GACTOR',
        operationType: 'crop',
        outputDigest: 'mid1_digest',
        depth: 1,
      },
      mid2_digest: {
        parentProofIds: ['leaf3_proof'],
        parentCommitments: ['c5'],
        manifestDigest: 'm_mid2',
        actor: 'GACTOR',
        operationType: 'blur',
        outputDigest: 'mid2_digest',
        depth: 1,
      },
    }

    const proofs: Record<string, ProofStatus> = {
      leaf1_proof: 'valid',
      leaf2_proof: 'valid',
      leaf3_proof: 'valid',
    }

    const fetcher: LineageFetcher = {
      getLineage: vi.fn(async (digest) => lineages[digest] ?? null),
      getProofStatus: vi.fn(async (proofId) => proofs[proofId] ?? 'missing'),
    }

    const result = await verifyLineageTree('root_digest', fetcher)

    expect(result.success).toBe(true)
    expect(result.failureReason).toBeUndefined()
    expect(result.revokedCount).toBe(0)
    expect(result.expiredCount).toBe(0)
    expect(result.disputedCount).toBe(0)
    expect(result.missingCount).toBe(0)
    expect(result.cycleDetected).toBe(false)
    expect(result.root.type).toBe('derivative')
    expect(result.root.operationType).toBe('compose')
    expect(result.root.parents).toHaveLength(2)

    const rendered = formatLineageTree(result.root)
    expect(rendered).toContain('root_digest (derivative: compose)')
    expect(rendered).toContain('mid1_digest (derivative: crop)')
    expect(rendered).toContain('leaf1_proof (original: valid)')
    expect(rendered).toContain('leaf2_proof (original: valid)')
    expect(rendered).toContain('mid2_digest (derivative: blur)')
    expect(rendered).toContain('leaf3_proof (original: valid)')
    // Confirm no metadata contents are printed
    expect(rendered).not.toContain('metadata')
    expect(rendered).not.toContain('GACTOR')
  })

  it('fails verification and reports when a parent is revoked', async () => {
    const lineages: Record<string, LineageRecord> = {
      root_digest: {
        parentProofIds: ['parent1_proof', 'parent2_proof'],
        parentCommitments: ['c1', 'c2'],
        manifestDigest: 'm_root',
        actor: 'GACTOR',
        operationType: 'crop',
        outputDigest: 'root_digest',
        depth: 1,
      },
    }

    const proofs: Record<string, ProofStatus> = {
      parent1_proof: 'valid',
      parent2_proof: 'revoked',
    }

    const fetcher: LineageFetcher = {
      getLineage: vi.fn(async (digest) => lineages[digest] ?? null),
      getProofStatus: vi.fn(async (proofId) => proofs[proofId] ?? 'missing'),
    }

    const result = await verifyLineageTree('root_digest', fetcher)

    expect(result.success).toBe(false)
    expect(result.revokedCount).toBe(1)
    expect(result.failureReason).toContain('1 ancestor(s) revoked')
    expect(result.root.parents[1].status).toBe('revoked')

    const rendered = formatLineageTree(result.root)
    expect(rendered).toContain('parent2_proof (original: revoked)')
  })

  it('fails verification and reports when an ancestor is expired', async () => {
    const lineages: Record<string, LineageRecord> = {
      root_digest: {
        parentProofIds: ['parent_proof'],
        parentCommitments: ['c1'],
        manifestDigest: 'm_root',
        actor: 'GACTOR',
        operationType: 'transcode',
        outputDigest: 'root_digest',
        depth: 1,
      },
    }

    const proofs: Record<string, ProofStatus> = {
      parent_proof: 'expired',
    }

    const fetcher: LineageFetcher = {
      getLineage: vi.fn(async (digest) => lineages[digest] ?? null),
      getProofStatus: vi.fn(async (proofId) => proofs[proofId] ?? 'missing'),
    }

    const result = await verifyLineageTree('root_digest', fetcher)

    expect(result.success).toBe(false)
    expect(result.expiredCount).toBe(1)
    expect(result.failureReason).toContain('1 ancestor(s) expired')
  })

  it('fails verification and reports when an ancestor is disputed', async () => {
    const lineages: Record<string, LineageRecord> = {
      root_digest: {
        parentProofIds: ['parent_proof'],
        parentCommitments: ['c1'],
        manifestDigest: 'm_root',
        actor: 'GACTOR',
        operationType: 'blur',
        outputDigest: 'root_digest',
        depth: 1,
      },
    }

    const proofs: Record<string, ProofStatus> = {
      parent_proof: 'disputed',
    }

    const fetcher: LineageFetcher = {
      getLineage: vi.fn(async (digest) => lineages[digest] ?? null),
      getProofStatus: vi.fn(async (proofId) => proofs[proofId] ?? 'missing'),
    }

    const result = await verifyLineageTree('root_digest', fetcher)

    expect(result.success).toBe(false)
    expect(result.disputedCount).toBe(1)
    expect(result.failureReason).toContain('1 ancestor(s) disputed')
  })

  it('fails verification and reports when a parent is missing/unregistered', async () => {
    const lineages: Record<string, LineageRecord> = {
      root_digest: {
        parentProofIds: ['nonexistent_proof'],
        parentCommitments: ['c1'],
        manifestDigest: 'm_root',
        actor: 'GACTOR',
        operationType: 'redact',
        outputDigest: 'root_digest',
        depth: 1,
      },
    }

    const fetcher: LineageFetcher = {
      getLineage: vi.fn(async (digest) => lineages[digest] ?? null),
      getProofStatus: vi.fn(async () => 'missing'),
    }

    const result = await verifyLineageTree('root_digest', fetcher)

    expect(result.success).toBe(false)
    expect(result.missingCount).toBe(1)
    expect(result.failureReason).toContain('1 ancestor(s) missing or unregistered')
    expect(result.root.parents[0].status).toBe('missing')
  })

  it('detects direct and indirect cycles in the lineage graph', async () => {
    // Cycle: A -> B -> C -> A
    const lineages: Record<string, LineageRecord> = {
      node_a: {
        parentProofIds: ['node_b'],
        parentCommitments: ['c1'],
        manifestDigest: 'm1',
        actor: 'GACTOR',
        operationType: 'crop',
        outputDigest: 'node_a',
        depth: 1,
      },
      node_b: {
        parentProofIds: ['node_c'],
        parentCommitments: ['c2'],
        manifestDigest: 'm2',
        actor: 'GACTOR',
        operationType: 'transcode',
        outputDigest: 'node_b',
        depth: 2,
      },
      node_c: {
        parentProofIds: ['node_a'],
        parentCommitments: ['c3'],
        manifestDigest: 'm3',
        actor: 'GACTOR',
        operationType: 'blur',
        outputDigest: 'node_c',
        depth: 3,
      },
    }

    const fetcher: LineageFetcher = {
      getLineage: vi.fn(async (digest) => lineages[digest] ?? null),
      getProofStatus: vi.fn(async () => 'valid'),
    }

    const result = await verifyLineageTree('node_a', fetcher)

    expect(result.success).toBe(false)
    expect(result.cycleDetected).toBe(true)
    expect(result.failureReason).toContain('cycle detected in lineage graph')

    const rendered = formatLineageTree(result.root)
    expect(rendered).toContain('[ERROR: cycle detected]')
  })

  it('enforces depth bounds client-side', async () => {
    // 6 levels deep (exceeding MAX_LINEAGE_DEPTH = 4)
    const lineages: Record<string, LineageRecord> = {}
    for (let i = 0; i <= 5; i++) {
      lineages[`level_${i}`] = {
        parentProofIds: [`level_${i + 1}`],
        parentCommitments: ['c'],
        manifestDigest: `m${i}`,
        actor: 'GACTOR',
        operationType: 'crop',
        outputDigest: `level_${i}`,
        depth: i + 1,
      }
    }

    const fetcher: LineageFetcher = {
      getLineage: vi.fn(async (digest) => lineages[digest] ?? null),
      getProofStatus: vi.fn(async () => 'valid'),
    }

    const result = await verifyLineageTree('level_0', fetcher, { maxDepth: MAX_LINEAGE_DEPTH })

    expect(result.success).toBe(false)
    const rendered = formatLineageTree(result.root)
    expect(rendered).toContain('depth bound exceeded')
  })

  it('enforces fan-out bounds client-side', async () => {
    // A node naming 5 parents (exceeding MAX_LINEAGE_FANOUT = 4)
    const lineages: Record<string, LineageRecord> = {
      fanout_node: {
        parentProofIds: ['p1', 'p2', 'p3', 'p4', 'p5'],
        parentCommitments: ['c1', 'c2', 'c3', 'c4', 'c5'],
        manifestDigest: 'm',
        actor: 'GACTOR',
        operationType: 'compose',
        outputDigest: 'fanout_node',
        depth: 1,
      },
    }

    const fetcher: LineageFetcher = {
      getLineage: vi.fn(async (digest) => lineages[digest] ?? null),
      getProofStatus: vi.fn(async () => 'valid'),
    }

    const result = await verifyLineageTree('fanout_node', fetcher, { maxFanout: MAX_LINEAGE_FANOUT })

    expect(result.success).toBe(false)
    expect(result.failureReason).toContain('lineage tree contains errors or bound violations')
    const rendered = formatLineageTree(result.root)
    expect(rendered).toContain('fan-out bound exceeded (5 > 4)')
  })
})
