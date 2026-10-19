import { createHash } from 'node:crypto'
import { describe, it, expect, vi } from 'vitest'
import { hex, sha256, sha256Blob, shortHash, fieldSecret } from './utils'

// ── hex ───────────────────────────────────────────────────────────────────

describe('hex', () => {
  it('converts an empty buffer to an empty string', () => {
    expect(hex(new ArrayBuffer(0))).toBe('')
  })

  it('converts a single-byte buffer to two hex chars', () => {
    const buf = new Uint8Array([0xca]).buffer
    expect(hex(buf)).toBe('ca')
  })

  it('pads single-digit hex values with a leading zero', () => {
    const buf = new Uint8Array([0x0f]).buffer
    expect(hex(buf)).toBe('0f')
  })

  it('converts a multi-byte buffer to a concatenated hex string', () => {
    const buf = new Uint8Array([0xde, 0xad, 0xbe, 0xef]).buffer
    expect(hex(buf)).toBe('deadbeef')
  })
})

// ── sha256 ────────────────────────────────────────────────────────────────

describe('sha256', () => {
  it('returns a 64-character lowercase hex string', async () => {
    const result = await sha256('hello')
    expect(result).toHaveLength(64)
    expect(result).toMatch(/^[0-9a-f]+$/)
  })

  it('returns the well-known SHA-256 of the empty string', async () => {
    // echo -n "" | sha256sum
    const result = await sha256('')
    expect(result).toBe('e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855')
  })

  it('returns the same hash for the same input (determinism)', async () => {
    const [a, b] = await Promise.all([sha256('abc'), sha256('abc')])
    expect(a).toBe(b)
  })

  it('accepts an ArrayBuffer input and produces the same result as a string', async () => {
    const str = 'hello world'
    const bytes = new TextEncoder().encode(str)
    const [fromStr, fromBuf] = await Promise.all([sha256(str), sha256(bytes.buffer)])
    expect(fromStr).toBe(fromBuf)
  })

  it('produces different hashes for different inputs', async () => {
    const [a, b] = await Promise.all([sha256('foo'), sha256('bar')])
    expect(a).not.toBe(b)
  })
})

describe('sha256Blob', () => {
  it('matches the existing SHA-256 result for file contents', async () => {
    const file = new File(['same evidence bytes'], 'evidence.mp4', {
      type: 'video/mp4',
    })
    const expected = await sha256(await file.arrayBuffer())

    await expect(sha256Blob(file)).resolves.toBe(expected)
  })

  it('reports processed bytes and reaches 100 percent at the total', async () => {
    const file = new File(['abcdefgh'], 'small.mp4')
    const progress: Array<{
      processedBytes: number
      totalBytes: number
      percentage: number
    }> = []

    await sha256Blob(file, (value) => progress.push(value), undefined, 3)

    expect(progress[0]).toEqual({ processedBytes: 0, totalBytes: 8, percentage: 0 })
    expect(progress.map((value) => value.processedBytes)).toEqual([0, 3, 6, 8])
    expect(progress.every((value) => value.totalBytes === 8)).toBe(true)
    expect(progress.at(-1)).toEqual({
      processedBytes: 8,
      totalBytes: 8,
      percentage: 100,
    })
  })

  it('hashes empty and sub-chunk files correctly', async () => {
    const empty = new Blob([])
    const small = new Blob(['abc'])
    const emptyProgress: Array<{
      processedBytes: number
      totalBytes: number
      percentage: number
    }> = []

    await expect(sha256Blob(empty, (value) => emptyProgress.push(value))).resolves.toBe(
      await sha256(await empty.arrayBuffer()),
    )
    await expect(sha256Blob(small, undefined, undefined, 8)).resolves.toBe(
      await sha256(await small.arrayBuffer()),
    )
    expect(emptyProgress).toEqual([{ processedBytes: 0, totalBytes: 0, percentage: 100 }])
  })

  it('handles data across exact and partial chunk boundaries', async () => {
    const file = new Blob(['0123456789abcdefg'])
    const progress: Array<{
      processedBytes: number
      totalBytes: number
      percentage: number
    }> = []

    const hash = await sha256Blob(file, (value) => progress.push(value), undefined, 8)

    expect(hash).toBe(await sha256(await file.arrayBuffer()))
    expect(progress.map((value) => value.processedBytes)).toEqual([0, 8, 16, 17])
  })

  it('stops promptly when its signal is aborted during hashing', async () => {
    const controller = new AbortController()
    const file = new Blob(['abcdefgh'])
    const progress: Array<{
      processedBytes: number
      totalBytes: number
      percentage: number
    }> = []

    await expect(
      sha256Blob(
        file,
        (value) => {
          progress.push(value)
          if (value.processedBytes > 0) controller.abort()
        },
        controller.signal,
        2,
      ),
    ).rejects.toMatchObject({ name: 'AbortError' })

    expect(progress.at(-1)?.processedBytes).toBe(2)
  })

  it('rejects an invalid chunk size before reading the blob', async () => {
    const file = new Blob(['abc'])

    await expect(sha256Blob(file, undefined, undefined, 0)).rejects.toThrow(
      'Hash chunk size must be greater than zero.',
    )
    await expect(sha256Blob(file, undefined, undefined, -1)).rejects.toThrow(
      'Hash chunk size must be greater than zero.',
    )
  })

  it('rejects immediately when its signal is already aborted', async () => {
    const controller = new AbortController()
    controller.abort()
    const onProgress = vi.fn()

    await expect(
      sha256Blob(new Blob(['abc']), onProgress, controller.signal),
    ).rejects.toMatchObject({ name: 'AbortError' })
    expect(onProgress).not.toHaveBeenCalled()
  })
})

// ── shortHash ─────────────────────────────────────────────────────────────

describe('shortHash', () => {
  it('returns "Not generated" for an empty string', () => {
    expect(shortHash('')).toBe('Not generated')
  })

  it('abbreviates a long hash with ellipsis', () => {
    const hash = 'a'.repeat(64)
    const result = shortHash(hash)
    expect(result).toContain('...')
    expect(result.startsWith('a'.repeat(12))).toBe(true)
    expect(result.endsWith('a'.repeat(10))).toBe(true)
  })

  it('includes exactly the first 12 and last 10 characters', () => {
    const hash = '0123456789abcdef'.repeat(4) // 64 chars
    const result = shortHash(hash)
    expect(result).toBe(`${hash.slice(0, 12)}...${hash.slice(-10)}`)
  })
})

// ── fieldSecret ───────────────────────────────────────────────────────────

describe('fieldSecret', () => {
  it('returns a decimal string', async () => {
    const result = await fieldSecret('credential', 'my-seed')
    expect(result).toMatch(/^\d+$/)
  })

  it('returns a non-zero value', async () => {
    const result = await fieldSecret('credential', 'my-seed')
    expect(BigInt(result)).toBeGreaterThan(0n)
  })

  it('produces different values for different labels', async () => {
    const [a, b] = await Promise.all([
      fieldSecret('credential', 'same-seed'),
      fieldSecret('nullifier', 'same-seed'),
    ])
    expect(a).not.toBe(b)
  })

  it('produces different values for different seeds', async () => {
    const [a, b] = await Promise.all([
      fieldSecret('credential', 'seed-a'),
      fieldSecret('credential', 'seed-b'),
    ])
    expect(a).not.toBe(b)
  })

  it('is deterministic — same inputs always produce the same output', async () => {
    const [first, second] = await Promise.all([
      fieldSecret('nullifier', 'determinism-test'),
      fieldSecret('nullifier', 'determinism-test'),
    ])
    expect(first).toBe(second)
  })

  it('matches the reference derivation SHA-256("harpocrates:{label}:{seed}") mod BN254', async () => {
    const BN254 =
      21888242871839275222246405745257275088548364400416034343698204186575808495617n
    const reference = (label: string, seed: string) => {
      const digest = createHash('sha256').update(`harpocrates:${label}:${seed}`).digest('hex')
      const value = BigInt(`0x${digest}`) % BN254
      return value === 0n ? '1' : value.toString(10)
    }
    const vectors: Array<[string, string]> = [
      ['credential', 'my-secret'],
      ['nullifier', 'my-secret'],
      ['credential', 'same-seed'],
      ['nullifier', 'determinism-test'],
      ['credential', ''],
      ['nullifier', 'ünïcödé seed'],
    ]
    for (const [label, seed] of vectors) {
      expect(await fieldSecret(label, seed)).toBe(reference(label, seed))
    }
  })
})
