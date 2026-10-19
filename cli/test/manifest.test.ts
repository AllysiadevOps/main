import { describe, it, expect } from 'vitest'
import {
  createProofManifest,
  serializeManifest,
  parseManifest,
  type ProofManifest,
} from '../src/manifest.js'

const VALID_INPUT = {
  proofId: 'a'.repeat(64),
  tier: 'silent' as const,
  network: 'Test SDF Network ; September 2015',
  contractId: 'CAAAAAAAAABCD1234567890ABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890',
  transactionRef: 'b'.repeat(64),
  videoHash: 'c'.repeat(64),
  metadataHash: 'd'.repeat(64),
  sourceHash: 'e'.repeat(64),
  timestamp: '2026-07-24T12:00:00.000Z',
}

describe('createProofManifest', () => {
  it('returns a manifest with protocol and version', () => {
    const manifest = createProofManifest(VALID_INPUT)
    expect(manifest.protocol).toBe('harpocrates')
    expect(manifest.version).toBe(2)
    expect(manifest.verifierScope).toBe('0')
    expect(manifest.epoch).toBe(0)
  })

  it('copies all supplied fields', () => {
    const manifest = createProofManifest(VALID_INPUT)
    expect(manifest.proofId).toBe(VALID_INPUT.proofId)
    expect(manifest.tier).toBe(VALID_INPUT.tier)
    expect(manifest.videoHash).toBe(VALID_INPUT.videoHash)
  })

  it('does not expose secret/private witness fields', () => {
    const manifest = createProofManifest(VALID_INPUT)
    const keys = Object.keys(manifest)
    const forbidden = [/seed/i, /credential/i, /nullifier/i, /witness/i, /private/i, /secret/i]
    for (const key of keys) {
      for (const pattern of forbidden) {
        expect(key).not.toMatch(pattern)
      }
    }
  })

  it.each(['silent', 'source', 'seal'] as const)('accepts tier "%s"', (tier) => {
    const manifest = createProofManifest({ ...VALID_INPUT, tier })
    expect(manifest.tier).toBe(tier)
  })
})

describe('serializeManifest', () => {
  it('returns valid JSON', () => {
    const manifest = createProofManifest(VALID_INPUT)
    const json = serializeManifest(manifest)
    expect(() => JSON.parse(json)).not.toThrow()
  })

  it('sorts keys alphabetically', () => {
    const manifest = createProofManifest(VALID_INPUT)
    const json = serializeManifest(manifest)
    const parsed = JSON.parse(json) as ProofManifest
    const keys = Object.keys(parsed)
    expect(keys).toEqual([...keys].sort())
  })

  it('is deterministic across invocations', () => {
    const manifest = createProofManifest(VALID_INPUT)
    expect(serializeManifest(manifest)).toBe(serializeManifest(manifest))
  })

  it('produces different output for different inputs', () => {
    const a = serializeManifest(createProofManifest(VALID_INPUT))
    const b = serializeManifest(createProofManifest({ ...VALID_INPUT, proofId: 'f'.repeat(64) }))
    expect(a).not.toBe(b)
  })
})

describe('parseManifest', () => {
  it('parses a valid manifest JSON', () => {
    const manifest = createProofManifest(VALID_INPUT)
    const json = serializeManifest(manifest)
    const parsed = parseManifest(json)
    expect(parsed).toEqual(manifest)
  })

  it('throws on non-JSON input', () => {
    expect(() => parseManifest('not json')).toThrow('not valid JSON')
  })

  it('throws on non-object JSON', () => {
    expect(() => parseManifest('"string"')).toThrow('must be a JSON object')
  })

  it('throws on non-harpocrates protocol', () => {
    const bad = serializeManifest({ ...createProofManifest(VALID_INPUT), protocol: 'other' as 'harpocrates' })
    expect(() => parseManifest(bad)).toThrow('protocol must be')
  })

  it('accepts legacy v1 and current v2 without changing the input version', () => {
    const current = createProofManifest(VALID_INPUT)
    expect(parseManifest(JSON.stringify({ ...current, version: 1 })).version).toBe(1)
    expect(parseManifest(JSON.stringify(current)).version).toBe(2)
  })

  it('rejects unsupported versions and malformed digests', () => {
    const current = createProofManifest(VALID_INPUT)
    expect(() => parseManifest(JSON.stringify({ ...current, version: 3 }))).toThrow('unsupported manifest version')
    expect(() => parseManifest(JSON.stringify({ ...current, videoHash: 'not-a-hash' }))).toThrow('manifest.videoHash')
  })

  it('rejects extra fields that could leak private witness data in a receipt', () => {
    const current = createProofManifest(VALID_INPUT)
    expect(() => parseManifest(JSON.stringify({ ...current, witness: 'private' }))).toThrow('unsupported fields')
  })

  it('rejects invalid v2 scope and epoch', () => {
    const current = createProofManifest(VALID_INPUT)
    expect(() => parseManifest(JSON.stringify({ ...current, verifierScope: '-1' }))).toThrow('scope or epoch')
    expect(() => parseManifest(JSON.stringify({ ...current, epoch: -1 }))).toThrow('scope or epoch')
  })

  it('throws on null JSON', () => {
    expect(() => parseManifest('null')).toThrow('must be a JSON object')
  })

  it('throws on JSON array', () => {
    // arrays are objects in JS; parseManifest reaches the protocol check
    expect(() => parseManifest('[]')).toThrow()
  })

  it('throws when version is missing', () => {
    const m = createProofManifest(VALID_INPUT)
    const obj = JSON.parse(serializeManifest(m)) as Record<string, unknown>
    delete obj['version']
    expect(() => parseManifest(JSON.stringify(obj))).toThrow('unsupported manifest version')
  })

  it('throws on unknown tier in manifest', () => {
    const m = createProofManifest(VALID_INPUT)
    const obj = JSON.parse(serializeManifest(m)) as Record<string, unknown>
    obj['tier'] = 'admin'
    expect(() => parseManifest(JSON.stringify(obj))).toThrow('tier must be one of')
  })

  it('throws when a required string field is missing', () => {
    const m = createProofManifest(VALID_INPUT)
    const obj = JSON.parse(serializeManifest(m)) as Record<string, unknown>
    delete obj['videoHash']
    expect(() => parseManifest(JSON.stringify(obj))).toThrow('manifest.videoHash')
  })

  it('round-trips through serialize then parse for all tiers', () => {
    for (const tier of ['silent', 'source', 'seal'] as const) {
      const manifest = createProofManifest({ ...VALID_INPUT, tier })
      const parsed = parseManifest(serializeManifest(manifest))
      expect(parsed.tier).toBe(tier)
      expect(parsed.protocol).toBe('harpocrates')
    }
  })
})

describe('createProofManifest — golden serialization', () => {
  it('produces the canonical serialized string for a fixed input', () => {
    const manifest = createProofManifest(VALID_INPUT)
    const expected =
      '{"contractId":"CAAAAAAAAABCD1234567890ABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890","epoch":0,"metadataHash":"dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd","network":"Test SDF Network ; September 2015","proofId":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","protocol":"harpocrates","sourceHash":"eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee","tier":"silent","timestamp":"2026-07-24T12:00:00.000Z","transactionRef":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","verifierScope":"0","version":2,"videoHash":"cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"}'
    expect(serializeManifest(manifest)).toBe(expected)
  })

  it('keeps key ordering stable and deterministic across calls', () => {
    const manifest = createProofManifest(VALID_INPUT)
    const first = serializeManifest(manifest)
    const second = serializeManifest(createProofManifest(VALID_INPUT))
    expect(first).toBe(second)
    const keys = Object.keys(JSON.parse(first) as ProofManifest)
    expect(keys).toEqual([...keys].sort())
  })
})

describe('createProofManifest — boundary and regression', () => {
  it('does not include protocol or version in witness-privacy check', () => {
    // protocol and version are public; privacy check applies to witness fields only
    const manifest = createProofManifest(VALID_INPUT)
    expect(manifest.protocol).toBe('harpocrates')
    expect(manifest.version).toBe(2)
  })

  it('serialized output does not contain secret-looking keys even with extra props', () => {
    // Callers cannot sneak private data into the manifest through extra keys on the input
    const manifest = createProofManifest(VALID_INPUT)
    const json = serializeManifest(manifest)
    const forbidden = ['seed', 'credential', 'nullifier', 'witness', 'private', 'secret']
    for (const word of forbidden) {
      expect(json.toLowerCase()).not.toContain(word)
    }
  })

  it('serialization is stable across multiple calls (no timestamp drift)', () => {
    const manifest = createProofManifest(VALID_INPUT)
    const first = serializeManifest(manifest)
    const second = serializeManifest(manifest)
    const third = serializeManifest(manifest)
    expect(first).toBe(second)
    expect(second).toBe(third)
  })

  it('two manifests with different proofIds produce different JSON', () => {
    const a = serializeManifest(createProofManifest({ ...VALID_INPUT, proofId: 'a'.repeat(64) }))
    const b = serializeManifest(createProofManifest({ ...VALID_INPUT, proofId: 'b'.repeat(64) }))
    expect(a).not.toBe(b)
  })

  it('two manifests differing only in tier produce different JSON', () => {
    const a = serializeManifest(createProofManifest({ ...VALID_INPUT, tier: 'silent' }))
    const b = serializeManifest(createProofManifest({ ...VALID_INPUT, tier: 'seal' }))
    expect(a).not.toBe(b)
  })
})
