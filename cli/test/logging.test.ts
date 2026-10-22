import { describe, it, expect } from 'vitest'
import { redactSensitive, logStructured, REDACTED_VALUE } from '../src/logging.js'

describe('Logging Redaction Helper (cli/src/logging.ts)', () => {
  describe('Nested objects', () => {
    it('redacts sensitive keys nested at various depths', () => {
      const input = {
        level1: {
          safe1: 'public-data',
          level2: {
            safe2: 123,
            level3: {
              password: 'super-secret-password',
              token: 'auth-token-12345',
              deepSafe: true,
            },
          },
        },
      }

      const redacted = redactSensitive(input)

      expect(redacted.level1.safe1).toBe('public-data')
      expect(redacted.level1.level2.safe2).toBe(123)
      expect(redacted.level1.level2.level3.deepSafe).toBe(true)
      expect(redacted.level1.level2.level3.password).toBe(REDACTED_VALUE)
      expect(redacted.level1.level2.level3.token).toBe(REDACTED_VALUE)
      expect(JSON.stringify(redacted)).not.toContain('super-secret-password')
      expect(JSON.stringify(redacted)).not.toContain('auth-token-12345')
    })

    it('redacts multiple sensitive keys in deeply nested structures', () => {
      const input = {
        a: {
          b: {
            c: {
              d: {
                privateKey: 'my-private-key',
                secret: 'deep-secret',
                safe: 'keep-me',
              },
            },
          },
        },
      }

      const redacted = redactSensitive(input)
      expect(redacted.a.b.c.d.privateKey).toBe(REDACTED_VALUE)
      expect(redacted.a.b.c.d.secret).toBe(REDACTED_VALUE)
      expect(redacted.a.b.c.d.safe).toBe('keep-me')
      expect(JSON.stringify(redacted)).not.toContain('my-private-key')
      expect(JSON.stringify(redacted)).not.toContain('deep-secret')
    })
  })

  describe('Arrays of objects', () => {
    it('redacts sensitive fields in arrays of objects', () => {
      const input = {
        users: [
          { id: 1, password: 'pw1', name: 'Alice' },
          { id: 2, password: 'pw2', name: 'Bob' },
        ],
        secretsList: [
          { token: 'tok-1' },
          { rawBytes: '0x1234567890' },
        ],
      }

      const redacted = redactSensitive(input)

      expect(redacted.users[0].name).toBe('Alice')
      expect(redacted.users[0].password).toBe(REDACTED_VALUE)
      expect(redacted.users[1].name).toBe('Bob')
      expect(redacted.users[1].password).toBe(REDACTED_VALUE)
      expect(redacted.secretsList[0].token).toBe(REDACTED_VALUE)
      expect(redacted.secretsList[1].rawBytes).toBe(REDACTED_VALUE)
      expect(JSON.stringify(redacted)).not.toContain('pw1')
      expect(JSON.stringify(redacted)).not.toContain('pw2')
      expect(JSON.stringify(redacted)).not.toContain('tok-1')
      expect(JSON.stringify(redacted)).not.toContain('0x1234567890')
    })

    it('redacts sensitive keys inside nested arrays and mixed structures', () => {
      const input = {
        matrix: [
          [
            { authorization: 'Bearer abc' },
            { safe: 'ok' },
          ],
          [
            { witness: 'witness-data-val' },
          ],
        ],
      }

      const redacted = redactSensitive(input as any)
      expect((redacted as any).matrix[0][0].authorization).toBe(REDACTED_VALUE)
      expect((redacted as any).matrix[0][1].safe).toBe('ok')
      expect((redacted as any).matrix[1][0].witness).toBe(REDACTED_VALUE)
      expect(JSON.stringify(redacted)).not.toContain('Bearer abc')
      expect(JSON.stringify(redacted)).not.toContain('witness-data-val')
    })
  })

  describe('Mixed-case sensitive keys', () => {
    it('redacts sensitive keys regardless of casing and punctuation', () => {
      const input = {
        PASSWORD: 'all-caps-password',
        Password: 'title-case-password',
        pAsSwOrD: 'mixed-case-password',
        'nullifier_secret': 'snake-case-secret',
        'NULLIFIER-SECRET': 'kebab-caps-secret',
        'CredentialSecret': 'pascal-case-secret',
        'CREDENTIAL_SECRET': 'screaming-snake-secret',
        'private_key': 'snake-key',
        'PRIVATE-KEY': 'kebab-key',
        'PublicInputs': ['val1', 'val2'],
        'PUBLIC_INPUTS': 'pub-inputs',
        'RAW_BYTES': 'bytes-123',
        'Cookie': 'session=abc',
        'AUTHORIZATION': 'Bearer token',
      }

      const redacted = redactSensitive(input)

      for (const key of Object.keys(input)) {
        expect(redacted[key as keyof typeof redacted]).toBe(REDACTED_VALUE)
      }

      const json = JSON.stringify(redacted)
      expect(json).not.toContain('all-caps-password')
      expect(json).not.toContain('title-case-password')
      expect(json).not.toContain('mixed-case-password')
      expect(json).not.toContain('snake-case-secret')
      expect(json).not.toContain('kebab-caps-secret')
      expect(json).not.toContain('pascal-case-secret')
      expect(json).not.toContain('screaming-snake-secret')
      expect(json).not.toContain('snake-key')
      expect(json).not.toContain('kebab-key')
      expect(json).not.toContain('val1')
      expect(json).not.toContain('val2')
      expect(json).not.toContain('pub-inputs')
      expect(json).not.toContain('bytes-123')
      expect(json).not.toContain('session=abc')
      expect(json).not.toContain('Bearer token')
    })

    it('redacts any key variant containing witness', () => {
      const input = {
        witnessData: 'data1',
        WitnessInputs: 'data2',
        WITNESS_SECRET: 'data3',
        silentWitnessProof: 'data4',
        user_witness_record: 'data5',
      }

      const redacted = redactSensitive(input)

      expect(redacted.witnessData).toBe(REDACTED_VALUE)
      expect(redacted.WitnessInputs).toBe(REDACTED_VALUE)
      expect(redacted.WITNESS_SECRET).toBe(REDACTED_VALUE)
      expect(redacted.silentWitnessProof).toBe(REDACTED_VALUE)
      expect(redacted.user_witness_record).toBe(REDACTED_VALUE)

      const json = JSON.stringify(redacted)
      expect(json).not.toContain('data1')
      expect(json).not.toContain('data2')
      expect(json).not.toContain('data3')
      expect(json).not.toContain('data4')
      expect(json).not.toContain('data5')
    })

    it('does not redact safe non-sensitive identifiers', () => {
      const input = {
        proofId: 'proof-12345',
        metadataHash: 'hash-abcde',
        sourceHash: 'source-67890',
        timestamp: '2026-10-18T12:00:00Z',
      }

      const redacted = redactSensitive(input)
      expect(redacted.proofId).toBe('proof-12345')
      expect(redacted.metadataHash).toBe('hash-abcde')
      expect(redacted.sourceHash).toBe('source-67890')
      expect(redacted.timestamp).toBe('2026-10-18T12:00:00Z')
    })
  })

  describe('Very long strings', () => {
    it('redacts sensitive fields containing very long string values without issues', () => {
      const longSensitiveValue = 'secret-'.repeat(20000) // ~140 KB
      const longSafeValue = 'safe-content-'.repeat(20000) // ~260 KB

      const input = {
        password: longSensitiveValue,
        safeText: longSafeValue,
        nested: {
          token: longSensitiveValue,
        },
      }

      const redacted = redactSensitive(input)

      expect(redacted.password).toBe(REDACTED_VALUE)
      expect(redacted.nested.token).toBe(REDACTED_VALUE)
      expect(redacted.safeText).toBe(longSafeValue)

      const json = JSON.stringify(redacted)
      expect(json).not.toContain(longSensitiveValue)
    })
  })

  describe('Cyclic references', () => {
    it('does not throw or hang on self-referential objects', () => {
      const cyclicObj: Record<string, unknown> = {
        name: 'cyclic',
        password: 'sensitive-password-in-cyclic',
      }
      cyclicObj.self = cyclicObj

      expect(() => redactSensitive(cyclicObj)).not.toThrow()

      const redacted = redactSensitive(cyclicObj)
      expect(redacted.name).toBe('cyclic')
      expect(redacted.password).toBe(REDACTED_VALUE)
      expect(redacted.self).toBe(REDACTED_VALUE)

      const json = JSON.stringify(redacted)
      expect(json).not.toContain('sensitive-password-in-cyclic')
      expect(json).toContain(REDACTED_VALUE)
    })

    it('does not throw or hang on mutually recursive objects', () => {
      const a: Record<string, unknown> = { name: 'a', secret: 'secret-a' }
      const b: Record<string, unknown> = { name: 'b', secret: 'secret-b' }
      a.partner = b
      b.partner = a

      expect(() => redactSensitive(a)).not.toThrow()

      const redactedA = redactSensitive(a)
      expect(redactedA.name).toBe('a')
      expect(redactedA.secret).toBe(REDACTED_VALUE)
      expect((redactedA.partner as Record<string, unknown>).name).toBe('b')
      expect((redactedA.partner as Record<string, unknown>).secret).toBe(REDACTED_VALUE)
      expect((redactedA.partner as Record<string, unknown>).partner).toBe(REDACTED_VALUE)

      const json = JSON.stringify(redactedA)
      expect(json).not.toContain('secret-a')
      expect(json).not.toContain('secret-b')
    })

    it('handles cyclic references inside arrays', () => {
      const arr: unknown[] = ['normal', { token: 'secret-in-array' }]
      arr.push(arr)

      const input = { items: arr }
      expect(() => redactSensitive(input)).not.toThrow()

      const redacted = redactSensitive(input)
      expect((redacted.items as unknown[])[0]).toBe('normal')
      expect(((redacted.items as unknown[])[1] as Record<string, unknown>).token).toBe(REDACTED_VALUE)
      expect((redacted.items as unknown[])[2]).toBe(REDACTED_VALUE)

      const json = JSON.stringify(redacted)
      expect(json).not.toContain('secret-in-array')
    })
  })

  describe('logStructured', () => {
    it('formats redacted data as JSON and calls logger', () => {
      const loggedMessages: string[] = []
      const fakeLogger = {
        debug: (msg: string) => loggedMessages.push(msg),
        info: (msg: string) => loggedMessages.push(msg),
        warn: (msg: string) => loggedMessages.push(msg),
        error: (msg: string) => loggedMessages.push(msg),
      }

      const input = {
        event: 'test_event',
        password: 'leak-password',
        nested: {
          token: 'leak-token',
        },
      }

      logStructured(fakeLogger, 'debug', input)

      expect(loggedMessages).toHaveLength(1)
      const parsed = JSON.parse(loggedMessages[0])
      expect(parsed.event).toBe('test_event')
      expect(parsed.password).toBe(REDACTED_VALUE)
      expect(parsed.nested.token).toBe(REDACTED_VALUE)
      expect(loggedMessages[0]).not.toContain('leak-password')
      expect(loggedMessages[0]).not.toContain('leak-token')
    })

    it('handles cyclic data in logStructured safely', () => {
      const loggedMessages: string[] = []
      const fakeLogger = {
        debug: (msg: string) => loggedMessages.push(msg),
        info: (msg: string) => loggedMessages.push(msg),
        warn: (msg: string) => loggedMessages.push(msg),
        error: (msg: string) => loggedMessages.push(msg),
      }

      const cyclicData: Record<string, unknown> = {
        event: 'cyclic_event',
        secret: 'cyclic-secret',
      }
      cyclicData.self = cyclicData

      expect(() => logStructured(fakeLogger, 'info', cyclicData)).not.toThrow()
      expect(loggedMessages).toHaveLength(1)
      const parsed = JSON.parse(loggedMessages[0])
      expect(parsed.event).toBe('cyclic_event')
      expect(parsed.secret).toBe(REDACTED_VALUE)
      expect(parsed.self).toBe(REDACTED_VALUE)
      expect(loggedMessages[0]).not.toContain('cyclic-secret')
    })
  })
})
