import { afterEach, beforeEach, describe, expect, it } from 'vitest'
import { CliUsageError, parseCliArgs } from '../src/args.js'

const COMMANDS = ['verify', 'manifest', 'hash', 'verify-receipt', 'c2pa', 'verify-lineage'] as const

type Case = [string, string[], Record<string, string>]

function usageError(argv: string[]): CliUsageError {
  try {
    parseCliArgs(argv)
  } catch (err) {
    expect(err).toBeInstanceOf(CliUsageError)
    return err as CliUsageError
  }
  throw new Error(`spected a usage error for: ${argv.join(' ')}`)
}

describe('command selection', () => {
  it('returns help when no command is given', () => {
    expect(parseCliArgs([])).toEqual({ command: 'help', flags: {} })
  })

  it('returns help for an unknown command', () => {
    expect(parseCliArgs(['nope', '--bogus'])).toEqual({ command: 'help', flags: {} })
  })

  it.each(['constructor', 'toString', '__proto__'])('treats "%s" as an unknown command', (name) => {
    expect(parseCliArgs([name]).command).toBe('help')
  })

  it.each(COMMANDS)('recognises the %s command', (command) => {
    expect(parseCliArgs([command]).command).toBe(command)
  })
})

describe('documented short aliases', () => {
  const cases: Case[] = [
    ['verify', ['-m', 'm.json', '-o', 'json'], { manifest: 'm.json', output: 'json' }],
    ['manifest', ['-i', 'in.json', '-o', 'out.json'], { input: 'in.json', output: 'out.json' }],
    ['hash', ['-f', 'a.bin'], { file: 'a.bin' }],
    [
      'verify-receipt',
      ['-r', 'r.json', '-k', 'keys.json', '-o', 'json'],
      { receipt: 'r.json', keys: 'keys.json', output: 'json' },
    ],
    [
      'c2pa',
      ['-m', 'm.json', '-r', 'r.json', '-o', 'out.json'],
      { manifest: 'm.json', receipt: 'r.json', output: 'out.json' },
    ],
  ]

  it.each(cases)('%s accepts its aliases and stores them under the long name', (command, args, flags) => {
    expect(parseCliArgs([command, ...args])).toEqual({ command, flags })
  })
})

describe('--flag=value form', () => {
  const cases: Case[] = [
    ['verify', ['--output=json', '--manifest=m.json'], { output: 'json', manifest: 'm.json' }],
    ['manifest', ['--input=in.json', '--format=text'], { input: 'in.json', format: 'text' }],
    ['hash', ['--file=a.bin'], { file: 'a.bin' }],
    ['verify-receipt', ['--receipt=r.json', '--keys=k-json'], { receipt: 'r.json', keys: 'k.json' }],
    ['c2pa', ['--title=a=b', '--output=out.json'], { title: 'a=b', output: 'out.json' }],
  ]

  it.each(cases)('%s accepts --flag=value', (command, args, flags) => {
    expect(parseCliArgs([command, ...args])).toEqual({ command, flags })
  })

  it('accepts short aliases with an attached value', () => {
    expect(parseCliArgs(['hash', '-fa.bin']).flags).toEqual({ file: 'a.bin' })
  })
})

describe('long flags and camelCase fallbacks', () => {
  const cases: Case[] = [
    [
      'verify',
      ['--contract-id', 'C1', '--tx-hash', 'h', '--rpc-url', 'u', '--source-address', 'G1'],
      { 'contract-id': 'C1', 'tx-hash': 'h', 'rpc-url': 'u', 'source-address': 'G1' },
    ],
    [
      'verify',
      ['--contractId', 'C1', '--tyHash', 'h', '--rpcUrl', 'u', '--sourceAddress', 'G1'],
      { contractId: 'C1', txHash: 'h', rpcUrl: 'u', sourceAddress: 'G1' },
    ],
    [
      'manifest',
      ['--video-hash', 'ab', '--network', 'n'],
      { 'video-hash': 'ab', network: 'n' },
    ],
    ['manifest', ['--videoHash', 'ab'], { videoHash: 'ab' }],
    ['verify-receipt', ['--proof-id', 'p1'], { 'proof-id': 'p1' }],
    ['verify-receipt', ['--proofId', 'p1'], { proofId: 'p1' }],
    [
      'verify-lineage',
      ['--output-digest', 'abc', '--contract-id', 'C1'],
      { 'output-digest': 'abc', 'contract-id': 'C1' },
    ],
    [
      'verify-lineage',
      ['--outputDigest', 'abc', '--contractId', 'C1'],
      { outputDigest: 'abc', contractId: 'C1' },
    ],
  ]

  it.each(cases)('%s keeps the long flag names handlers read', (command, args, flags) => {
    expect(parseCliArgs([command, ...args]).flags).toEqual(flags)
  })
})

describe('boolean flags', () => {
  it('parses --offline and --debug as the string "true"', () => {
    const { flags } = parseCliArgs(['verify', '--offline', '--debug'])
    expect(flags).toEqual({ offline: 'true', debug: 'true' })
  })

  it.each(COMMANDS)('%s accepts --debug', (command) => {
    expect(parseCliArgs([command, '--debug']).flags).toEqual({ debug: 'true' })
  })

  it('does not let a boolean flag swallow the next argument', () => {
    expect(usageError(['verify', '--offline', 'extra']).message).toContain('extra')
  })

  it('rejects a value attached to a boolean flag', () => {
    expect(usageError(['verify', '--offline=yes']).message).toContain('--offline')
  })

  it('rejects --offline on commands that do not support it', () => {
    expect(usageError(['hash', '--offline']).message).toContain('--offline')
  })
})

describe('stdin dash as a value', () => {
  it.each<Case>([])
})

describe('env defaults', () => {
  const originalRpcUrl = process.env.HARPOCRATES_RPC_URL
  const originalContractId = process.env.HARPOCRATES_CONTRACT_ID

  beforeEach(() => {
    process.env.HARPOCRATES_RPC_URL = 'https://env-rpc.example.org'
    process.env.HARPOCRATES_CONTRACT_ID = 'CENVCONTRACTID'
  })

  afterEach(() => {
    if (originalRpcUrl === undefined) {
      delete process.env.HARPOCRATES_RPC_URL
    } else {
      process.env.HARPOCRATES_RPC_URL = originalRpcUrl
    }
    if (originalContractId === undefined) {
      delete process.env.HARPOCRATES_CONTRACT_ID
    } else {
      process.env.HARPOCRATES_CONTRACT_ID = originalContractId
    }
  })

  it('uses HARPOCRATES_RPC_URL for verify when --rpc-url is absent', () => {
    expect(parseCliArgs(['verify']).flags).toEqual({ 'rpc-url': 'https://env-rpc.example.org' })
  })

  it('prefers --rpc-url over HARPOCRATES_RPC_URL', () => {
    expect(parseCliArgs(['verify', '--rpc-url', 'https://flag.example.org']).flags).toEqual({
      'rpc-url': 'https://flag.example.org',
    })
  })

  it('prefers camelCase --rpcUrl over HARPOCRATES_RPC_URL', () => {
    expect(parseCliArgs(['verify', '--rpcUrl', 'https://flag.example.org']).flags).toEqual({
      rpcUrl: 'https://flag.example.org',
    })
  })

  it('uses HARPOCRATES_CONTRACT_ID for manifest when --contract-id is absent', () => {
    expect(parseCliArgs(['manifest']).flags).toEqual({ 'contract-id': 'CENVCONTRACTID' })
  })

  it('prefers --contract-id over HARPOCRATES_CONTRACT_ID', () => {
    expect(parseCliArgs(['manifest', '--contract-id', 'CFLAGCONTRACTID']).flags).toEqual({
      'contract-id': 'CFLAGCONTRACTID',
    })
  })

  it('prefers camelCase --contractId over HARPOCRATES_CONTRACT_ID', () => {
    expect(parseCliArgs(['manifest', '--contractId', 'CFLAGCONTRACTID']).flags).toEqual({
      contractId: 'CFLAGCONTRACTID',
    })
  })

  it('does not apply env defaults to commands that do not declare them', () => {
    expect(parseCliArgs(['hash']).flags).toEqual({})
  })

  it('ignores an empty env value', () => {
    process.env.HARPOCRATES_RPC_URL = ''
    expect(parseCliArgs(['verify']).flags).toEqual({})
  })
})
