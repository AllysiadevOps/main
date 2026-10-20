import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { Account, StrKey } from '@stellar/stellar-sdk'

const { getAccountMock, simulateTransactionMock, ServerMock, scValToNativeMock } = vi.hoisted(() => {
  const getAccountMock = vi.fn()
  const simulateTransactionMock = vi.fn()
  const ServerMock = vi.fn(() => ({
    getAccount: getAccountMock,
    simulateTransaction: simulateTransactionMock,
  }))
  const scValToNativeMock = vi.fn()
  return { getAccountMock, simulateTransactionMock, ServerMock, scValToNativeMock }
})

vi.mock('@stellar/stellar-sdk', async (importOriginal) => {
  const actual = await importOriginal<typeof import('@stellar/stellar-sdk')>()
  return {
    ...actual,
    scValToNative: scValToNativeMock,
    rpc: {
      ...actual.rpc,
      Server: ServerMock,
      Api: {
        ...actual.rpc.Api,
        isSimulationError: (sim: unknown) =>
          Boolean(sim && typeof sim === 'object' && 'error' in sim && (sim as { error?: unknown }).error),
        isSimulationSuccess: (sim: unknown) =>
          Boolean(sim && typeof sim === 'object' && 'result' in sim && !('error' in sim)),
        isSimulationRestore: () => false,
      },
    },
  }
})

import {
  lookupProofStatus,
  normalizeProofStatus,
  type ProofLifecycleStatus,
} from '../src/stellar-lookup.js'
import {
  formatProofStatus,
  handleStatus,
  helpText,
  main,
  STATUS_EXIT_CODES,
} from '../src/cli.js'

const CONTRACT_ID = StrKey.encodeContract(Uint8Array.from({ length: 32 }, (_, i) => i + 1))
const SOURCE_ADDRESS = 'GAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAWHF'
const VALID_PROOF_ID = 'ab'.repeat(32)

class ExitSignal extends Error {
  readonly code: number
  constructor(code: number) {
    super(`exit(${code})`)
    this.code = code
  }
}

describe('lookupProofStatus', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    getAccountMock.mockResolvedValue(new Account(SOURCE_ADDRESS, '1'))
    simulateTransactionMock.mockResolvedValue({
      result: {
        retval: { mockScVal: true },
      },
    })
  })

  it.each<[unknown, ProofLifecycleStatus]>([
    ['Valid', 'registered'],
    [['Valid'], 'registered'],
    ['registered', 'registered'],
    ['Revoked', 'revoked'],
    [['Revoked'], 'revoked'],
    ['Expired', 'expired'],
    [['Expired'], 'expired'],
    ['NotFound', 'unknown'],
    [['NotFound'], 'unknown'],
    ['unknown', 'unknown'],
  ])('maps scValToNative result %j to "%s"', async (nativeValue, expectedStatus) => {
    scValToNativeMock.mockReturnValueOnce(nativeValue)

    const status = await lookupProofStatus(CONTRACT_ID, VALID_PROOF_ID, {
      rpcUrl: 'https://rpc.example.org',
      sourceAddress: SOURCE_ADDRESS,
      networkPassphrase: 'Test SDF Network ; September 2015',
    })

    expect(status).toBe(expectedStatus)
    expect(ServerMock).toHaveBeenCalledWith('https://rpc.example.org')
    expect(getAccountMock).toHaveBeenCalledWith(SOURCE_ADDRESS)
    expect(simulateTransactionMock).toHaveBeenCalledTimes(1)
    expect(scValToNativeMock).toHaveBeenCalledWith({ mockScVal: true })
  })

  it('rejects an invalid proofId before constructing rpc.Server', async () => {
    await expect(
      lookupProofStatus(CONTRACT_ID, 'not-a-valid-hex-proof-id', {
        rpcUrl: 'https://rpc.example.org',
        sourceAddress: SOURCE_ADDRESS,
      }),
    ).rejects.toThrow('proofId must be a 32-byte hex string')

    expect(ServerMock).not.toHaveBeenCalled()
    expect(getAccountMock).not.toHaveBeenCalled()
    expect(simulateTransactionMock).not.toHaveBeenCalled()
  })
})

describe('status CLI command', () => {
  let stdoutChunks: string[]
  let stderrChunks: string[]

  beforeEach(() => {
    vi.clearAllMocks()
    stdoutChunks = []
    stderrChunks = []
    getAccountMock.mockResolvedValue(new Account(SOURCE_ADDRESS, '1'))
    simulateTransactionMock.mockResolvedValue({
      result: {
        retval: { mockScVal: true },
      },
    })

    vi.spyOn(process.stdout, 'write').mockImplementation((chunk: string | Uint8Array) => {
      stdoutChunks.push(typeof chunk === 'string' ? chunk : Buffer.from(chunk).toString('utf-8'))
      return true
    })
    vi.spyOn(process.stderr, 'write').mockImplementation((chunk: string | Uint8Array) => {
      stderrChunks.push(typeof chunk === 'string' ? chunk : Buffer.from(chunk).toString('utf-8'))
      return true
    })
    vi.spyOn(process, 'exit').mockImplementation(((code?: string | number | null) => {
      throw new ExitSignal(Number(code ?? 0))
    }) as never)
  })

  afterEach(() => {
    vi.restoreAllMocks()
  })

  async function runCli(args: string[]): Promise<{ code: number; stdout: string; stderr: string }> {
    try {
      await main(args)
    } catch (err) {
      if (err instanceof ExitSignal) {
        return {
          code: err.code,
          stdout: stdoutChunks.join(''),
          stderr: stderrChunks.join(''),
        }
      }
      throw err
    }
    throw new Error('Expected CLI command to exit')
  }

  it.each<[string, ProofLifecycleStatus, number]>([
    ['Valid', 'registered', 0],
    ['Revoked', 'revoked', 2],
    ['Expired', 'expired', 1],
    ['NotFound', 'unknown', 3],
  ])(
    'prints %s as "%s" in text mode and exits %d',
    async (chainVariant, expectedStatus, expectedExitCode) => {
      scValToNativeMock.mockReturnValueOnce([chainVariant])

      const { code, stdout, stderr } = await runCli([
        'status',
        '--contract-id',
        CONTRACT_ID,
        '--proof-id',
        VALID_PROOF_ID.toUpperCase(),
        '--rpc-url',
        'https://rpc.example.org',
        '--network',
        'Test SDF Network ; September 2015',
        '--output',
        'text',
      ])

      expect(code).toBe(expectedExitCode)
      expect(STATUS_EXIT_CODES[expectedStatus]).toBe(expectedExitCode)
      expect(stderr).toBe('')
      expect(stdout).toContain(`Proof ID: ${VALID_PROOF_ID}`)
      expect(stdout).toContain(`Contract: ${CONTRACT_ID}`)
      expect(stdout).toContain(`Status:   ${expectedStatus}`)
      expect(simulateTransactionMock).toHaveBeenCalledTimes(1)
    },
  )

  it.each<[string, ProofLifecycleStatus, number]>([
    ['Valid', 'registered', 0],
    ['Revoked', 'revoked', 2],
    ['Expired', 'expired', 1],
    ['NotFound', 'unknown', 3],
  ])(
    'prints %s as "%s" in JSON mode and exits %d',
    async (chainVariant, expectedStatus, expectedExitCode) => {
      scValToNativeMock.mockReturnValueOnce(chainVariant)

      const { code, stdout, stderr } = await runCli([
        'status',
        '--contract-id',
        CONTRACT_ID,
        '--proof-id',
        VALID_PROOF_ID,
        '--rpc-url',
        'https://rpc.example.org',
        '--network',
        'Test SDF Network ; September 2015',
        '--output',
        'json',
      ])

      expect(code).toBe(expectedExitCode)
      expect(stderr).toBe('')
      const parsed = JSON.parse(stdout)
      expect(parsed).toEqual({
        proofId: VALID_PROOF_ID,
        contractId: CONTRACT_ID,
        network: 'Test SDF Network ; September 2015',
        status: expectedStatus,
      })
      expect(simulateTransactionMock).toHaveBeenCalledTimes(1)
    },
  )

  it.each(['', 'short', 'zz'.repeat(32), '0x' + 'aa'.repeat(32), 'aa'.repeat(31)])(
    'exits 2 for invalid proof id %j without making an RPC call',
    async (invalidProofId) => {
      const args = invalidProofId
        ? ['status', '--contract-id', CONTRACT_ID, '--proof-id', invalidProofId]
        : ['status', '--contract-id', CONTRACT_ID]

      const { code, stderr } = await runCli(args)

      expect(code).toBe(2)
      expect(stderr).toContain('--proof-id')
      expect(ServerMock).not.toHaveBeenCalled()
      expect(getAccountMock).not.toHaveBeenCalled()
      expect(simulateTransactionMock).not.toHaveBeenCalled()
      expect(scValToNativeMock).not.toHaveBeenCalled()
    },
  )

  it('exits 2 when handleStatus is invoked directly with an invalid proof id without RPC calls', async () => {
    await expect(
      handleStatus({
        'contract-id': CONTRACT_ID,
        'proof-id': 'invalid-proof-id',
      }),
    ).rejects.toMatchObject({ code: 2 })

    expect(ServerMock).not.toHaveBeenCalled()
    expect(simulateTransactionMock).not.toHaveBeenCalled()
  })

  it('includes status command and options in help text', () => {
    const help = helpText()
    expect(help).toContain('status')
    expect(help).toContain('--proof-id')
    expect(help).toContain('Status options:')
  })

  it('normalizes status variants and formats human-readable status text', () => {
    expect(normalizeProofStatus(1)).toBe('registered')
    expect(normalizeProofStatus(2)).toBe('revoked')
    expect(normalizeProofStatus(3)).toBe('expired')
    expect(normalizeProofStatus(null)).toBe('unknown')

    const text = formatProofStatus({
      proofId: VALID_PROOF_ID,
      contractId: CONTRACT_ID,
      network: 'Test SDF Network ; September 2015',
      status: 'registered',
    })
    expect(text).toContain('Status:   registered')
  })
})
