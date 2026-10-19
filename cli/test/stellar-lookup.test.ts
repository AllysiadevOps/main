import { describe, it, expect, afterEach, beforeEach } from 'vitest'
import { StrKey } from '@stellar/stellar-sdk'
import { checkContractMatch } from '../src/stellar-lookup.js'

const contractBytes = Uint8Array.from({ length: 32 }, (_, index) => index)
const contractId = StrKey.encodeContract(contractBytes)

describe('checkContractMatch', () => {
  it('matches the decoded Stellar contract ID bytes', () => {
    const envelope = Uint8Array.from([255, ...contractBytes, 255])
    expect(checkContractMatch(envelope, contractId)).toBe(true)
  })

  it('rejects a different contract, malformed ID and empty envelope', () => {
    expect(checkContractMatch(new Uint8Array(32), contractId)).toBe(false)
    expect(checkContractMatch(contractBytes, '0x' + contractId)).toBe(false)
    expect(checkContractMatch(new Uint8Array(), contractId)).toBe(false)
  })
})

describe('env defaults', () => {
  const originalRpcUrl = process.env.HARPOCRATES_RPC_URL
  const originalContractId = process.env.HARPOCRATES_CONTRACT_ID

  beforeEach(() => {
    process.env.HARPOCRATES_RPC_URL = 'https://env-rpc.example.org'
    process.env.HARPOCRATES_CONTRACT_ID = contractId
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

  it('uses env contract ID when no flag is provided', () => {
    const envelope = Uint8Array.from([255, ...contractBytes, 255])
    expect(checkContractMatch(envelope, process.env.HARPOCRATES_CONTRACT_ID)).toBe(true)
  })

  it('prefers explicit contract ID over env value', () => {
    const otherBytes = Uint8Array.from({ length: 32 }, () => 0)
    const otherId = StrKey.encodeContract(otherBytes)
    const envelope = Uint8Array.from([255, ...contractBytes, 255])
    expect(checkContractMatch(envelope, otherId)).toBe(false)
    expect(checkContractMatch(envelope, contractId)).toBe(true)
  })

  it('rejects an invalid env contract ID', () => {
    process.env.HARPOCRATES_CONTRACT_ID = 'not-a-contract-id'
    const envelope = Uint8Array.from([255, ...contractBytes, 255])
    expect(checkContractMatch(envelope, process.env.HARPOCRATES_CONTRACT_ID)).toBe(false)
  })
})
