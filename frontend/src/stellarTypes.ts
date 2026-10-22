export type IdentityTier = 'silent' | 'source' | 'seal'

export type Hex32 = string & { readonly __hex32: unique symbol }
export type HexBytes = string & { readonly __hexBytes: unique symbol }

export type SilentWitnessArtifacts = {
  publicInputs: HexBytes
  proof: HexBytes
}

export type RegisterProofInput = {
  contractId: string
  publicKey: string
  tier: IdentityTier
  videoHash: string
  metadataHash: string
  proofId: string
  silentWitness?: {
    publicInputs: string
    proof: string
  }
}

export type NormalizedRegisterProofInput = {
  contractId: string
  publicKey: string
  tier: IdentityTier
  videoHash: Hex32
  metadataHash: Hex32
  proofId: Hex32
  silentWitness?: SilentWitnessArtifacts
}

export type TxState = 'idle' | 'submitting' | 'awaiting_confirmation' | 'confirmed' | 'failed' | 'timeout'

export type TxStatusLabel =
  | 'Not submitted'
  | 'Pending'
  | 'Confirmed'
  | 'Failed'
  | 'Rejected by wallet'
  | 'Timed out'

export function describeTxState(state: TxState): TxStatusLabel {
  switch (state) {
    case 'idle':
      return 'Not submitted'
    case 'submitting':
      return 'Pending'
    case 'awaiting_confirmation':
      return 'Pending'
    case 'confirmed':
      return 'Confirmed'
    case 'failed':
      return 'Failed'
    case 'timeout':
      return 'Timed out'
  }
}

export type RegisterProofResult = {
  hash: string
  status: string
  txState: TxState
}

export type VerifierRotationInput = {
  contractId: string
  publicKey: string
  verifier: string
  activationLedger: number | bigint
  overlapWindow: number | bigint
  rollbackWindow: number | bigint
}

export type VerifierRotationActionInput = {
  contractId: string
  publicKey: string
}

export type ChainVerifierState = {
  activeVerifier: string | null
  pendingVerifier: string | null
  previousVerifier: string | null
  activationLedger: string
  overlapWindow: string
  rollbackWindow: string
  rollbackWindowEnd: string
}

export type ChainProofRecord = {
  videoHash: string
  metadataHash: string
  tier: number
  status: number
  createdAt: string
  /**
   * `ProofRecord.expires_at` in Unix seconds. `0` means the record never
   * expires, matching the registry's expiry policy.
   */
  expiresAt: number | null
  source: string | null
  issuer: string | null
}

export type ProofHistoryAction = 1 | 2 | 3 | 4 | 5 | 6

export type ProofHistoryEntry = {
  action: ProofHistoryAction
  timestamp: string
  actor: string | null
  reasonCode: number
}

export type ProofHistoryResult = {
  entries: ProofHistoryEntry[]
  count: number
}

/**
 * `IssuerRecord` from the registry: an institutional issuer's standing.
 * `active` is the registry's own flag, so revocation is authoritative here
 * rather than inferred from the proof record.
 */
export type IssuerRecord = {
  metadataHash: string
  active: boolean
}

export type SupportedPredicateType = 'Equality' | 'SetMembership' | 'Range'

export type SelectiveDisclosureChainInput = {
  publicInputs: string
  proof: string
  schemaHash: string
  evidenceDigest: string
}

export type SchemaChainRecord = {
  schemaHash: string
  issuerNamespace: string
  version: number
  active: boolean
  attributeCount: number
  createdAt: string
}

export type RegistryMethod =
  | 'register_anonymous_verified'
  | 'register_source'
  | 'register_seal'
  | 'get_by_video'
  | 'get_issuer'
  | 'get_proof_history_at'
  | 'get_proof_history_count'
  | 'set_scope_epoch'
  | 'get_scope_epoch'
  | 'add_schema'
  | 'get_schema'
  | 'get_verifier_state'
  | 'get_open_dispute_count'

export type ProofHistoryEntry = {
  action: number
  timestamp: string
  actor: string | null
  reasonCode: number
}

export type ProofHistoryResult = {
  entries: ProofHistoryEntry[]
  count: number
}

export type ProofHistoryEntry = {
  /** Registry action code (see the contract's HistoryAction enum). */
  action: number
  /** Ledger sequence / timestamp captured at the time of the action. */
  timestamp: string
  /** Actor address that triggered the action, if recorded. */
  actor: string | null
  /** Reason code attached to the action. */
  reasonCode: number
}

export type ProofHistoryResult = {
  entries: ProofHistoryEntry[]
  count: number
}

export type ScopedProofScope = {
  /** Field element derived from the scope string (SHA-256 mod BN254). */
  scopeField: string
  /** Human-readable scope name (for manifest only, not sent on-chain). */
  scopeName: string
}

export type ScopedProofEpoch = {
  /** Epoch number matching the on-chain scope epoch. */
  epoch: number
}
