#![no_std]

#[cfg(test)]
extern crate std;

use soroban_sdk::{
    contract, contracterror, contractevent, contractimpl, contracttype, panic_with_error, Address,
    Bytes, BytesN, Env, IntoVal, InvokeError, Symbol, Val, Vec,
};

pub type SorobanVec<T> = Vec<T>;

pub mod verifier_inputs;

// Wasm size-budget constants and helpers (#346). Host-side only so the
// deployed artifact stays byte-identical to the pre-budget build.
#[cfg(not(target_arch = "wasm32"))]
pub mod wasm_budget;

use verifier_inputs::{RejectCode, PUBLIC_INPUTS_LEN, REVOCATION_PUBLIC_INPUTS_LEN};

/// Schema selectors accepted by [`HarpocratesRegistry::classify_public_inputs`].
pub const SCHEMA_ID_SILENT_WITNESS: u32 = 1;
pub const SCHEMA_ID_REVOCATION_WITNESS: u32 = 2;
/// Circuit-versioned silent-witness envelope (`silent_witness/v2`, #368).
/// Distinct from [`SCHEMA_ID_SILENT_WITNESS`] so `classify_public_inputs` can
/// enforce the appended circuit-version field without touching the v1 codec.
pub const SCHEMA_ID_SILENT_WITNESS_V2: u32 = 3;

/// Maximum Merkle depth for the `revocation_witness` circuit (#357).
/// Must match `MAX_REVOCATION_WITNESS_DEPTH` in the Noir circuit and host tooling.
/// Raising this value requires a new circuit version — do not change it silently.
pub const MAX_REVOCATION_WITNESS_DEPTH: u32 = 3;
/// Leaf capacity implied by [`MAX_REVOCATION_WITNESS_DEPTH`] (`2^depth` = 8).
pub const MAX_REVOCATION_LEAVES: u32 = 8;

const TIER_SILENT_WITNESS: u32 = 1;
const TIER_CONSISTENT_SOURCE: u32 = 2;
const TIER_PUBLIC_SEAL: u32 = 3;

const STATUS_REGISTERED: u32 = 1;
const STATUS_REVOKED: u32 = 2;
const STATUS_EXPIRED: u32 = 3;

pub const DEFAULT_PROOF_TTL_SECS: u64 = 0;

const STATUS_POLICY_ACTIVE: u32 = 1;
const STATUS_POLICY_CANCELLED: u32 = 2;

const MAX_SIGNERS: u32 = 16;
const DEFAULT_APPROVAL_TTL_SECS: u64 = 86_400;

pub const MAX_REVOKE_PROOFS_BATCH_SIZE: u32 = 20;

// ---------------------------------------------------------------------------
// Lineage graph bounds (#333)
// ---------------------------------------------------------------------------
//
// A lineage record is a directed edge from registered evidence (or another
// derivative) to a new derivative. Both directions of every edge are bounded so
// no single artefact can be amplified into an unbounded family:
//
// - `MAX_LINEAGE_FANOUT` caps the parents one derivative may name (in-degree)
//   and the derivatives one parent may be charged for (out-degree).
// - `MAX_LINEAGE_DEPTH` caps how far a derivative may sit from the evidence it
//   descends from. Depth is derived from the parents, never taken from the
//   caller, so the bound cannot be bypassed by asserting a smaller number.
// - `MAX_LINEAGE_PAYLOAD_BYTES` caps the encoded lineage payload a registered
//   edge stands for. The registry only ever sees 32-byte digests, so the bound
//   it can check is the parent set; the compile-time assertion below keeps the
//   two bounds consistent, and the manifest body bound is enforced by the
//   backend that owns the manifest.
const MAX_LINEAGE_DEPTH: u32 = 4;
const MAX_LINEAGE_FANOUT: u32 = 4;
const MAX_LINEAGE_PAYLOAD_BYTES: u32 = 4096;
/// Max children returned by a single `list_lineage_children` page (#335).
pub const MAX_LINEAGE_CHILDREN_PAGE: u32 = 50;
/// Max indexed children stored per parent proof/digest (#335).
pub const MAX_LINEAGE_CHILDREN_PER_PARENT: u32 = 256;

// ---------------------------------------------------------------------------
// Independent timestamp claims (#339)
// ---------------------------------------------------------------------------
//
// On-chain commitments to off-chain time attestations (see
// `backend/docs/time-attestation-protocol.md`). The ledger timestamp and
// sequence provide an independent anchor; RFC 3161 material is stored only as
// a 32-byte commitment (never raw tokens, media, or secrets).
//
// Source bitflags (combinable):
pub const TIMESTAMP_SOURCE_CLAIMED: u32 = 0x01;
pub const TIMESTAMP_SOURCE_STELLAR: u32 = 0x02;
pub const TIMESTAMP_SOURCE_RFC3161: u32 = 0x04;

/// Maximum allowed claimed_time drift ahead of ledger time (5 minutes).
pub const MAX_TIMESTAMP_FUTURE_DRIFT_SECS: u64 = 300;

/// Assurance levels aligned with the off-chain protocol hierarchy.
pub const TIMESTAMP_ASSURANCE_NONE: u32 = 0;
pub const TIMESTAMP_ASSURANCE_CLAIMED: u32 = 1;
pub const TIMESTAMP_ASSURANCE_OBSERVED: u32 = 2;
pub const TIMESTAMP_ASSURANCE_INDEPENDENT: u32 = 3;

/// A parent set that fits the fan-out cap must also fit the payload budget.
const _: () = assert!(
    (MAX_LINEAGE_FANOUT as usize) * 32 <= MAX_LINEAGE_PAYLOAD_BYTES as usize,
    "MAX_LINEAGE_FANOUT parent digests must fit inside MAX_LINEAGE_PAYLOAD_BYTES"
);

// ---------------------------------------------------------------------------
// Tier 2 Source Batch Commitments
// ---------------------------------------------------------------------------
pub const MAX_SOURCE_BATCH_COUNT: u32 = 1_048_576;
pub const MIN_SOURCE_BATCH_COUNT: u32 = 1;
pub const MAX_SOURCE_BATCH_PROOF_LEN: u32 = 32;

pub const SOURCE_BATCH_LEAF_DOMAIN: u8 = 0x00;
pub const SOURCE_BATCH_NODE_DOMAIN: u8 = 0x01;


// ---------------------------------------------------------------------------
// On-chain metadata envelope versioning (#317)
// ---------------------------------------------------------------------------
//
// Off-chain steganography payloads use versioned envelopes (`HRPSTG1` /
// `HRPSTG2` in `backend/envelope.py`). On-chain we store only the canonical
// metadata hash plus an explicit envelope version so verifiers can interpret
// the hash without a second protocol truth and without ever logging media,
// witnesses, or private keys.
//
// Legacy registrations that only supply `metadata_hash` are stamped as V1.
// V2 is additive; unsupported versions fail closed with a stable error.

/// Envelope version matching backend `HRPSTG1`.
pub const METADATA_ENVELOPE_V1: u32 = 1;
/// Envelope version matching backend `HRPSTG2`.
pub const METADATA_ENVELOPE_V2: u32 = 2;
/// Highest envelope version this wasm accepts.
pub const METADATA_ENVELOPE_VERSION_MAX: u32 = METADATA_ENVELOPE_V2;
/// Default for bare `metadata_hash` registrations (backward compatible).
pub const METADATA_ENVELOPE_VERSION_DEFAULT: u32 = METADATA_ENVELOPE_V1;
/// Maximum size of canonical evidence metadata stored on-chain: one 32-byte digest.
pub const MAX_EVIDENCE_METADATA_HASH_BYTES: u32 = 32;

// ---------------------------------------------------------------------------
// Proof-history bounds (#90)
// ---------------------------------------------------------------------------
//
// Every proof carries an append-only history of lifecycle transitions.
// Each entry is bounded in size and the total number of entries per proof
// is capped to prevent storage exhaustion under hostile inputs.
//
// - MAX_HISTORY_ENTRIES_PER_PROOF limits total entries per proof.
// - MAX_HISTORY_LIMIT bounds the maximum number of entries returned by a
//   single query, protecting callers from unbounded iteration costs.
pub const MAX_HISTORY_ENTRIES_PER_PROOF: u32 = 256;
pub const MAX_HISTORY_LIMIT: u32 = 50;

// ---------------------------------------------------------------------------
// Scoped emergency pause controls (#87)
// ---------------------------------------------------------------------------
//
// Pauses are scoped per registration domain (one bit per identity tier) so a
// compromised path can be contained without freezing unaffected tiers or any
// read entry point. Reads (`get_proof`, `get_proof_status`, `get_by_video`,
// `has_nullifier`, `get_issuer`, `get_credential_root`, `get_verifier`,
// `is_paused`, `get_pause_state`) are never gated by pause state. Admin
// remediation entry points (`revoke_proof`, `revoke_issuer`,
// `revoke_credential_root`, `set_verifier`) also stay callable while paused,
// since incident response depends on them.
//
// Every pause is bounded: callers supply a `duration_secs` capped by
// `MAX_PAUSE_DURATION_SECS` (admin) or `MAX_GUARDIAN_PAUSE_DURATION_SECS`
// (guardian). A pause auto-expires once `ledger().timestamp() >=
// expires_at`, so a lost admin/guardian key cannot brick registration
// forever. `pause` is idempotent (re-pausing overwrites/extends the
// existing record); `unpause` on an already-unpaused domain is a no-op.
// Only the admin can lift a pause early — a compromised guardian key can
// raise the alarm but cannot stand it down before the bounded expiry.
//
// Migration: `Guardian` and `Pause(domain)` are new, additive storage keys.
// Existing deployments read as "no guardian set" / "nothing paused" until
// the admin opts in, so upgrading is backward compatible and requires no
// migration step. Rolling back to a pre-#87 wasm simply ignores these keys.
pub const PAUSE_DOMAIN_TIER1_REGISTRATION: u32 = 1 << 0;
pub const PAUSE_DOMAIN_TIER2_REGISTRATION: u32 = 1 << 1;
pub const PAUSE_DOMAIN_TIER3_REGISTRATION: u32 = 1 << 2;
/// Convenience alias that expands to all three registration domains at once.
pub const PAUSE_DOMAIN_ALL_REGISTRATION: u32 = PAUSE_DOMAIN_TIER1_REGISTRATION
    | PAUSE_DOMAIN_TIER2_REGISTRATION
    | PAUSE_DOMAIN_TIER3_REGISTRATION;

const PAUSE_DOMAIN_SINGLE_BITS: [u32; 3] = [
    PAUSE_DOMAIN_TIER1_REGISTRATION,
    PAUSE_DOMAIN_TIER2_REGISTRATION,
    PAUSE_DOMAIN_TIER3_REGISTRATION,
];

/// Maximum pause duration an admin may set in a single call (7 days).
pub const MAX_PAUSE_DURATION_SECS: u64 = 7 * 24 * 60 * 60;
/// Maximum pause duration a guardian may set in a single call (24 hours).
/// Kept shorter than the admin cap so a compromised guardian key cannot
/// freeze registration for longer than a day without admin involvement.
pub const MAX_GUARDIAN_PAUSE_DURATION_SECS: u64 = 24 * 60 * 60;

// ---------------------------------------------------------------------------
// Constrained issuer and source delegation (#192)
// ---------------------------------------------------------------------------
//
// A source or issuer often needs an assistant, a scheduler, or a CI job to
// register on its behalf without handing over the key. A delegation grants
// exactly one capability, for a bounded time, and nothing else.
//
// What a delegation is NOT:
//
// - It is not issuer or source authority. A delegate cannot add or revoke
//   issuers, cannot add or revoke credential roots, cannot set the verifier,
//   pause a domain, or touch admin state. Those paths still require the
//   grantor's own key.
// - It is not transitive. `grant_delegation` requires the grantor's own
//   signature, and the delegated registration entry points are not grant entry
//   points, so there is no call path by which a delegate can re-delegate the
//   authority it received. A delegate that grants to a third party grants only
//   *its own* authority; the third party still cannot act for the original
//   grantor. This is enforced by construction, not by a runtime scan, so it
//   holds without bounding a delegation graph walk.
// - It is not attribution laundering. The registered `ProofRecord` still names
//   the grantor as source/issuer; the delegate appears only in the proof's
//   lifecycle history, so an auditor can see who actually acted.
//
// Bounds. `scope` must be a non-empty subset of the known scope bits.
// `duration_secs` must be non-zero and at most `MAX_DELEGATION_DURATION_SECS`.
// A grantor may hold at most `MAX_DELEGATIONS_PER_GRANTOR` distinct delegate
// addresses; re-granting to an existing delegate overwrites its record and does
// not consume another slot, so retries and renewals are idempotent in storage.
//
// Expiry. A delegation lapses on its own at `expires_at` — a forgotten grant
// cannot become permanent authority. An expired record still occupies its slot
// until `revoke_delegation` prunes it, which keeps the cap a simple, auditable
// count of distinct delegates rather than a time-dependent quantity.
//
// Migration. `Delegation` and `DelegationCount` are new, additive storage keys
// and the delegated entry points are new functions. Existing deployments read
// as "no delegations" until a grantor opts in; no migration step is required.
// Rolling back to a pre-#192 wasm ignores these keys, which fails closed: the
// delegated entry points disappear and only direct-key registration remains.

/// A delegate may call `register_source_delegated` for the grantor.
pub const DELEGATION_SCOPE_REGISTER_SOURCE: u32 = 1 << 0;
/// A delegate may call `register_seal_delegated` for the grantor.
pub const DELEGATION_SCOPE_REGISTER_SEAL: u32 = 1 << 1;
/// Every known scope bit. Used to reject unknown bits in `scope`.
pub const DELEGATION_SCOPE_ALL: u32 =
    DELEGATION_SCOPE_REGISTER_SOURCE | DELEGATION_SCOPE_REGISTER_SEAL;

/// Longest delegation a grantor may issue in a single call (30 days).
pub const MAX_DELEGATION_DURATION_SECS: u64 = 30 * 24 * 60 * 60;

/// Maximum number of distinct delegate addresses a single grantor may hold.
/// Bounds per-grantor storage growth under a hostile or buggy client.
pub const MAX_DELEGATIONS_PER_GRANTOR: u32 = 32;

// ---------------------------------------------------------------------------
// Issuer rotation grace windows (#323)
// ---------------------------------------------------------------------------
//
// A Tier 3 issuer key rotates out by activating a replacement and retiring the
// old key. Retiring the key must not make evidence it already signed
// unverifiable in the same transaction: the off-chain key-transparency
// directory keeps pre-rotation signatures valid inside the predecessor's
// validity window (`docs/issuer-key-transparency.md`), and the registry has to
// express the same bounded window or the two public boundaries disagree.
//
// A rotation retires the previous key immediately — it can no longer sign new
// seals — and opens a bounded grace window during which the evidence it already
// signed stays verifiable. The window is lazy: readers compare
// `grace_expires_at` against ledger time, so it lapses without a transaction,
// and any caller may settle the record afterwards with
// `finalize_issuer_rotation`, which publishes the grace-expiry event.
//
// `grace_secs == 0` selects `DEFAULT_ISSUER_ROTATION_GRACE_SECS`, so a rotation
// can never silently drop the window. A request above
// `MAX_ISSUER_ROTATION_GRACE_SECS`, or one whose `rotated_at + grace_secs`
// overflows, fails closed with `InvalidIssuerRotationGrace`.
//
// Revocation outranks the window: `revoke_issuer`, its timelocked twin, and
// `add_issuer` all clear any rotation record, so a withdrawn or re-onboarded
// key never keeps standing it should not have.
//
// Migration. `DataKey::IssuerRotation(issuer)` is a new, additive key and the
// stored `IssuerRecord` keeps its exact `{metadata_hash, active}` shape, so
// records written by an earlier wasm still decode unchanged and a deployment
// that never rotates reads as "no rotation" with standing decided by `active`
// alone. Rolling back to a pre-#323 wasm ignores the key and falls back to the
// `active` flag, which only widens acceptance for a retired key — never for a
// revoked one, and never for new evidence after an explicit `revoke_issuer`.

/// Grace window applied when `rotate_issuer` is called with `grace_secs == 0`
/// (90 days). A rotation never silently leaves pre-rotation evidence uncovered.
pub const DEFAULT_ISSUER_ROTATION_GRACE_SECS: u64 = 90 * 24 * 60 * 60;
/// Longest grace window an admin may open in a single rotation (365 days).
pub const MAX_ISSUER_ROTATION_GRACE_SECS: u64 = 365 * 24 * 60 * 60;

// ---------------------------------------------------------------------------
// Verifier circuit-version validation (#343)
// ---------------------------------------------------------------------------
//
// Every proof that crosses the contract's public boundary was produced by a
// specific Noir circuit version. Two parties own that fact: this wasm build
// knows which frame versions its codec can frame and interpret, and the
// configured external verifier is the authority on which circuit versions it
// can actually check. This section binds those facts so a call cannot smuggle
// a proof generated by a circuit the active verifier does not support.
//
// There is exactly one source of truth for each version value: the codec
// constants in `verifier_inputs` and the circuit domain separators already in
// this file. The implicit versions below are read off those existing
// boundaries; this is not a second protocol truth.
//
// Compatibility. The active window defaults to the full built-in range and is
// only narrowed by an explicit admin call, so existing deployments and stored
// evidence validate exactly as before. A verifier that declares a window is
// checked at the trust boundary *before* it is invoked, so an unsupported
// version fails closed with a stable error instead of reaching a dependency
// that cannot answer.

/// Circuit version of the v1 silent-witness frame (160 bytes).
pub const CIRCUIT_VERSION_SILENT_WITNESS_V1: u32 = 1;
/// Circuit version of the v2 scoped-nullifier frame (224 bytes).
pub const CIRCUIT_VERSION_SILENT_WITNESS_V2: u32 = 2;
/// Circuit version of the revocation-witness frame (128 bytes).
pub const CIRCUIT_VERSION_REVOCATION_WITNESS: u32 = 1;
/// Circuit version of the aggregation proof (`AGGREGATION_DOMAIN_SEPARATOR`).
pub const CIRCUIT_VERSION_AGGREGATION: u32 = 1;
/// Circuit version of the selective-disclosure proof (carried in the frame).
pub const CIRCUIT_VERSION_SELECTIVE_DISCLOSURE: u32 = CURRENT_SELECTIVE_DISCLOSURE_VERSION;

/// Lowest circuit version this wasm build can frame and interpret.
pub const MIN_SUPPORTED_CIRCUIT_VERSION: u32 = 1;
/// Highest circuit version this wasm build can frame and interpret.
pub const MAX_SUPPORTED_CIRCUIT_VERSION: u32 = CIRCUIT_VERSION_SILENT_WITNESS_V2;

// ---------------------------------------------------------------------------
// Verifier rotation state
// ---------------------------------------------------------------------------
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VerifierState {
    pub active_verifier: Option<Address>,
    pub pending_verifier: Option<Address>,
    pub previous_verifier: Option<Address>,
    pub activation_ledger: u64,
    pub overlap_window: u64,
    pub rollback_window: u64,
    pub rollback_window_end: u64,
}

/// A verifier's declared circuit-version window (#343).
///
/// Immutable record of what the active verifier was told it may check, plus
/// who declared it and when. When no record exists the window is the full
/// built-in `[MIN_SUPPORTED_CIRCUIT_VERSION, MAX_SUPPORTED_CIRCUIT_VERSION]`
/// range, which is the pre-#343 behaviour.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VerifierCircuitVersions {
    pub min_version: u32,
    pub max_version: u32,
    pub set_by: Address,
    pub set_at: u64,
}

/// Configuration snapshot for verifier-backed operations.
///
/// Loaded once at the start of verified registration calls to reduce repeated
/// storage reads across validation helpers.
#[derive(Clone, Debug)]
pub struct VerifierContext {
    pub verifier: Option<Address>,
    pub circuit_versions: (u32, u32),
}

impl VerifierContext {
    pub fn load(env: &Env) -> Self {
        let verifier = env.storage().persistent().get(&DataKey::Verifier);
        let circuit_versions = get_verifier_circuit_versions_raw(env);
        Self {
            verifier,
            circuit_versions,
        }
    }

    pub fn verifier(&self, env: &Env) -> &Address {
        self.verifier
            .as_ref()
            .unwrap_or_else(|| panic_with_error!(env, RegistryError::VerifierNotSet))
    }

    pub fn require_supported_circuit_version(&self, env: &Env, circuit_version: u32) {
        if circuit_version < MIN_SUPPORTED_CIRCUIT_VERSION
            || circuit_version > MAX_SUPPORTED_CIRCUIT_VERSION
        {
            panic_with_error!(env, RegistryError::UnsupportedCircuitVersion);
        }

        let (min_version, max_version) = self.circuit_versions;
        if circuit_version < min_version || circuit_version > max_version {
            panic_with_error!(env, RegistryError::UnsupportedCircuitVersion);
        }
    }

    pub fn require_verified_proof(
        &self,
        env: &Env,
        circuit_version: u32,
        public_inputs: Bytes,
        proof: Bytes,
    ) {
        self.require_supported_circuit_version(env, circuit_version);

        if proof.is_empty() {
            panic_with_error!(env, RegistryError::InvalidProof);
        }

        let verifier = self.verifier(env);
        if !verify_external_proof(env, verifier, public_inputs, proof) {
            panic_with_error!(env, RegistryError::InvalidProof);
        }
    }

    pub fn has_nullifier(&self, env: &Env, nullifier: &BytesN<32>) -> bool {
        if let Some(ref verifier) = self.verifier {
            if env
                .storage()
                .persistent()
                .has(&DataKey::VerifierNullifier(verifier.clone(), nullifier.clone()))
            {
                return true;
            }
        }
        env.storage()
            .persistent()
            .has(&DataKey::Nullifier(nullifier.clone()))
    }
}

// ---------------------------------------------------------------------------
// Timelocked verifier and policy administration (#86)
// ---------------------------------------------------------------------------

#[contracttype]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u32)]
pub enum ProposalAction {
    SetVerifier = 1,
    RevokeIssuer = 2,
    SetProofTtl = 3,
    RevokeCredentialRoot = 4,
    ExpireCredentialRoot = 5,
    UpgradeWasm = 6,
}

pub const DEFAULT_SCOPE_EPOCH: u64 = 0;
pub const MIN_AGGREGATION_SIZE: u32 = 1;
pub const MAX_AGGREGATION_SIZE: u32 = 8;
pub const AGGREGATION_DOMAIN_SEPARATOR: [u8; 32] = [0u8; 32];

#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TimelockProposal {
    pub action: u32,
    pub proposer: Address,
    pub target: Address,
    pub payload: BytesN<32>,
    pub created_at: u64,
    pub min_execution_at: u64,
    pub executed: bool,
    pub cancelled: bool,
}

pub const DEFAULT_TIMELOCK_MIN_DELAY_SECS: u64 = 86_400;
pub const MAX_TIMELOCK_MIN_DELAY_SECS: u64 = 604_800;
pub const MAX_PENDING_TIMELOCK_PROPOSALS: u32 = 16;
/// Maximum number of proposals a single `list_timelock_proposals` page may return.
pub const MAX_TIMELOCK_PROPOSALS_PAGE: u32 = 25;

/// Paginated result from `list_timelock_proposals`.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TimelockProposalPage {
    pub proposals: SorobanVec<TimelockProposal>,
    /// Cursor for the next page (`Some(next_cursor)`), or `None` if end reached.
    pub next_cursor: Option<u32>,
}

/// Maximum number of credential roots a single `list_credential_roots` page may return (#731).
pub const MAX_CREDENTIAL_ROOTS_PAGE: u32 = 25;
/// Maximum number of credential roots backfilled in a single `upgrade_storage` call (#731).
pub const MAX_ROOTS_BACKFILL_BATCH: u32 = 25;

/// An entry in a `CredentialRootPage` (#731).
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CredentialRootEntry {
    pub root_hash: BytesN<32>,
    pub status: u32,
}

/// Paginated result from `list_credential_roots` (#731).
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CredentialRootPage {
    pub roots: SorobanVec<CredentialRootEntry>,
    /// Cursor for the next page (`Some(next_cursor)`), or `None` if end reached.
    pub next_cursor: Option<u32>,
}


/// A narrowly scoped, expiring authority to act for `grantor`.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DelegationRecord {
    pub grantor: Address,
    pub delegate: Address,
    /// Bitwise-OR of `DELEGATION_SCOPE_*`.
    pub scope: u32,
    pub granted_at: u64,
    /// Epoch seconds after which the delegation is inert. Never zero.
    pub expires_at: u64,
}

#[contractevent(topics = ["deleg", "grant"])]
pub struct DelegationGranted {
    #[topic]
    pub grantor: Address,
    #[topic]
    pub delegate: Address,
    pub scope: u32,
    pub granted_at: u64,
    pub expires_at: u64,
}

#[contractevent(topics = ["deleg", "revoke"])]
pub struct DelegationRevoked {
    #[topic]
    pub grantor: Address,
    #[topic]
    pub delegate: Address,
    pub revoked_by: Address,
    pub revoked_at: u64,
}

#[contractevent(topics = ["deleg", "used"])]
pub struct DelegationUsed {
    #[topic]
    pub grantor: Address,
    #[topic]
    pub delegate: Address,
    pub scope: u32,
    pub proof_id: BytesN<32>,
}

/// Threshold in ledgers below which we extend the TTL of records (approx 14 days)
pub const BUMP_THRESHOLD_LEDGERS: u32 = 241_920;

/// Target TTL in ledgers when extending the TTL of records (approx 30 days)
pub const BUMP_TARGET_LEDGERS: u32 = 518_400;

/// Verification status returned by `get_proof_status`.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ProofVerificationStatus {
    Valid,
    Revoked,
    Expired,
    NotFound,
}

/// Comprehensive proof assurance view combining status, tier, timestamp assurance,
/// dispute count, envelope version, and issuer verifiability in a single call.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProofAssurance {
    pub status: ProofVerificationStatus,
    pub tier: u32,
    pub timestamp_assurance_level: u32,
    pub open_dispute_count: u32,
    pub envelope_version: u32,
    pub issuer_verifiable: bool,
}

impl ProofAssurance {
    pub fn timestamp_assurance(&self) -> u32 {
        self.timestamp_assurance_level
    }

    pub fn is_issuer_verifiable(&self) -> bool {
        self.issuer_verifiable
    }
}

/// On-chain lineage edge for a verifiable derivative.
///
/// `parent_proof_ids` retain graph topology for cycle/depth checks.
/// `parent_commitments` store domain-separated content bindings for each
/// parent so public boundaries (events / interop) can cite parents without
/// relying on raw proof identifiers alone. Derived as
/// `SHA-256("harp_lin_pc" || binding_a || binding_b)` where a proof parent
/// binds `(video_hash, metadata_hash)` and a lineage parent binds
/// `(manifest_digest, output_digest)`.
///
/// Migration: additive field on new registrations. Pre-existing lineage
/// rows (if any) lack commitments and must be re-registered after upgrade;
/// rolling back to a pre-#332 wasm ignores the new event / getter and leaves
/// stored records readable only by matching wasm.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LineageRecord {
    pub parent_proof_ids: soroban_sdk::Vec<BytesN<32>>,
    pub parent_commitments: soroban_sdk::Vec<BytesN<32>>,
    pub manifest_digest: BytesN<32>,
    pub actor: Address,
    pub operation_type: Symbol,
    pub output_digest: BytesN<32>,
    pub depth: u32,
}

/// On-chain independent timestamp claim for a registered proof (#339).
///
/// Stores commitments and ledger-derived anchors only — never TSA token
/// bytes, media, witness values, or private keys.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TimestampClaim {
    /// Proof this claim is bound to.
    pub proof_id: BytesN<32>,
    /// Digest of the off-chain `harpocrates-time-attestation/v1` envelope.
    pub attestation_digest: BytesN<32>,
    /// Optional claimed capture time (unix seconds). `0` means absent.
    pub claimed_time: u64,
    /// Ledger timestamp when this claim was anchored (independent observed time).
    pub anchored_at: u64,
    /// Ledger sequence at anchor time for external cross-checks.
    pub ledger_sequence: u32,
    /// Combinable `TIMESTAMP_SOURCE_*` bitflags.
    pub sources: u32,
    /// Commitment to an RFC 3161 token (`[0;32]` if absent).
    pub rfc3161_commitment: BytesN<32>,
    /// Authenticated actor who submitted the claim.
    pub actor: Address,
    /// Derived assurance level (`TIMESTAMP_ASSURANCE_*`).
    pub assurance: u32,
}

/// One page of child output digests for a lineage parent (#335).
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LineageChildrenPage {
    pub children: soroban_sdk::Vec<BytesN<32>>,
    /// Absolute offset of the next unread child (equals `total` when exhausted).
    pub next_offset: u32,
    pub total: u32,
}

#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProofRecord {
    pub video_hash: BytesN<32>,
    pub metadata_hash: BytesN<32>,
    pub tier: u32,
    pub status: u32,
    pub created_at: u64,
    pub expires_at: u64,
    pub source: Option<Address>,
    pub issuer: Option<Address>,
    pub nullifier: Option<BytesN<32>>,
    /// Optional batch size when this proof was registered as part of an
    /// aggregated batch (0 = not part of a batch).
    pub batch_size: u32,
}

/// Tier 2 source batch root record.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BatchRecord {
    pub root: BytesN<32>,
    pub source: Address,
    pub count: u32,
    pub metadata_hash: BytesN<32>,
    pub created_at: u64,
}

pub type SourceBatchRecord = BatchRecord;


/// Versioned on-chain metadata envelope binding (#317).
///
/// Stores only `(version, metadata_hash)` commitments — never raw envelope
/// bytes, media, witnesses, or secrets. Aligns with backend `envelope.py`.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MetadataEnvelope {
    /// Proof this envelope is bound to.
    pub proof_id: BytesN<32>,
    /// Envelope schema version (`METADATA_ENVELOPE_V1` / `V2`).
    pub version: u32,
    /// Canonical metadata hash (same value stored on `ProofRecord`).
    pub metadata_hash: BytesN<32>,
    /// Ledger timestamp when this envelope binding was written.
    pub bound_at: u64,
}

#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct IssuerRecord {
    pub metadata_hash: BytesN<32>,
    pub active: bool,
}

/// Rotation grace record for an issuer key that has rotated out (#323).
///
/// Keyed by the *previous* (retired) key at `DataKey::IssuerRotation(Address)`
/// so the stored `IssuerRecord` keeps its byte-identical `{metadata_hash,
/// active}` shape and records written by an earlier wasm still decode.
/// Presence means "this key was rotated, not revoked, and the evidence it
/// already signed stays verifiable until `grace_expires_at`".
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct IssuerRotationRecord {
    /// The key that rotated out — also the record's storage key.
    pub previous_issuer: Address,
    /// The active key that replaced it.
    pub replacement_issuer: Address,
    /// Ledger timestamp at which the rotation was accepted.
    pub rotated_at: u64,
    /// Epoch seconds after which the grace window has lapsed. A reader at
    /// exactly this timestamp sees the window as already closed.
    pub grace_expires_at: u64,
    /// Resolved window length (the protocol default when the caller passed 0).
    pub grace_secs: u64,
}

#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CredentialRootRecordV1 {
    pub metadata_hash: BytesN<32>,
    pub active: bool,
    pub issued_at: u64,
}

#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CredentialRootRecord {
    pub metadata_hash: BytesN<32>,
    pub status: u32,
    pub issued_at: u64,
    pub expires_at: u64,
}

/// Pause record for a single registration domain bit. Presence of a record
/// does not by itself mean "paused" — see `domain_is_paused`, which also
/// checks `expires_at` against the current ledger time so pauses expire on
/// their own without requiring a follow-up transaction.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PauseRecord {
    pub paused_by: Address,
    pub paused_at: u64,
    pub expires_at: u64,
}

#[contracttype]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u32)]
pub enum ProofLifecycleAction {
    Registered = 1,
    Verified = 2,
    Revoked = 3,
    Expired = 4,
    Corrected = 5,
    TtlUpdated = 6,
}

#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProofHistoryEntry {
    pub action: u32,
    pub timestamp: u64,
    pub actor: Option<Address>,
    pub reason_code: u32,
}

#[contractevent(topics = ["proof", "reg"])]
pub struct ProofRegistered {
    #[topic]
    pub proof_id: BytesN<32>,
    pub video_hash: BytesN<32>,
    pub tier: u32,
    pub status: u32,
    pub batch_size: u32,
}

// Metadata envelope events (#317) — version + hash only (privacy-safe).
// Third topic carried as a `Symbol` field (spec allows two literal prefixes);
// emitted topics stay `["metadata", "envelope", "bound", proof_id]`.
#[contractevent(topics = ["metadata", "envelope"])]
pub struct MetadataEnvelopeBound {
    #[topic]
    pub bound: Symbol,
    #[topic]
    pub proof_id: BytesN<32>,
    pub version: u32,
    pub metadata_hash: BytesN<32>,
    pub bound_at: u64,
}

#[contractevent(topics = ["metadata", "envelope"])]
pub struct MetadataEnvelopeUpgraded {
    #[topic]
    pub upgraded: Symbol,
    #[topic]
    pub proof_id: BytesN<32>,
    pub previous: u32,
    pub current: u32,
    pub metadata_hash: BytesN<32>,
}

// The spec allows at most two literal prefix topics
// (`ScSpecEventV0.prefix_topics` is `VecM<ScSymbol, 2>`), so the third topic
// is carried as a `Symbol` field. Fields follow the prefix in declaration
// order, keeping the emitted topic list exactly
// `["proof", "batch", "reg", batch_id]`.
#[contractevent(topics = ["proof", "batch"])]
pub struct BatchProofRegistered {
    #[topic]
    pub reg: Symbol,
    #[topic]
    pub batch_id: BytesN<32>,
    pub credential_root: BytesN<32>,
    pub count: u32,
    pub tier: u32,
    pub status: u32,
}

#[contractevent(topics = ["batch", "root"])]
pub struct SourceBatchRootRegistered {
    #[topic]
    pub root: BytesN<32>,
    #[topic]
    pub source: Address,
    pub count: u32,
    pub metadata_hash: BytesN<32>,
    pub registered_at: u64,
}


#[contractevent(topics = ["proof", "revoke"])]
pub struct ProofRevoked {
    #[topic]
    pub proof_id: BytesN<32>,
    pub status: u32,
}

#[contractevent(topics = ["issuer", "add"])]
pub struct IssuerAdded {
    #[topic]
    pub issuer: Address,
    pub metadata_hash: BytesN<32>,
}

#[contractevent(topics = ["issuer", "revoke"])]
pub struct IssuerRevoked {
    #[topic]
    pub issuer: Address,
}

#[contractevent(topics = ["issuer", "metadata"])]
pub struct IssuerMetadataUpdated {
    #[topic]
    pub issuer: Address,
    pub previous_metadata_hash: BytesN<32>,
    pub new_metadata_hash: BytesN<32>,
}

/// Emitted when an active issuer key rotates to a replacement (#323).
///
/// Carries addresses, ledger time, and the grace bound only — never key
/// material, metadata preimages, witnesses, media, or secrets.
#[contractevent(topics = ["issuer", "rotate"])]
pub struct IssuerRotated {
    #[topic]
    pub previous_issuer: Address,
    pub replacement_issuer: Address,
    pub rotated_at: u64,
    pub grace_expires_at: u64,
    pub grace_secs: u64,
}

/// Emitted when a rotation grace window is settled after it lapses (#323).
#[contractevent(topics = ["issuer", "grace"])]
pub struct IssuerRotationGraceExpired {
    #[topic]
    pub issuer: Address,
    pub replacement_issuer: Address,
    pub grace_expires_at: u64,
}

#[contractevent(topics = ["verif", "set"])]
pub struct VerifierSet {
    #[topic]
    pub verifier: Address,
}

#[contractevent(topics = ["verif", "schedule"])]
pub struct VerifierRotationScheduled {
    #[topic]
    pub active_verifier: Address,
    pub pending_verifier: Address,
    pub activation_ledger: u64,
    pub overlap_window: u64,
    pub rollback_window: u64,
}

#[contractevent(topics = ["verif", "activate"])]
pub struct VerifierRotationActivated {
    #[topic]
    pub active_verifier: Address,
    pub previous_verifier: Address,
    pub rollback_window_end: u64,
}

#[contractevent(topics = ["verif", "rollback"])]
pub struct VerifierRotationRolledBack {
    #[topic]
    pub active_verifier: Address,
    pub previous_verifier: Address,
}

/// Emitted when the admin narrows or widens the active verifier's supported
/// circuit-version window (#343). Version numbers only — no witness material.
#[contractevent(topics = ["verif", "versions"])]
pub struct VerifierCircuitVersionsSet {
    #[topic]
    pub verifier: Address,
    pub min_version: u32,
    pub max_version: u32,
}

#[contractevent(topics = ["credroot", "add"])]
pub struct CredentialRootAdded {
    #[topic]
    pub credential_root: BytesN<32>,
    pub metadata_hash: BytesN<32>,
    pub issued_at: u64,
}

#[contractevent(topics = ["credroot", "revoke"])]
pub struct CredentialRootRevoked {
    #[topic]
    pub credential_root: BytesN<32>,
}

#[contractevent(topics = ["credroot", "expire"])]
pub struct CredentialRootExpired {
    #[topic]
    pub credential_root: BytesN<32>,
    pub expired_at: u64,
}

/// Domain-separated, privacy-safe proof lifecycle history event (#90).
///
/// Topics: `["proof", "history", proof_id]`. The payload carries only bounded
/// metadata (action, timestamp, actor, reason_code) — never media, proof bytes,
/// witnesses, nullifiers, or metadata hashes.
#[contractevent(topics = ["proof", "history"])]
pub struct ProofHistoryEvent {
    #[topic]
    pub proof_id: BytesN<32>,
    pub action: u32,
    pub timestamp: u64,
    pub actor: Option<Address>,
    pub reason_code: u32,
}

/// Privacy-safe lineage registration signal (#332).
///
/// Publishes parent *commitments* (not raw parent proof ids) so indexers and
/// interoperable consumers can observe derivative linkage without expanding
/// the public surface beyond opaque 32-byte digests.
#[contractevent(topics = ["lineage", "reg"])]
pub struct LineageRegistered {
    #[topic]
    pub output_digest: BytesN<32>,
    pub manifest_digest: BytesN<32>,
    pub actor: Address,
    pub operation_type: Symbol,
    pub depth: u32,
    pub parent_commitments: soroban_sdk::Vec<BytesN<32>>,
}

// ---------------------------------------------------------------------------
// Dispute / correction state machine (#dispute)
// ---------------------------------------------------------------------------
//
// A dispute is a bounded, auditable record that challenges a proof's accuracy
// without deleting or revoking the original proof. Disputes are separate from
// revocation: a disputed proof may still be `Valid` under `get_proof_status`.
//
// States
// ------
// Open        - dispute submitted, response pending.
// Responded   - issuer/source submitted a response commitment; admin decision pending.
// Resolved    - admin resolved the dispute (corrective action taken or noted).
// Dismissed   - admin dismissed the dispute (no corrective action).
// Superseded  - the disputed proof was superseded by a corrected proof.
//
// Valid transitions
// -----------------
// Open -> Responded  (by issuer/source of the proof, within respond_deadline)
// Open -> Dismissed  (by admin at any time)
// Open -> Superseded (by admin when a correcting proof is linked)
// Responded -> Resolved  (by admin, within resolve_deadline after response)
// Responded -> Dismissed (by admin at any time after response)
// Responded -> Superseded (by admin when a correcting proof is linked)
//
// Resolved, Dismissed, Superseded are terminal states.
//
// Spam / abuse controls
// ---------------------
// - MAX_OPEN_DISPUTES_PER_PROOF (4): cap on simultaneously Open disputes for
//   a single proof. Prevents resource exhaustion.
// - REPORTER_COOLDOWN_SECS (86400, 24 h): minimum interval between disputes
//   opened by the same reporter_hash for the same proof.
// - Deadlines stored in the record; callers / indexers can observe them.
//
// Privacy
// -------
// The reporter's identity is stored as a caller-supplied commitment
// (reporter_hash = H(reporter_address || proof_id)) rather than in the clear.
// This allows duplicate/spam detection without leaking the reporter address in
// contract storage that is world-readable on-chain.

/// Maximum number of simultaneously Open disputes allowed per proof.
pub const MAX_OPEN_DISPUTES_PER_PROOF: u32 = 4;
/// Maximum number of simultaneously Open disputes allowed across all proofs per reporter.
pub const MAX_OPEN_DISPUTES_PER_REPORTER: u32 = 5;
/// Minimum seconds between consecutive disputes by the same reporter on the
/// same proof (24 hours).
pub const REPORTER_COOLDOWN_SECS: u64 = 86_400;
/// Seconds from dispute open until the issuer/source must respond (7 days).
pub const RESPOND_DEADLINE_SECS: u64 = 604_800;
/// Seconds from response until the admin must resolve or dismiss (14 days).
pub const RESOLVE_DEADLINE_SECS: u64 = 1_209_600;
/// Maximum number of dispute IDs returned by a single `list_proof_disputes` call.
pub const MAX_PROOF_DISPUTES_PAGE: u32 = 50;

/// Dispute state transitions. Numeric values are stable on-chain identifiers;
/// do not renumber existing variants.
#[contracttype]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u32)]
pub enum DisputeStatus {
    Open = 1,
    Responded = 2,
    Resolved = 3,
    Dismissed = 4,
    Superseded = 5,
}

/// Categorised dispute reasons. Numeric values are stable on-chain; do not
/// renumber.
#[contracttype]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u32)]
pub enum DisputeReason {
    ContentError = 1,
    MetadataError = 2,
    TierMismatch = 3,
    CredentialLapsed = 4,
    PrivacyViolation = 5,
    Other = 6,
}

/// Immutable dispute record. Only `status`, `response_commitment`,
/// `resolve_deadline`, `resolved_at`, and `superseded_by` are mutated after
/// initial creation; the rest are set once at open time.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DisputeRecord {
    /// Unique dispute identifier (caller-supplied, 32-byte opaque commitment).
    pub dispute_id: BytesN<32>,
    /// The proof this dispute challenges.
    pub proof_id: BytesN<32>,
    /// Categorised reason for the dispute.
    pub reason: DisputeReason,
    /// Privacy-safe commitment: H(reporter_address_bytes || proof_id_bytes).
    /// Used for the per-proof cooldown and emitted in events.
    pub reporter_hash: BytesN<32>,
    /// Off-chain commitment to the reporter's full evidence submission.
    pub commitment_hash: BytesN<32>,
    /// Address of the reporter who opened this dispute.
    pub reporter: Address,
    /// Current lifecycle state.
    pub status: DisputeStatus,
    /// Ledger timestamp when the dispute was opened.
    pub opened_at: u64,
    /// Ledger timestamp by which the issuer/source must respond.
    pub respond_deadline: u64,
    /// Ledger timestamp by which the admin must decide after a response.
    /// Set to 0 until a response is submitted.
    pub resolve_deadline: u64,
    /// Issuer/source commitment hash in response. None until Responded.
    pub response_commitment: Option<BytesN<32>>,
    /// Ledger timestamp of final resolution/dismissal. 0 while open.
    pub resolved_at: u64,
    /// Proof ID that supersedes the disputed proof, if Superseded.
    pub superseded_by: Option<BytesN<32>>,
}

// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// Timestamp claim events (#339) — commitments and ledger metadata only
// ---------------------------------------------------------------------------

#[contractevent(topics = ["timestamp", "anchor"])]
pub struct TimestampClaimAnchored {
    #[topic]
    pub proof_id: BytesN<32>,
    pub attestation_digest: BytesN<32>,
    pub sources: u32,
    pub assurance: u32,
    pub anchored_at: u64,
    pub ledger_sequence: u32,
}

// Dispute events (privacy-safe: commitments and timestamps only)
// ---------------------------------------------------------------------------

#[contractevent(topics = ["dispute", "open"])]
pub struct DisputeOpened {
    #[topic]
    pub dispute_id: BytesN<32>,
    #[topic]
    pub proof_id: BytesN<32>,
    pub reason: DisputeReason,
    pub reporter_hash: BytesN<32>,
    pub commitment_hash: BytesN<32>,
    pub respond_deadline: u64,
}

#[contractevent(topics = ["dispute", "respond"])]
pub struct DisputeResponded {
    #[topic]
    pub dispute_id: BytesN<32>,
    #[topic]
    pub proof_id: BytesN<32>,
    pub response_commitment: BytesN<32>,
    pub resolve_deadline: u64,
}

#[contractevent(topics = ["dispute", "resolve"])]
pub struct DisputeResolved {
    #[topic]
    pub dispute_id: BytesN<32>,
    #[topic]
    pub proof_id: BytesN<32>,
    pub resolved_at: u64,
}

#[contractevent(topics = ["dispute", "dismiss"])]
pub struct DisputeDismissed {
    #[topic]
    pub dispute_id: BytesN<32>,
    #[topic]
    pub proof_id: BytesN<32>,
    pub resolved_at: u64,
}

#[contractevent(topics = ["dispute", "supersede"])]
pub struct DisputeSuperseded {
    #[topic]
    pub dispute_id: BytesN<32>,
    #[topic]
    pub proof_id: BytesN<32>,
    pub superseded_by: BytesN<32>,
    pub resolved_at: u64,
}

// ---------------------------------------------------------------------------
// Signed receipt digest commitment (#337)
// ---------------------------------------------------------------------------

/// Admin-managed receipt-signing key record. `public_key` is a SEC-1
/// encoded uncompressed P-256 point (`0x04 || X || Y`); public keys are not
/// secrets, and no private key material is ever stored.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReceiptSignerRecord {
    pub public_key: BytesN<65>,
    /// False once revoked. Revocation is recorded rather than deleted so an
    /// operator can distinguish "revoked" from "never registered".
    pub active: bool,
    pub added_at: u64,
    /// 0 while the signer is active.
    pub revoked_at: u64,
}

/// Immutable commitment to a signed verification receipt for one proof.
///
/// Privacy: every field is a commitment, an address, an identifier, or a
/// timestamp. No receipt bytes, media, metadata hashes, witness values,
/// signatures, or private keys are stored.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReceiptCommitmentRecord {
    pub proof_id: BytesN<32>,
    /// `sha256(canonical_json(signed_verification_receipt))`.
    pub receipt_digest: BytesN<32>,
    /// Identity tier of the committed proof at commit time (1, 2, or 3).
    pub tier: u32,
    /// The attesting receipt-signing public key.
    pub public_key: BytesN<65>,
    /// Address that authorized the commit (proof subject or admin).
    pub committed_by: Address,
    pub committed_at: u64,
}

/// Emitted on the first successful commit for a proof. Idempotent retries
/// emit nothing, so exactly one `["receipt", "commit"]` exists per proof.
#[contractevent(topics = ["receipt", "commit"])]
pub struct ReceiptDigestCommitted {
    #[topic]
    pub proof_id: BytesN<32>,
    pub receipt_digest: BytesN<32>,
    pub tier: u32,
    pub public_key: BytesN<65>,
    pub committed_at: u64,
}

#[contractevent(topics = ["signer", "add"])]
pub struct ReceiptSignerAdded {
    #[topic]
    pub public_key: BytesN<65>,
    pub added_at: u64,
}

#[contractevent(topics = ["signer", "revoke"])]
pub struct ReceiptSignerRevocation {
    #[topic]
    pub public_key: BytesN<65>,
    pub revoked_at: u64,
}

/// Schema record for issuer-certified attribute schemas.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SchemaRecord {
    pub schema_hash: BytesN<32>,
    pub issuer_namespace: BytesN<32>,
    pub version: u32,
    pub active: bool,
    pub attribute_count: u32,
    pub created_at: u64,
}

#[contractevent(topics = ["schema", "add"])]
pub struct SchemaAdded {
    #[topic]
    pub schema_hash: BytesN<32>,
    pub issuer_namespace: BytesN<32>,
    pub version: u32,
    pub attribute_count: u32,
}

#[contractevent(topics = ["schema", "deprecate"])]
pub struct SchemaDeprecated {
    #[topic]
    pub schema_hash: BytesN<32>,
}

#[contractevent(topics = ["seldisc", "verify"])]
pub struct SelectiveDisclosureVerified {
    #[topic]
    pub schema_hash: BytesN<32>,
    pub credential_root: BytesN<32>,
    pub nullifier: BytesN<32>,
    pub evidence_digest: BytesN<32>,
}

/// Domain separator that binds non-revocation proofs to the Harpocrates
/// revocation witness circuit version.  Both the Noir circuit and this
/// contract use the same constant.  Changing the circuit requires updating
/// this value to prevent proof replay across protocol versions.
///
/// Format: 32-byte big-endian BN254 field element serialization of
///   `0x484152504f4352415445535f5245564f434154494f4e5f5631`
/// which represents the ASCII string "HARPOCRATES_REVOCATION_V1" as a
/// 192-bit integer.  The 8 leading zero bytes come from the BN254 field
/// serialisation (field elements are padded to 32 bytes).
///
/// Layout:
///   [ 0.. 8)  leading zeros (BN254 field padding)
///   [ 8..32)  "HARPOCRATES_REVOCATION_V1" (24 ASCII bytes)
const REVOCATION_DOMAIN_SEPARATOR: [u8; 32] = [
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // 7 leading zeros (BN254 padding)
    0x48, 0x41, 0x52, 0x50, 0x4f, 0x43, 0x52, 0x41, // HARPOCRA
    0x54, 0x45, 0x53, 0x5f, 0x52, 0x45, 0x56, 0x4f, // TES_REVO
    0x43, 0x41, 0x54, 0x49, 0x4f, 0x4e, 0x5f, 0x56, // CATION_V
    0x31, // 1
];

/// Domain separator for the scoped nullifier v1 circuit.
/// "HARPOCRATES_SCOPED_NULLIFIER_V1" encoded as a 32-byte BN254 field element
/// (31 ASCII bytes with a leading 0x00 pad).
#[allow(dead_code)]
const SCOPED_NULLIFIER_V1_DOMAIN: [u8; 32] = [
    0x00, // leading zero (BN254 field padding)
    0x48, 0x41, 0x52, 0x50, 0x4f, 0x43, 0x52, 0x41, // HARPOCRA
    0x54, 0x45, 0x53, 0x5f, 0x53, 0x43, 0x4f, 0x50, // TES_SCOP
    0x45, 0x44, 0x5f, 0x4e, 0x55, 0x4c, 0x4c, 0x49, // ED_NULLI
    0x46, 0x49, 0x45, 0x52, 0x5f, 0x56, 0x31, // FIER_V1
];

/// Protocol domain constant ("harpocrates" SHA-256 field element).
pub const DOMAIN_PROTOCOL_FIELD: [u8; 32] = [
    0x26, 0x1e, 0x9f, 0x6e, 0x39, 0xe3, 0xc1, 0xae, 0x6a, 0xca, 0x9f, 0x29, 0xe8, 0x4c, 0x10, 0xd5,
    0x9c, 0x82, 0xd5, 0xf4, 0xb4, 0x0c, 0x21, 0xc1, 0xb7, 0xe3, 0xc0, 0x1a, 0xd5, 0x71, 0xc2, 0x01,
];

/// Circuit version domain constant ("1" SHA-256 field element).
pub const DOMAIN_VERSION_FIELD: [u8; 32] = [
    0x0c, 0x89, 0xef, 0xf4, 0xec, 0x8e, 0x39, 0xa0, 0x1e, 0x9f, 0x19, 0x54, 0x7a, 0x0c, 0xc9, 0xdd,
    0x7f, 0xd2, 0xa9, 0x7d, 0x79, 0xba, 0x4d, 0x94, 0xfd, 0x32, 0xe9, 0x7a, 0x1f, 0x5a, 0xc6, 0x23,
];

/// Target network domain constant ("testnet" SHA-256 field element).
pub const DOMAIN_NETWORK_FIELD: [u8; 32] = [
    0x2a, 0x2c, 0x3f, 0x48, 0xce, 0x2e, 0x3c, 0x2f, 0x1e, 0x6c, 0x89, 0xb1, 0x8d, 0x64, 0xb5, 0xf5,
    0xc1, 0xf8, 0x8a, 0x59, 0xa0, 0xd9, 0xbc, 0x82, 0xcb, 0x61, 0xa1, 0xe8, 0xcb, 0x77, 0xa5, 0x0f,
];

/// Expected length of v1 public inputs (5 × 32 = 160 bytes, including domain_tag).
const SILENT_WITNESS_V1_INPUT_LEN: u32 = 160;

/// Expected length of v1 browser public inputs (4 × 32 = 128 bytes, shipped in frontend/public/noir/silent_witness.json).
const SILENT_WITNESS_BROWSER_V1_INPUT_LEN: u32 = 128;

/// Length of the superseded bare v2 scoped frame (7 x 32 = 224 bytes, including
/// domain_tag). It commits no circuit version, so a verifier could only *infer*
/// one from the length. `register_anonymous_verified` rejects it outright with
/// [`RegistryError::CircuitVersionMismatch`]; it is declared here only so that
/// the rejection has a named, documented length instead of falling through to
/// the generic `InvalidPublicInputs` arm.
const SILENT_WITNESS_V2_BARE_INPUT_LEN: u32 = 224;

/// Expected length of the circuit-versioned v2 envelope (#368): the 224-byte
/// scoped frame plus a trailing 32-byte `circuit_version` field element. This
/// is the `silent_witness/v2` frame of the canonical codec, so the length comes
/// from [`verifier_inputs::SILENT_WITNESS_V2_PUBLIC_INPUTS_LEN`] rather than
/// being restated here.
///
/// [`HarpocratesRegistry::register_anonymous_verified`] accepts only this frame
/// for the v2 path; a trailer other than
/// [`verifier_inputs::EXPECTED_CIRCUIT_VERSION`] is rejected with
/// [`RegistryError::CircuitVersionMismatch`].
const SILENT_WITNESS_V2_ENVELOPED_INPUT_LEN: u32 =
    verifier_inputs::SILENT_WITNESS_V2_PUBLIC_INPUTS_LEN as u32;

/// Byte offset of the trailing `circuit_version` field inside the envelope: the
/// envelope is the scoped frame followed by exactly one field element.
const CIRCUIT_VERSION_TRAILER_OFFSET: usize =
    verifier_inputs::SILENT_WITNESS_V2_PUBLIC_INPUTS_LEN - verifier_inputs::FIELD_LEN;

#[contractevent(topics = ["revroot", "set"])]
pub struct RevocationRootSet {
    #[topic]
    pub revocation_root: BytesN<32>,
}

#[contractevent(topics = ["nonrev", "check"])]
pub struct NonRevocationChecked {
    #[topic]
    pub credential_root: BytesN<32>,
    pub nullifier: BytesN<32>,
    pub revocation_root: BytesN<32>,
}

#[contractevent(topics = ["pause", "set"])]
pub struct DomainPaused {
    #[topic]
    pub domain: u32,
    pub paused_by: Address,
    pub paused_at: u64,
    pub expires_at: u64,
}

#[contractevent(topics = ["pause", "clear"])]
pub struct DomainUnpaused {
    #[topic]
    pub domain: u32,
    pub unpaused_by: Address,
    pub unpaused_at: u64,
}

#[contractevent(topics = ["guardian", "set"])]
pub struct GuardianSet {
    #[topic]
    pub guardian: Address,
}

#[contractevent(topics = ["guardian", "clear"])]
pub struct GuardianCleared {}

#[contractevent(topics = ["admin", "propose"])]
pub struct AdminProposed {
    #[topic]
    pub pending_admin: Address,
    pub current_admin: Address,
}

#[contractevent(topics = ["admin", "cancel"])]
pub struct AdminTransferCancelled {
    #[topic]
    pub pending_admin: Address,
    pub current_admin: Address,
}

#[contractevent(topics = ["admin", "accept"])]
pub struct AdminAccepted {
    #[topic]
    pub new_admin: Address,
    pub previous_admin: Address,
}

#[contractevent(topics = ["scope", "epoch"])]
pub struct ScopeEpochSet {
    #[topic]
    pub scope: BytesN<32>,
    pub epoch: u64,
}

// ---------------------------------------------------------------------------
// Timelock proposal events (#86)
// ---------------------------------------------------------------------------

#[contractevent(topics = ["timelock", "propose"])]
pub struct TimelockProposalCreated {
    #[topic]
    pub proposal_id: u32,
    pub action: u32,
    #[topic]
    pub proposer: Address,
    pub target: Address,
    pub created_at: u64,
    pub min_execution_at: u64,
}

#[contractevent(topics = ["timelock", "cancel"])]
pub struct TimelockProposalCancelled {
    #[topic]
    pub proposal_id: u32,
    pub action: u32,
    #[topic]
    pub cancelled_by: Address,
    pub cancelled_at: u64,
}

#[contractevent(topics = ["timelock", "exec"])]
pub struct TimelockProposalExecuted {
    #[topic]
    pub proposal_id: u32,
    pub action: u32,
    #[topic]
    pub executed_by: Address,
    pub executed_at: u64,
}

#[contractevent(topics = ["timelock", "emergency"])]
pub struct TimelockEmergencyExec {
    #[topic]
    pub proposal_id: u32,
    pub action: u32,
    #[topic]
    pub executed_by: Address,
    pub executed_at: u64,
}

// Two literal prefix topics max; the third is a `Symbol` field so the emitted
// topic list stays exactly `["timelock", "delay", "set", set_by]`.
#[contractevent(topics = ["timelock", "delay"])]
pub struct TimelockMinDelaySet {
    pub previous_delay: u64,
    pub new_delay: u64,
    #[topic]
    pub set: Symbol,
    #[topic]
    pub set_by: Address,
}

#[contracttype]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u32)]
pub enum SchemaVersion {
    V1 = 1,
    V2 = 2,
}

#[contractevent(topics = ["schema", "upgrade"])]
pub struct SchemaUpgraded {
    pub previous: u32,
    pub current: u32,
}

#[contractevent(topics = ["contract", "upgrade"])]
pub struct ContractUpgraded {
    pub old_wasm_hash: BytesN<32>,
    pub new_wasm_hash: BytesN<32>,
}

// ---------------------------------------------------------------------------
// Paginated verifier-set inspection
// ---------------------------------------------------------------------------
//
// `list_verifiers` returns a bounded, stable page of the current verifier
// configuration — the active slot, the pending slot (if a rotation is
// scheduled), and the previous slot (if within the rollback window).
//
// Design constraints:
//   - Callers supply a u32 `cursor` (slot index, 0-based) and a `limit` (max
//     entries per page). Cursor 0 starts at the first populated slot.
//   - A cursor beyond the end of the populated slot list returns an empty
//     page — not an error — so callers can safely probe with any cursor.
//   - `limit` must be non-zero and at most MAX_VERIFIER_LIST_LIMIT.
//   - No authentication is required (identical to `get_verifier`).
//   - Slots are always ordered: Active → Pending → Previous.
//     This ordering is stable across rotation events, so callers can page
//     incrementally without re-reading prior pages.
//   - Only populated (non-None) slots appear in `entries`, so the
//     `next_cursor` can skip unpopulated slots.
//   - `total_populated` exposes the total number of non-None slots at call
//     time; it is informational only and safe to expose because addresses
//     are already visible via `get_verifier` / `get_verifier_state`.
//
// Privacy invariants:
//   - No private witness values, credential secrets, video hashes, or
//     nullifiers are surfaced through this function.
//   - An out-of-range cursor returns a stable empty page (not a
//     revealing error) so a scanner cannot enumerate capacity by probing.
//
// Migration: These are new, additive storage keys and a new contract
// entry point. Existing deployments return an empty VerifierPage until
// `set_verifier` or a rotation is configured. Rolling back to a pre-this
// wasm simply removes the entry point; callers fall back to `get_verifier`.

/// Maximum number of verifier entries a single `list_verifiers` call may return.
pub const MAX_VERIFIER_LIST_LIMIT: u32 = 10;

/// The role of a verifier address in the current rotation state.
#[contracttype]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u32)]
pub enum VerifierRole {
    Active = 1,
    Pending = 2,
    Previous = 3,
}

/// A single verifier slot returned by `list_verifiers`.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VerifierEntry {
    /// The verifier contract address for this slot.
    pub address: Address,
    /// The role of this verifier in the current configuration.
    pub role: VerifierRole,
}

/// Paginated result from `list_verifiers`.
///
/// `entries` contains up to `limit` `VerifierEntry` items in slot order
/// (Active → Pending → Previous). Only non-None slots are included.
///
/// `next_cursor` is `Some(offset)` when more items exist beyond this page,
/// or `None` when the page is the last (or only) page. Pass `next_cursor`
/// as the `cursor` argument in the subsequent call.
///
/// `total_populated` is the total count of populated (non-None) verifier
/// slots at the time of the query. It is always ≤ 3.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VerifierPage {
    pub entries: SorobanVec<VerifierEntry>,
    pub next_cursor: Option<u32>,
    pub total_populated: u32,
}

#[contractevent(topics = ["ttl", "maintain"])]
pub struct TTLMaintained {
    pub count: u32,
}

#[contractevent(topics = ["ttl", "instance"])]
pub struct InstanceTTLMaintained;

#[contracttype]
pub enum DataKey {
    Admin,
    Proof(BytesN<32>),
    Video(BytesN<32>),
    Nullifier(BytesN<32>),
    CredentialRoot(BytesN<32>),
    CredentialRootV2(BytesN<32>),
    /// Sequential counter for credential root index (#731).
    CredentialRootSeq,
    /// Credential root index entry by sequential ID (1-based) (#731).
    CredentialRootIndex(u32),
    /// Tracking index presence by root hash for idempotency (#731).
    CredentialRootIndexed(BytesN<32>),
    /// Staged credential roots for backfill during upgrade_storage (#731).
    CredentialRootsBackfillQueue,
    /// Cursor for backfill during upgrade_storage (#731).
    CredentialRootsBackfillCursor,
    /// Alias for backfill queue compatibility (#731).
    CredentialRootsBackfill,
    Issuer(Address),
    /// Rotation grace record for an issuer key that has rotated out (#323).
    IssuerRotation(Address),
    Verifier,
    ProofTtl,
    /// Optional emergency-pause guardian, distinct from admin (#87).
    Guardian,
    /// Pause record for a single registration domain bit (#87).
    Pause(u32),
    PendingAdmin,
    /// Merkle root of the credential-revocation tree (set by admin).
    RevocationRoot,
    ProofHistorySeq(BytesN<32>),
    ProofHistoryEntry(BytesN<32>, u32),
    /// Scoped, expiring delegation from a grantor to a delegate (#192).
    Delegation(Address, Address),
    /// Count of distinct delegate addresses held by a grantor (#192).
    DelegationCount(Address),
    /// Verifier rotation state (schedule/activate/rollback).
    VerifierState,
    /// Declared circuit-version window for the active verifier (#343).
    VerifierCircuitVersions,
    /// Storage schema version.
    SchemaVersion,
    /// Hash of the current active contract Wasm bytecode.
    WasmHash,
    /// Scope epoch for verifier-scope binding.
    ScopeEpoch(BytesN<32>),
    /// Sequential counter for timelock proposal IDs (#86).
    ProposalSeq,
    /// Timelock proposal by sequential ID (#86).
    Proposal(u32),
    /// Minimum timelock delay in seconds (#86).
    TimelockMinDelay,
    /// Schema definition by schema hash.
    Schema(BytesN<32>),
    /// Verifiable derivative lineage record keyed by output digest.
    Lineage(BytesN<32>),
    /// Independent timestamp claim keyed by proof_id (#339).
    TimestampClaim(BytesN<32>),
    /// Count of indexed children for a parent proof/digest (#335).
    LineageChildSeq(BytesN<32>),
    /// Child output digest at 1-based sequence for a parent (#335).
    LineageChild(BytesN<32>, u32),
    /// Versioned metadata envelope binding keyed by proof_id (#317).
    MetadataEnvelope(BytesN<32>),
    /// Stores the `DisputeRecord` for a given dispute_id (#dispute).
    Dispute(BytesN<32>),
    /// Counts open (non-terminal) disputes for a proof_id (#dispute).
    /// Used to enforce MAX_OPEN_DISPUTES_PER_PROOF.
    ProofOpenDisputeCount(BytesN<32>),
    /// Counts open (non-terminal) disputes across all proofs for a reporter Address.
    /// Used to enforce MAX_OPEN_DISPUTES_PER_REPORTER.
    ReporterOpenDisputeCount(Address),
    /// Tracks the last-opened timestamp for a reporter_hash/proof pair.
    /// Key is the caller-supplied `reporter_hash` (a 32-byte commitment).
    ReporterCooldown(BytesN<32>),
    /// Scoped nullifier separated by verifier address context (#325).
    VerifierNullifier(Address, BytesN<32>),
    /// Sequential counter for disputes indexed under a proof_id (#dispute).
    ProofDisputeSeq(BytesN<32>),
    /// Dispute ID at 1-based sequence for a proof_id (#dispute).
    ProofDispute(BytesN<32>, u32),
}

#[contracterror]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u32)]
pub enum RegistryError {
    AlreadyInitialized = 1,
    NotInitialized = 2,
    Unauthorized = 3,
    DuplicateProof = 4,
    DuplicateVideo = 5,
    DuplicateNullifier = 6,
    InvalidProof = 7,
    UnknownIssuer = 8,
    VerifierNotSet = 9,
    InvalidPublicInputs = 10,
    UnknownCredentialRoot = 11,
    RevokedCredentialRoot = 12,
    HistorySaturated = 13,
    /// The scoped-nullifier proof carries an epoch that does not match the
    /// current on-chain epoch for its scope. Replaces the unused
    /// `InvalidHistoryAction` slot so the wire code does not change.
    StaleEpoch = 14,
    InvalidReasonCode = 15,
    HistoryLimitExceeded = 16,
    AlreadyExpired = 17,
    NoCorrectionChange = 18,
    HistoryCorruption = 19,
    NoPendingAdmin = 20,
    /// The requested operation is blocked by an active domain pause (#87).
    Paused = 21,
    /// `domain` was zero or contained bits outside the known pause domains.
    InvalidPauseDomain = 22,
    /// `duration_secs` was zero or exceeded the caller's role cap.
    InvalidPauseDuration = 23,
    /// `scope` was zero or contained bits outside `DELEGATION_SCOPE_ALL` (#192).
    InvalidDelegationScope = 24,
    /// `duration_secs` was zero or above `MAX_DELEGATION_DURATION_SECS` (#192).
    InvalidDelegationDuration = 25,
    /// No delegation exists from the named grantor to the caller (#192).
    DelegationNotFound = 26,
    /// The delegation exists but its `expires_at` has passed (#192).
    DelegationExpired = 27,
    /// The delegation exists and is live, but does not carry the scope the
    /// attempted operation requires (#192).
    DelegationScopeExceeded = 28,
    /// The grantor already holds `MAX_DELEGATIONS_PER_GRANTOR` delegates (#192).
    DelegationsSaturated = 29,
    /// A grantor may not delegate to itself (#192).
    SelfDelegation = 30,
    /// The requested timelock proposal does not exist (#86).
    ProposalNotFound = 31,
    ProposalNotReady = 32,
    ProposalAlreadyExecuted = 33,
    ProposalCancelled = 34,
    InvalidProposalAction = 35,
    InvalidProposalPayload = 36,
    ProposalsSaturated = 37,
    InvalidTimelockDelay = 38,
    AlreadyCancelled = 39,
    RotationNotScheduled = 40,
    RotationNotReady = 41,
    RotationWindowClosed = 42,
    BatchTooLarge = 43,
    InvalidScopeEpoch = 44,
    DisputeNotFound = 45,
    DisputeAlreadyResolved = 46,
    SupersessionCycleDetected = 47,
    SupersessionNotFound = 48,
    DomainTagMismatch = 49,
    UnknownSchema = 50,
    InactiveSchema = 51,
    SchemaVersionMismatch = 52,
    /// The cursor supplied to `list_verifiers` is out of range or malformed.
    /// Returns a stable, privacy-safe failure that does not reveal set size.
    InvalidCursor = 53,
    /// The `limit` supplied to `list_verifiers` exceeds `MAX_VERIFIER_LIST_LIMIT`.
    ListLimitExceeded = 54,
    // --- Restored feature errors (append-only; never renumber existing) ---
    /// A scoped-nullifier proof was generated for a stale scope epoch.
    StaleEpoch = 53,
    /// Batch aggregation was requested with zero or too many elements.
    BatchSizeExceeded = 54,
    /// Credential roots in a batch were not all identical.
    BatchCredentialRootMismatch = 55,
    /// The batch element count did not match the supplied video-hash list.
    BatchCountMismatch = 56,
    /// A lineage parent proof/lineage record was not found.
    InvalidLineage = 57,
    ExpiredCredentialRoot = 58,
    /// A lineage edge would introduce a cycle.
    LineageCycle = 58,
    /// The requested lineage depth exceeds `MAX_LINEAGE_DEPTH`.
    LineageTooDeep = 59,
    /// The requested lineage fan-out exceeds `MAX_LINEAGE_FANOUT`.
    LineageFanOutExceeded = 60,
    /// The proof already has `MAX_OPEN_DISPUTES_PER_PROOF` open disputes.
    TooManyOpenDisputes = 61,
    /// The respond/resolve deadline for this dispute transition has passed.
    DisputeWindowExpired = 62,
    /// The dispute is already in a terminal state.
    DisputeAlreadyClosed = 63,
    /// Supersession would create a cycle (direct or depth-1).
    DisputeCyclicSupersession = 64,
    /// The caller is not the proof's issuer/source (or admin for Tier 1).
    UnauthorizedResponder = 65,
    /// The reporter must wait out `REPORTER_COOLDOWN_SECS` before re-reporting.
    ReporterOnCooldown = 66,
    /// The dispute is not in the state this transition requires.
    InvalidDisputeTransition = 67,
    /// Timestamp claim is malformed, far-future, or missing required digest (#339).
    InvalidTimestampClaim = 72,
    /// No timestamp claim exists for the requested proof (#339).
    TimestampClaimNotFound = 73,
    /// A timestamp claim is already anchored and the update is not an upgrade (#339).
    TimestampClaimAlreadyAnchored = 74,
    /// Caller is neither admin nor the proof's source/issuer (#339).
    UnauthorizedTimestampActor = 75,
    /// Lineage registration supplied zero parents (commitments require ≥1).
    LineageEmptyParents = 76,
    /// A lineage parent proof is revoked or expired and cannot anchor a derivative.
    LineageParentUnavailable = 77,
    /// Lineage output digest is already registered.
    DuplicateLineage = 78,
    /// `list_lineage_children` limit was zero or above the page cap (#335).
    LineageChildrenLimitExceeded = 79,
    /// Parent already holds MAX_LINEAGE_CHILDREN_PER_PARENT children (#335).
    LineageChildrenSaturated = 80,
    /// Metadata envelope version is zero or above `METADATA_ENVELOPE_VERSION_MAX` (#317).
    UnsupportedMetadataEnvelopeVersion = 68,
    /// Metadata envelope hash is zero / malformed (#317).
    InvalidMetadataEnvelope = 69,
    /// No metadata envelope (and no proof) for the requested id (#317).
    MetadataEnvelopeNotFound = 70,
    /// Bound envelope hash does not match the proof's `metadata_hash` (#317).
    MetadataEnvelopeHashMismatch = 71,
    /// Proof declares a circuit version outside the active verifier's window (#343).
    UnsupportedCircuitVersion = 81,
    /// Requested circuit-version window is empty or outside the wasm range (#343).
    InvalidCircuitVersionRange = 82,
    /// Requested rotation grace window is above `MAX_ISSUER_ROTATION_GRACE_SECS`
    /// or overflows ledger time (#323).
    InvalidIssuerRotationGrace = 83,
    /// A rotation named the same issuer key twice; absent or inactive keys
    /// report `UnknownIssuer` instead (#323).
    InvalidIssuerRotation = 84,
    /// No issuer rotation grace record exists for the requested key (#323).
    IssuerRotationNotFound = 85,
    /// The issuer rotation grace window has not lapsed yet (#323).
    IssuerRotationGraceStillActive = 86,
    /// A scoped-nullifier envelope carried a `circuit_version` trailer other
    /// than [`verifier_inputs::EXPECTED_CIRCUIT_VERSION`], or was the superseded
    /// bare 224-byte frame that commits no circuit version at all (#368).
    CircuitVersionMismatch = 87,
    /// The reporter reached `MAX_OPEN_DISPUTES_PER_REPORTER`.
    ReporterDisputesSaturated = 88,
}

#[contract]
pub struct HarpocratesRegistry;

#[contractimpl]
impl HarpocratesRegistry {
    pub fn init(env: Env, admin: Address) {
        if env.storage().persistent().has(&DataKey::Admin) {
            panic_with_error!(&env, RegistryError::AlreadyInitialized);
        }

        admin.require_auth();
        env.storage().persistent().set(&DataKey::Admin, &admin);
        env.storage()
            .persistent()
            .set(&DataKey::SchemaVersion, &(SchemaVersion::V2 as u32));
    }

    /// Return the persistent storage schema version.
    ///
    /// Missing keys (pre-#85 deployments) are treated as V1 so callers and
    /// the upgrade harness stay compatible without a forced rewrite.
    pub fn get_storage_schema_version(env: Env) -> u32 {
        env.storage()
            .persistent()
            .get(&DataKey::SchemaVersion)
            .unwrap_or(SchemaVersion::V1 as u32)
    }

    /// Apply sequential storage migrations up to the current target schema.
    ///
    /// - Admin-only; unauthorized callers fail with `Unauthorized`.
    /// - Idempotent at the current target (V1): repeated calls are no-ops and
    ///   do not emit `SchemaUpgraded`.
    /// - Legacy deployments without `DataKey::SchemaVersion` are stamped to V1
    ///   without emitting `SchemaUpgraded` (layout already matches V1).
    /// - Future V2+ migrations land in the `current < target` branch and MUST
    ///   preserve existing proof / video / nullifier records and never log
    ///   media, secrets, witnesses, or private keys.
    ///
    /// Rollback: redeploying a prior wasm that ignores unknown keys leaves
    /// stamped `SchemaVersion` intact; V1 readers treat it as authoritative.
    pub fn upgrade_storage(env: Env, admin: Address) {
        require_admin(&env, &admin);

        let had_version = env.storage().persistent().has(&DataKey::SchemaVersion);
        let current_version: u32 = env
            .storage()
            .persistent()
            .get(&DataKey::SchemaVersion)
            .unwrap_or(SchemaVersion::V1 as u32);

        let target_version = SchemaVersion::V2 as u32;

        // Legacy pre-#85 registries: stamp V1 without a SchemaUpgraded event.
        if !had_version {
            env.storage()
                .persistent()
                .set(&DataKey::SchemaVersion, &(SchemaVersion::V1 as u32));
            // Current version conceptually becomes V1 here
        }

        let actual_current = if !had_version {
            SchemaVersion::V1 as u32
        } else {
            current_version
        };

        if actual_current < target_version {
            // Migrations will be added here when moving to V2, V3, etc.
            // V1 -> V2: Domain-separated nullifiers by verifier context (#325).
            // Legacy nullifiers are preserved, so no iterative key rewrite is required.

            env.storage()
                .persistent()
                .set(&DataKey::SchemaVersion, &target_version);

            SchemaUpgraded {
                previous: actual_current,
                current: target_version,
            }
            .publish(&env);
        }

        // Backfill legacy credential roots into the index (bounded per call) (#731).
        backfill_credential_roots_step(&env);
    }

    /// Return the active storage schema version. Legacy deployments that have
    /// not called `upgrade_storage` report `V1`; fresh V2 deployments report `V2`.
    pub fn get_schema_version(env: Env) -> u32 {
        env.storage()
            .persistent()
            .get(&DataKey::SchemaVersion)
            .unwrap_or(SchemaVersion::V1 as u32)
    }

    pub fn propose_admin(env: Env, admin: Address, pending_admin: Address) {
        require_admin(&env, &admin);
        require_admin_role_available(&env, &pending_admin);

        env.storage()
            .persistent()
            .set(&DataKey::PendingAdmin, &pending_admin);
        AdminProposed {
            pending_admin,
            current_admin: admin,
        }
        .publish(&env);
    }

    pub fn cancel_admin_transfer(env: Env, admin: Address) {
        require_admin(&env, &admin);

        let pending_admin: Address = env
            .storage()
            .persistent()
            .get(&DataKey::PendingAdmin)
            .unwrap_or_else(|| panic_with_error!(&env, RegistryError::NoPendingAdmin));
        env.storage().persistent().remove(&DataKey::PendingAdmin);
        AdminTransferCancelled {
            pending_admin,
            current_admin: admin,
        }
        .publish(&env);
    }

    pub fn accept_admin(env: Env, pending_admin: Address) {
        let proposed_admin: Address = env
            .storage()
            .persistent()
            .get(&DataKey::PendingAdmin)
            .unwrap_or_else(|| panic_with_error!(&env, RegistryError::NoPendingAdmin));

        pending_admin.require_auth();
        if proposed_admin != pending_admin {
            panic_with_error!(&env, RegistryError::Unauthorized);
        }
        require_admin_role_available(&env, &pending_admin);

        let previous_admin: Address = env
            .storage()
            .persistent()
            .get(&DataKey::Admin)
            .unwrap_or_else(|| panic_with_error!(&env, RegistryError::NotInitialized));
        env.storage()
            .persistent()
            .set(&DataKey::Admin, &pending_admin);
        env.storage().persistent().remove(&DataKey::PendingAdmin);
        AdminAccepted {
            new_admin: pending_admin,
            previous_admin,
        }
        .publish(&env);
    }

    pub fn add_issuer(env: Env, admin: Address, issuer: Address, metadata_hash: BytesN<32>) {
        require_admin(&env, &admin);
        require_issuer_role_available(&env, &issuer);
        if env
            .storage()
            .persistent()
            .get::<_, Address>(&DataKey::PendingAdmin)
            .as_ref()
            == Some(&issuer)
        {
            panic_with_error!(&env, RegistryError::RoleConflict);
        }

        env.storage().persistent().set(
            &DataKey::Issuer(issuer.clone()),
            &IssuerRecord {
                metadata_hash: metadata_hash.clone(),
                active: true,
            },
        );
        // Re-adding a key makes it the current key again, so a leftover
        // rotation grace record for it would be a second, contradictory answer
        // to `is_issuer_verifiable` (#323).
        env.storage()
            .persistent()
            .remove(&DataKey::IssuerRotation(issuer.clone()));
        IssuerAdded {
            issuer,
            metadata_hash,
        }
        .publish(&env);
    }

    pub fn set_verifier(env: Env, admin: Address, verifier: Address) {
        require_admin(&env, &admin);

        env.storage()
            .persistent()
            .set(&DataKey::Verifier, &verifier);
        env.storage().persistent().remove(&DataKey::VerifierState);
        // A freshly configured verifier has not declared a window yet; fall
        // back to the full built-in range rather than inheriting the previous
        // verifier's claim.
        env.storage()
            .persistent()
            .remove(&DataKey::VerifierCircuitVersions);
        VerifierSet { verifier }.publish(&env);
    }

    pub fn get_verifier(env: Env) -> Option<Address> {
        env.storage().persistent().get(&DataKey::Verifier)
    }

    /// Declare the circuit-version window the active verifier can check (#343).
    ///
    /// Admin-only and additive. `min_version..=max_version` must lie inside
    /// this wasm build's own supported range; an empty or out-of-range window
    /// fails with the stable `InvalidCircuitVersionRange` code rather than
    /// being silently clamped. Once declared, every proof-verifying entry point
    /// refuses a proof whose circuit version falls outside the window *before*
    /// the external verifier is invoked, so an unsupported version can never
    /// reach a dependency that cannot answer.
    ///
    /// Restore the default by setting the window back to
    /// `MIN_SUPPORTED_CIRCUIT_VERSION..=MAX_SUPPORTED_CIRCUIT_VERSION`.
    pub fn set_verifier_circuit_versions(
        env: Env,
        admin: Address,
        min_version: u32,
        max_version: u32,
    ) {
        require_admin(&env, &admin);

        if min_version > max_version
            || min_version < MIN_SUPPORTED_CIRCUIT_VERSION
            || max_version > MAX_SUPPORTED_CIRCUIT_VERSION
        {
            panic_with_error!(&env, RegistryError::InvalidCircuitVersionRange);
        }

        let verifier = get_active_verifier(&env);
        env.storage().persistent().set(
            &DataKey::VerifierCircuitVersions,
            &VerifierCircuitVersions {
                min_version,
                max_version,
                set_by: admin,
                set_at: env.ledger().timestamp(),
            },
        );
        VerifierCircuitVersionsSet {
            verifier,
            min_version,
            max_version,
        }
        .publish(&env);
    }

    /// The active verifier's circuit-version window (#343).
    ///
    /// An undeclared window answers as the full built-in range, so a pre-#343
    /// deployment reports what it actually enforces instead of erroring.
    pub fn get_verifier_circuit_versions(env: Env) -> VerifierCircuitVersions {
        match env
            .storage()
            .persistent()
            .get::<DataKey, VerifierCircuitVersions>(&DataKey::VerifierCircuitVersions)
        {
            Some(record) => record,
            None => VerifierCircuitVersions {
                min_version: MIN_SUPPORTED_CIRCUIT_VERSION,
                max_version: MAX_SUPPORTED_CIRCUIT_VERSION,
                set_by: env
                    .storage()
                    .persistent()
                    .get(&DataKey::Admin)
                    .unwrap_or_else(|| panic_with_error!(&env, RegistryError::NotInitialized)),
                set_at: 0,
            },
        }
    }

    /// Read-only: may a proof carrying `version` be accepted right now?
    ///
    /// True only when `version` is both framable by this wasm build and inside
    /// the active verifier's declared window. Callers can pre-flight without a
    /// trial transaction.
    pub fn is_supported_circuit_version(env: Env, version: u32) -> bool {
        if version < MIN_SUPPORTED_CIRCUIT_VERSION || version > MAX_SUPPORTED_CIRCUIT_VERSION {
            return false;
        }
        let (min_version, max_version) = get_verifier_circuit_versions_raw(&env);
        version >= min_version && version <= max_version
    }

    pub fn schedule_verifier_rotation(
        env: Env,
        admin: Address,
        verifier: Address,
        activation_ledger: u64,
        overlap_window: u64,
        rollback_window: u64,
    ) {
        require_admin(&env, &admin);

        let active_verifier = get_active_verifier(&env);
        let state = VerifierState {
            active_verifier: Some(active_verifier.clone()),
            pending_verifier: Some(verifier.clone()),
            previous_verifier: Some(active_verifier.clone()),
            activation_ledger,
            overlap_window,
            rollback_window,
            rollback_window_end: activation_ledger.saturating_add(rollback_window),
        };
        env.storage()
            .persistent()
            .set(&DataKey::VerifierState, &state);
        VerifierRotationScheduled {
            active_verifier: active_verifier.clone(),
            pending_verifier: verifier.clone(),
            activation_ledger,
            overlap_window,
            rollback_window,
        }
        .publish(&env);
    }

    pub fn activate_verifier_rotation(env: Env, admin: Address) {
        require_admin(&env, &admin);

        let mut state = get_verifier_rotation_state(&env);
        let pending_verifier = state
            .pending_verifier
            .clone()
            .unwrap_or_else(|| panic_with_error!(&env, RegistryError::RotationNotScheduled));
        let active_verifier = state
            .active_verifier
            .clone()
            .unwrap_or_else(|| panic_with_error!(&env, RegistryError::RotationNotScheduled));
        let current_ledger = u64::from(env.ledger().sequence());
        if current_ledger < state.activation_ledger {
            panic_with_error!(&env, RegistryError::RotationNotReady);
        }

        state.active_verifier = Some(pending_verifier.clone());
        state.pending_verifier = None;
        state.rollback_window_end = current_ledger.saturating_add(state.rollback_window.max(0));
        env.storage()
            .persistent()
            .set(&DataKey::VerifierState, &state);
        env.storage()
            .persistent()
            .set(&DataKey::Verifier, &pending_verifier);
        // The incoming verifier must declare its own window; do not inherit the
        // outgoing verifier's circuit-version claim.
        env.storage()
            .persistent()
            .remove(&DataKey::VerifierCircuitVersions);
        VerifierRotationActivated {
            active_verifier: pending_verifier,
            previous_verifier: active_verifier,
            rollback_window_end: state.rollback_window_end,
        }
        .publish(&env);
    }

    pub fn rollback_verifier_rotation(env: Env, admin: Address) {
        require_admin(&env, &admin);

        let state = get_verifier_rotation_state(&env);
        let active_verifier = state
            .active_verifier
            .clone()
            .unwrap_or_else(|| panic_with_error!(&env, RegistryError::RotationNotScheduled));
        let previous_verifier = state
            .previous_verifier
            .clone()
            .unwrap_or_else(|| panic_with_error!(&env, RegistryError::RotationNotScheduled));
        let current_ledger = u64::from(env.ledger().sequence());
        if state.rollback_window_end == 0 || current_ledger > state.rollback_window_end {
            panic_with_error!(&env, RegistryError::RotationWindowClosed);
        }

        env.storage()
            .persistent()
            .set(&DataKey::Verifier, &previous_verifier);
        env.storage().persistent().remove(&DataKey::VerifierState);
        env.storage()
            .persistent()
            .remove(&DataKey::VerifierCircuitVersions);
        VerifierRotationRolledBack {
            active_verifier: previous_verifier.clone(),
            previous_verifier: active_verifier,
        }
        .publish(&env);
    }

    pub fn get_verifier_state(env: Env) -> VerifierState {
        get_verifier_rotation_state(&env)
    }

    pub fn add_credential_root(
        env: Env,
        admin: Address,
        credential_root: BytesN<32>,
        metadata_hash: BytesN<32>,
    ) {
        require_admin(&env, &admin);

        let issued_at = env.ledger().timestamp();
        env.storage().persistent().set(
            &DataKey::CredentialRootV2(credential_root.clone()),
            &CredentialRootRecord {
                metadata_hash: metadata_hash.clone(),
                status: STATUS_REGISTERED,
                issued_at,
                expires_at: 0,
            },
        );
        index_credential_root(&env, &credential_root);
        CredentialRootAdded {
            credential_root,
            metadata_hash,
            issued_at,
        }
        .publish(&env);
    }

    pub fn revoke_credential_root(env: Env, admin: Address, credential_root: BytesN<32>) {
        require_admin(&env, &admin);

        let mut record = get_credential_root_record(&env, &credential_root);
        record.status = STATUS_REVOKED;
        env.storage()
            .persistent()
            .set(&DataKey::CredentialRootV2(credential_root.clone()), &record);
        CredentialRootRevoked { credential_root }.publish(&env);
    }

    pub fn expire_credential_root(env: Env, admin: Address, credential_root: BytesN<32>) {
        require_admin(&env, &admin);

        let mut record = get_credential_root_record(&env, &credential_root);
        record.status = STATUS_EXPIRED;
        record.expires_at = env.ledger().timestamp();
        env.storage()
            .persistent()
            .set(&DataKey::CredentialRootV2(credential_root.clone()), &record);
        CredentialRootExpired { credential_root, expired_at: record.expires_at }.publish(&env);
    }

    pub fn get_credential_root(
        env: Env,
        credential_root: BytesN<32>,
    ) -> Option<CredentialRootRecord> {
        env.storage()
            .persistent()
            .get(&DataKey::CredentialRoot(credential_root))
    }

    /// Return the total number of indexed credential roots (#731).
    pub fn get_credential_root_count(env: Env) -> u32 {
        env.storage()
            .persistent()
            .get(&DataKey::CredentialRootSeq)
            .unwrap_or(0u32)
    }

    /// Enumerate credential roots and their current statuses across sequential IDs (#731).
    ///
    /// - `cursor`: ID offset to start scanning from (1-based sequential IDs).
    ///   If `cursor == 0`, scanning begins at ID 1.
    /// - `limit`: maximum number of roots to return; capped at `MAX_CREDENTIAL_ROOTS_PAGE`.
    ///   If 0 or exceeding the cap, `limit` is clamped to `MAX_CREDENTIAL_ROOTS_PAGE`.
    /// - Non-existent/deleted entries are skipped.
    /// - Read-only query; no auth required.
    pub fn list_credential_roots(
        env: Env,
        cursor: u32,
        limit: u32,
    ) -> CredentialRootPage {
        let effective_limit = if limit == 0 || limit > MAX_CREDENTIAL_ROOTS_PAGE {
            MAX_CREDENTIAL_ROOTS_PAGE
        } else {
            limit
        };

        let total_seq: u32 = env
            .storage()
            .persistent()
            .get(&DataKey::CredentialRootSeq)
            .unwrap_or(0u32);

        let mut roots = SorobanVec::new(&env);
        let mut next_cursor: Option<u32> = None;

        let mut id = if cursor == 0 { 1u32 } else { cursor };

        while id <= total_seq {
            if let Some(root) = env
                .storage()
                .persistent()
                .get::<_, BytesN<32>>(&DataKey::CredentialRootIndex(id))
            {
                if let Some(record) = get_credential_root_record_opt(&env, &root) {
                    let status = if record.status == STATUS_EXPIRED
                        || (record.expires_at > 0 && env.ledger().timestamp() >= record.expires_at)
                    {
                        STATUS_EXPIRED
                    } else {
                        record.status
                    };
                    roots.push_back(CredentialRootEntry {
                        root_hash: root,
                        status,
                    });
                    if roots.len() == effective_limit {
                        if id < total_seq {
                            next_cursor = Some(id + 1);
                        }
                        break;
                    }
                }
            }
            id = id.saturating_add(1);
        }

        CredentialRootPage {
            roots,
            next_cursor,
        }
    }

    /// Stage or queue legacy credential roots for bounded backfill during `upgrade_storage` (#731).
    pub fn stage_credential_roots_for_backfill(
        env: Env,
        admin: Address,
        roots: SorobanVec<BytesN<32>>,
    ) {
        require_admin(&env, &admin);
        let backfill_key = DataKey::CredentialRootsBackfillQueue;
        let mut queue: SorobanVec<BytesN<32>> = env
            .storage()
            .persistent()
            .get(&backfill_key)
            .unwrap_or_else(|| SorobanVec::new(&env));
        for r in roots.iter() {
            queue.push_back(r);
        }
        env.storage().persistent().set(&backfill_key, &queue);
    }

    pub fn revoke_issuer(env: Env, admin: Address, issuer: Address) {
        require_admin(&env, &admin);

        let mut record = get_issuer_record(&env, &issuer);
        record.active = false;
        env.storage()
            .persistent()
            .set(&DataKey::Issuer(issuer.clone()), &record);
        // Revocation outranks any rotation grace window: a withdrawn or
        // compromised key must never keep standing through a rotation record
        // (#323).
        env.storage()
            .persistent()
            .remove(&DataKey::IssuerRotation(issuer.clone()));
        IssuerRevoked { issuer }.publish(&env);
    }

    /// Update an active issuer's metadata hash.
    ///
    /// Requires admin auth and that `issuer` is active.
    /// Only the metadata hash changes; active status and any rotation grace
    /// records are preserved.
    ///
    /// # Reverts
    ///
    /// - `Unauthorized` if `admin` is not the current admin
    /// - `UnknownIssuer` if `issuer` does not exist or is inactive
    pub fn update_issuer_metadata(
        env: Env,
        admin: Address,
        issuer: Address,
        metadata_hash: BytesN<32>,
    ) {
        require_admin(&env, &admin);

        let mut record = get_issuer_record(&env, &issuer);
        if !record.active {
            panic_with_error!(&env, RegistryError::UnknownIssuer);
        }

        let previous_metadata_hash = record.metadata_hash;
        record.metadata_hash = metadata_hash.clone();
        env.storage()
            .persistent()
            .set(&DataKey::Issuer(issuer.clone()), &record);

        IssuerMetadataUpdated {
            issuer,
            previous_metadata_hash,
            new_metadata_hash: metadata_hash,
        }
        .publish(&env);
    }

    /// Rotate an active issuer key to a replacement, opening a bounded grace
    /// window over the retiring key's pre-rotation evidence (#323).
    ///
    /// Admin-only. `previous_issuer` and `replacement_issuer` must be distinct,
    /// both registered, and both active. The rotation retires `previous_issuer`
    /// immediately — it can no longer sign new seals, directly or through a
    /// delegation — while the evidence it already signed stays verifiable until
    /// `grace_expires_at`, after which [`Self::is_issuer_verifiable`] fails
    /// closed.
    ///
    /// `grace_secs == 0` selects [`DEFAULT_ISSUER_ROTATION_GRACE_SECS`].
    /// Returns the absolute `grace_expires_at` so a caller can record the
    /// deadline without re-reading storage. The window is lazy — it lapses with
    /// no transaction — and [`Self::finalize_issuer_rotation`] settles the
    /// record afterwards.
    ///
    /// # Reverts
    ///
    /// - `Unauthorized`               if the caller is not the admin
    /// - `InvalidIssuerRotation`      if previous and replacement are equal
    /// - `UnknownIssuer`              if either key is absent or inactive
    /// - `InvalidIssuerRotationGrace` if `grace_secs` exceeds
    ///   [`MAX_ISSUER_ROTATION_GRACE_SECS`] or the window would overflow ledger
    ///   time
    pub fn rotate_issuer(
        env: Env,
        admin: Address,
        previous_issuer: Address,
        replacement_issuer: Address,
        grace_secs: u64,
    ) -> u64 {
        require_admin(&env, &admin);

        if previous_issuer == replacement_issuer {
            panic_with_error!(&env, RegistryError::InvalidIssuerRotation);
        }

        let mut previous = get_issuer_record(&env, &previous_issuer);
        if !previous.active {
            panic_with_error!(&env, RegistryError::UnknownIssuer);
        }
        let replacement = get_issuer_record(&env, &replacement_issuer);
        if !replacement.active {
            panic_with_error!(&env, RegistryError::UnknownIssuer);
        }

        // `0` means "use the protocol default", never "no window": a rotation
        // that left pre-rotation evidence unverifiable in the same transaction
        // would break the boundary this feature exists to keep.
        let resolved_grace = if grace_secs == 0 {
            DEFAULT_ISSUER_ROTATION_GRACE_SECS
        } else {
            grace_secs
        };
        if resolved_grace > MAX_ISSUER_ROTATION_GRACE_SECS {
            panic_with_error!(&env, RegistryError::InvalidIssuerRotationGrace);
        }

        let rotated_at = env.ledger().timestamp();
        let grace_expires_at = rotated_at
            .checked_add(resolved_grace)
            .unwrap_or_else(|| panic_with_error!(&env, RegistryError::InvalidIssuerRotationGrace));

        // Retire the previous key immediately: a rotated-out key must not sign
        // anything new, grace window or not.
        previous.active = false;
        env.storage()
            .persistent()
            .set(&DataKey::Issuer(previous_issuer.clone()), &previous);

        env.storage().persistent().set(
            &DataKey::IssuerRotation(previous_issuer.clone()),
            &IssuerRotationRecord {
                previous_issuer: previous_issuer.clone(),
                replacement_issuer: replacement_issuer.clone(),
                rotated_at,
                grace_expires_at,
                grace_secs: resolved_grace,
            },
        );

        IssuerRotated {
            previous_issuer,
            replacement_issuer,
            rotated_at,
            grace_expires_at,
            grace_secs: resolved_grace,
        }
        .publish(&env);

        grace_expires_at
    }

    /// Settle a lapsed issuer-rotation grace window (#323).
    ///
    /// Permissionless by design: the transition is fully determined by the
    /// stored `grace_expires_at`, so any caller may close the record once the
    /// window has lapsed, and no admin key is needed to stop a retired key from
    /// holding standing. Callable at exactly `grace_expires_at` and after it;
    /// the record is removed and `IssuerRotationGraceExpired` is published.
    ///
    /// # Reverts
    ///
    /// - `IssuerRotationNotFound`         if no rotation record exists
    /// - `IssuerRotationGraceStillActive` if the window has not lapsed
    pub fn finalize_issuer_rotation(env: Env, issuer: Address) {
        let record: IssuerRotationRecord = env
            .storage()
            .persistent()
            .get(&DataKey::IssuerRotation(issuer.clone()))
            .unwrap_or_else(|| panic_with_error!(&env, RegistryError::IssuerRotationNotFound));

        if env.ledger().timestamp() < record.grace_expires_at {
            panic_with_error!(&env, RegistryError::IssuerRotationGraceStillActive);
        }

        env.storage()
            .persistent()
            .remove(&DataKey::IssuerRotation(issuer.clone()));

        IssuerRotationGraceExpired {
            issuer,
            replacement_issuer: record.replacement_issuer,
            grace_expires_at: record.grace_expires_at,
        }
        .publish(&env);
    }

    /// The rotation grace record for `issuer`, when the key has rotated out and
    /// the window has not been settled yet (#323).
    ///
    /// `None` for an unknown key, an active key, a revoked key, and a key whose
    /// lapsed window was already finalized. In each of those cases
    /// [`Self::is_issuer_verifiable`] is the read that decides standing.
    pub fn get_issuer_rotation(env: Env, issuer: Address) -> Option<IssuerRotationRecord> {
        env.storage()
            .persistent()
            .get(&DataKey::IssuerRotation(issuer))
    }

    /// Whether `issuer` may still anchor verification of evidence it issued
    /// (#323).
    ///
    /// True while the registry lists the issuer as active, and true for a
    /// rotated-out key until its grace window lapses. False for an unknown key,
    /// a revoked key, and a key at or past `grace_expires_at` — a lapsed window
    /// fails closed rather than being silently extended. Never panics, so a
    /// caller can pre-flight an unknown, revoked, or unsupported issuer without
    /// risking a reverted transaction.
    pub fn is_issuer_verifiable(env: Env, issuer: Address) -> bool {
        let record: Option<IssuerRecord> = env
            .storage()
            .persistent()
            .get(&DataKey::Issuer(issuer.clone()));
        match record {
            None => false,
            Some(current) if current.active => true,
            Some(_) => {
                let rotation: Option<IssuerRotationRecord> = env
                    .storage()
                    .persistent()
                    .get(&DataKey::IssuerRotation(issuer));
                match rotation {
                    Some(window) => env.ledger().timestamp() < window.grace_expires_at,
                    None => false,
                }
            }
        }
    }

    // -----------------------------------------------------------------------
    // Expiration policy (#44)
    // -----------------------------------------------------------------------

    pub fn set_proof_ttl(env: Env, admin: Address, ttl_secs: u64) {
        require_admin(&env, &admin);
        env.storage()
            .persistent()
            .set(&DataKey::ProofTtl, &ttl_secs);
    }

    pub fn get_proof_ttl(env: Env) -> u64 {
        env.storage()
            .persistent()
            .get(&DataKey::ProofTtl)
            .unwrap_or(DEFAULT_PROOF_TTL_SECS)
    }

    // -----------------------------------------------------------------------
    // Timelocked verifier and policy administration (#86)
    // -----------------------------------------------------------------------

    pub fn propose_timelocked_action(
        env: Env,
        admin: Address,
        action: u32,
        target: Address,
        payload: BytesN<32>,
    ) -> u32 {
        require_admin(&env, &admin);
        if action == 0 || action > 6 || action == 5 {
            panic_with_error!(&env, RegistryError::InvalidProposalAction);
        }
        let pending_count: u32 = count_pending_proposals(&env);
        if pending_count >= MAX_PENDING_TIMELOCK_PROPOSALS {
            panic_with_error!(&env, RegistryError::ProposalsSaturated);
        }
        let now = env.ledger().timestamp();
        let min_delay = get_timelock_min_delay(&env);
        let proposal_id = next_proposal_id(&env);
        let proposal = TimelockProposal {
            action,
            proposer: admin.clone(),
            target,
            payload,
            created_at: now,
            min_execution_at: now.saturating_add(min_delay),
            executed: false,
            cancelled: false,
        };
        env.storage()
            .persistent()
            .set(&DataKey::Proposal(proposal_id), &proposal);
        TimelockProposalCreated {
            proposal_id,
            action,
            proposer: admin,
            target: proposal.target,
            created_at: now,
            min_execution_at: proposal.min_execution_at,
        }
        .publish(&env);
        proposal_id
    }

    pub fn cancel_timelocked_proposal(env: Env, admin: Address, proposal_id: u32) {
        require_admin(&env, &admin);
        let mut proposal = get_timelock_proposal_or_panic(&env, proposal_id);
        if proposal.executed {
            panic_with_error!(&env, RegistryError::ProposalAlreadyExecuted);
        }
        if proposal.cancelled {
            panic_with_error!(&env, RegistryError::AlreadyCancelled);
        }
        proposal.cancelled = true;
        env.storage()
            .persistent()
            .set(&DataKey::Proposal(proposal_id), &proposal);
        TimelockProposalCancelled {
            proposal_id,
            action: proposal.action,
            cancelled_by: admin,
            cancelled_at: env.ledger().timestamp(),
        }
        .publish(&env);
    }

    pub fn execute_timelocked_proposal(env: Env, caller: Address, proposal_id: u32) {
        let proposal = get_timelock_proposal_or_panic(&env, proposal_id);
        if proposal.executed {
            panic_with_error!(&env, RegistryError::ProposalAlreadyExecuted);
        }
        if proposal.cancelled {
            panic_with_error!(&env, RegistryError::ProposalCancelled);
        }
        let now = env.ledger().timestamp();
        if now < proposal.min_execution_at {
            panic_with_error!(&env, RegistryError::ProposalNotReady);
        }
        let mut mutable_proposal = proposal.clone();
        mutable_proposal.executed = true;
        env.storage()
            .persistent()
            .set(&DataKey::Proposal(proposal_id), &mutable_proposal);
        caller.require_auth();
        dispatch_timelocked_action(&env, &proposal);
        TimelockProposalExecuted {
            proposal_id,
            action: proposal.action,
            executed_by: caller,
            executed_at: now,
        }
        .publish(&env);
    }

    pub fn emergency_execute_timelock(env: Env, admin: Address, proposal_id: u32) {
        require_admin(&env, &admin);
        let proposal = get_timelock_proposal_or_panic(&env, proposal_id);
        if proposal.executed {
            panic_with_error!(&env, RegistryError::ProposalAlreadyExecuted);
        }
        if proposal.cancelled {
            panic_with_error!(&env, RegistryError::ProposalCancelled);
        }
        if proposal.action == ProposalAction::UpgradeWasm as u32 {
            panic_with_error!(&env, RegistryError::InvalidProposalAction);
        }
        let mut mutable_proposal = proposal.clone();
        mutable_proposal.executed = true;
        env.storage()
            .persistent()
            .set(&DataKey::Proposal(proposal_id), &mutable_proposal);
        dispatch_timelocked_action(&env, &proposal);
        TimelockEmergencyExec {
            proposal_id,
            action: proposal.action,
            executed_by: admin,
            executed_at: env.ledger().timestamp(),
        }
        .publish(&env);
    }

    pub fn get_timelock_proposal(env: Env, proposal_id: u32) -> Option<TimelockProposal> {
        env.storage()
            .persistent()
            .get(&DataKey::Proposal(proposal_id))
    }

    pub fn get_current_wasm_hash(env: Env) -> Option<BytesN<32>> {
        env.storage().persistent().get(&DataKey::WasmHash)
    }

    pub fn get_timelock_proposal_count(env: Env) -> u32 {
        env.storage()
            .persistent()
            .get(&DataKey::ProposalSeq)
            .unwrap_or(0u32)
    }

    /// Enumerate timelocked proposals across sequential IDs.
    ///
    /// - `cursor`: ID offset to start scanning from (e.g. 0 or 1 starts at first proposal).
    ///   Proposals use 1-based sequential IDs. If `cursor == 0`, scanning begins at ID 1.
    /// - `limit`: maximum number of proposals to return; capped at `MAX_TIMELOCK_PROPOSALS_PAGE`.
    ///   If 0 or exceeding the cap, `limit` is clamped to `MAX_TIMELOCK_PROPOSALS_PAGE`.
    /// - Non-existent/deleted proposals are skipped.
    /// - Read-only query; no auth required.
    pub fn list_timelock_proposals(
        env: Env,
        cursor: u32,
        limit: u32,
    ) -> TimelockProposalPage {
        let effective_limit = if limit == 0 || limit > MAX_TIMELOCK_PROPOSALS_PAGE {
            MAX_TIMELOCK_PROPOSALS_PAGE
        } else {
            limit
        };

        let total_seq: u32 = env
            .storage()
            .persistent()
            .get(&DataKey::ProposalSeq)
            .unwrap_or(0u32);

        let mut proposals = SorobanVec::new(&env);
        let mut next_cursor: Option<u32> = None;

        let mut id = if cursor == 0 { 1u32 } else { cursor };

        while id <= total_seq {
            if let Some(proposal) = env
                .storage()
                .persistent()
                .get::<DataKey, TimelockProposal>(&DataKey::Proposal(id))
            {
                proposals.push_back(proposal);
                if proposals.len() == effective_limit {
                    if id < total_seq {
                        next_cursor = Some(id + 1);
                    }
                    break;
                }
            }
            id = id.saturating_add(1);
        }

        TimelockProposalPage {
            proposals,
            next_cursor,
        }
    }

    pub fn get_timelock_min_delay_secs(env: Env) -> u64 {
        get_timelock_min_delay(&env)
    }

    pub fn set_timelock_min_delay_secs(env: Env, admin: Address, delay_secs: u64) {
        require_admin(&env, &admin);
        if delay_secs == 0 || delay_secs > MAX_TIMELOCK_MIN_DELAY_SECS {
            panic_with_error!(&env, RegistryError::InvalidTimelockDelay);
        }
        let previous = get_timelock_min_delay(&env);
        env.storage()
            .persistent()
            .set(&DataKey::TimelockMinDelay, &delay_secs);
        TimelockMinDelaySet {
            previous_delay: previous,
            new_delay: delay_secs,
            set: Symbol::new(&env, "set"),
            set_by: admin,
        }
        .publish(&env);
    }

    pub fn get_proof_status(env: Env, proof_id: BytesN<32>) -> ProofVerificationStatus {
        let record: Option<ProofRecord> = env.storage().persistent().get(&DataKey::Proof(proof_id));
        match record {
            None => ProofVerificationStatus::NotFound,
            Some(r) => {
                if r.status == STATUS_REVOKED {
                    return ProofVerificationStatus::Revoked;
                }
                if r.status == STATUS_EXPIRED {
                    return ProofVerificationStatus::Expired;
                }
                if r.expires_at > 0 && env.ledger().timestamp() > r.expires_at {
                    return ProofVerificationStatus::Expired;
                }
                ProofVerificationStatus::Valid
            }
        }
    }

    /// Return the human-readable verification status of multiple proofs in a single
    /// batch query, efficiently retrieving them without exceeding Soroban read budgets.
    ///
    /// The maximum number of proof IDs in a single batch is bounded (e.g. 100) to
    /// ensure the query always completes within resource limits.
    pub fn get_proof_statuses(
        env: Env,
        proof_ids: soroban_sdk::Vec<BytesN<32>>,
    ) -> soroban_sdk::Vec<ProofVerificationStatus> {
        let max_batch_size = 100;
        if proof_ids.len() > max_batch_size {
            panic_with_error!(&env, RegistryError::BatchTooLarge);
        }

        let mut statuses = SorobanVec::new(&env);
        for proof_id in proof_ids.iter() {
            statuses.push_back(Self::get_proof_status(env.clone(), proof_id));
        }
        statuses
    }

    /// Single read call that summarises everything a verifier needs to trust a proof:
    /// verification status, tier, timestamp assurance level, open dispute count,
    /// metadata envelope version, and issuer verifiability.
    ///
    /// Returns `None` if the proof is not found.
    pub fn get_proof_assurance(env: Env, proof_id: BytesN<32>) -> Option<ProofAssurance> {
        let record: ProofRecord = env.storage().persistent().get(&DataKey::Proof(proof_id.clone()))?;
        let status = Self::get_proof_status(env.clone(), proof_id.clone());
        let timestamp_assurance_level = Self::get_timestamp_claim(env.clone(), proof_id.clone())
            .map(|c| c.assurance)
            .unwrap_or(TIMESTAMP_ASSURANCE_NONE);
        let open_dispute_count = Self::get_open_dispute_count(env.clone(), proof_id.clone());
        let envelope_version = Self::resolve_metadata_envelope_ver(env.clone(), proof_id.clone());
        let issuer_verifiable = match record.issuer {
            Some(issuer) => Self::is_issuer_verifiable(env.clone(), issuer),
            None => false,
        };

        Some(ProofAssurance {
            status,
            tier: record.tier,
            timestamp_assurance_level,
            open_dispute_count,
            envelope_version,
            issuer_verifiable,
        })
    }

    // -----------------------------------------------------------------------
    // Scope epoch management (scoped nullifier v1)
    // -----------------------------------------------------------------------

    /// Set the current epoch for a given scope identifier.
    ///
    /// When the admin advances the epoch for a scope, all proofs generated
    /// under the previous epoch for that scope will have stale epoch values
    /// and will be rejected by `register_anonymous_verified`.
    ///
    /// Epochs are strictly monotonic (`epoch > current`). Setting an epoch
    /// less than or equal to the current epoch panics with `RegistryError::StaleEpoch`
    /// to prevent epoch rollback and re-enabling previously consumed nullifiers.
    /// Non-increasing transitions (including equal) are rejected rather than
    /// treated idempotently to ensure every update explicitly advances the epoch.
    ///
    /// The scope is a 32-byte identifier derived from the scope string
    /// (e.g., SHA-256 hash mod BN254 field).  An empty (zero) scope
    /// represents the global/unscoped context.
    ///
    /// Only the registry admin may call this.
    pub fn set_scope_epoch(env: Env, admin: Address, scope: BytesN<32>, epoch: u64) {
        require_admin(&env, &admin);

        let current_epoch = get_scope_epoch_raw(&env, &scope);
        if epoch <= current_epoch {
            panic_with_error!(&env, RegistryError::StaleEpoch);
        }

        env.storage()
            .persistent()
            .set(&DataKey::ScopeEpoch(scope.clone()), &epoch);
        ScopeEpochSet { scope, epoch }.publish(&env);
    }

    /// Get the current epoch for a given scope.
    /// Returns `DEFAULT_SCOPE_EPOCH` (0) if no epoch has been set.
    pub fn get_scope_epoch(env: Env, scope: BytesN<32>) -> u64 {
        env.storage()
            .persistent()
            .get(&DataKey::ScopeEpoch(scope))
            .unwrap_or(DEFAULT_SCOPE_EPOCH)
    }

    // -----------------------------------------------------------------------
    // Registration entry points
    // -----------------------------------------------------------------------

    pub fn register_anonymous(
        env: Env,
        video_hash: BytesN<32>,
        metadata_hash: BytesN<32>,
        proof_id: BytesN<32>,
        nullifier: BytesN<32>,
        credential_root: BytesN<32>,
        proof: Bytes,
    ) -> ProofRecord {
        require_domain_unpaused(&env, PAUSE_DOMAIN_TIER1_REGISTRATION);
        require_unique(&env, &proof_id, &video_hash);

        let verifier = get_active_verifier(&env);
        if Self::has_nullifier(env.clone(), verifier.clone(), nullifier.clone()) {
            panic_with_error!(&env, RegistryError::DuplicateNullifier);
        }

        if !verify_demo_zk_boundary(&proof, &credential_root) {
            panic_with_error!(&env, RegistryError::InvalidProof);
        }
        require_active_credential_root(&env, &credential_root);

        env.storage()
            .persistent()
            .set(&DataKey::VerifierNullifier(verifier, nullifier.clone()), &true);

        let expires_at = compute_expires_at(&env);
        let record = ProofRecord {
            video_hash,
            metadata_hash,
            tier: TIER_SILENT_WITNESS,
            status: STATUS_REGISTERED,
            created_at: env.ledger().timestamp(),
            expires_at,
            source: None,
            issuer: None,
            nullifier: Some(nullifier),
            batch_size: 0,
        };
        save_record(&env, &proof_id, record.clone(), None);
        record
    }

    pub fn register_anonymous_verified(
        env: Env,
        video_hash: BytesN<32>,
        metadata_hash: BytesN<32>,
        proof_id: BytesN<32>,
        public_inputs: Bytes,
        proof: Bytes,
    ) -> ProofRecord {
        let verifier_ctx = VerifierContext::load(&env);
        require_domain_unpaused(&env, PAUSE_DOMAIN_TIER1_REGISTRATION);
        require_unique(&env, &proof_id, &video_hash);

        let input_len = public_inputs.len();

        let record = if input_len == SILENT_WITNESS_V2_BARE_INPUT_LEN {
            // The bare v2 frame predates #368 and commits no circuit version, so
            // the verifier could only infer one from the length. Rejecting it by
            // length here means a proof cannot dodge the version commitment by
            // omitting the trailer.
            panic_with_error!(&env, RegistryError::CircuitVersionMismatch);
        } else if input_len == SILENT_WITNESS_V2_ENVELOPED_INPUT_LEN {
            // v2 scoped nullifier path; the circuit-version envelope trailer is
            // mandatory (#368).
            let parsed = parse_scoped_silent_witness_public_inputs(&env, &public_inputs);
            if parsed.video_hash != video_hash {
                panic_with_error!(&env, RegistryError::InvalidPublicInputs);
            }
            if parsed.domain_tag != expected_domain_tag(&env) {
                panic_with_error!(&env, RegistryError::DomainTagMismatch);
            }
            require_active_credential_root(&env, &parsed.credential_root);

            // Epoch validation: the proof's epoch must match the current epoch for its scope.
            let current_epoch = get_scope_epoch_raw(&env, &parsed.verifier_scope);
            if parsed.epoch != current_epoch {
                panic_with_error!(&env, RegistryError::StaleEpoch);
            }

            let verifier = verifier_ctx.verifier(&env);
            if verifier_ctx.has_nullifier(&env, &parsed.nullifier) {
                panic_with_error!(&env, RegistryError::DuplicateNullifier);
            }
            verifier_ctx.require_verified_proof(
                &env,
                CIRCUIT_VERSION_SILENT_WITNESS_V2,
                public_inputs,
                proof,
            );

            env.storage()
                .persistent()
                .set(&DataKey::VerifierNullifier(verifier.clone(), parsed.nullifier.clone()), &true);

            let expires_at = compute_expires_at(&env);
            save_record(
                &env,
                &proof_id,
                ProofRecord {
                    video_hash,
                    metadata_hash,
                    tier: TIER_SILENT_WITNESS,
                    status: STATUS_REGISTERED,
                    created_at: env.ledger().timestamp(),
                    expires_at,
                    source: None,
                    issuer: None,
                    nullifier: Some(parsed.nullifier),
                    batch_size: 0,
                },
                None,
            )
        } else if input_len == SILENT_WITNESS_V1_INPUT_LEN {
            // v1 legacy path (backward compatible)
            let parsed = parse_silent_witness_public_inputs(&env, &public_inputs);
            if parsed.video_hash != video_hash {
                panic_with_error!(&env, RegistryError::InvalidPublicInputs);
            }
            if parsed.domain_tag != expected_domain_tag(&env) {
                panic_with_error!(&env, RegistryError::DomainTagMismatch);
            }
            require_active_credential_root(&env, &parsed.credential_root);

            let verifier = verifier_ctx.verifier(&env);
            if verifier_ctx.has_nullifier(&env, &parsed.nullifier) {
                panic_with_error!(&env, RegistryError::DuplicateNullifier);
            }
            verifier_ctx.require_verified_proof(
                &env,
                CIRCUIT_VERSION_SILENT_WITNESS_V1,
                public_inputs,
                proof,
            );

            env.storage()
                .persistent()
                .set(&DataKey::VerifierNullifier(verifier.clone(), parsed.nullifier.clone()), &true);

            let expires_at = compute_expires_at(&env);
            save_record(
                &env,
                &proof_id,
                ProofRecord {
                    video_hash,
                    metadata_hash,
                    tier: TIER_SILENT_WITNESS,
                    status: STATUS_REGISTERED,
                    created_at: env.ledger().timestamp(),
                    expires_at,
                    source: None,
                    issuer: None,
                    nullifier: Some(parsed.nullifier),
                    batch_size: 0,
                },
                None,
            )
        } else if input_len == SILENT_WITNESS_BROWSER_V1_INPUT_LEN {
            // v1 browser artifact path (4 x 32 = 128 bytes, shipped in frontend/public/noir)
            let parsed = parse_browser_silent_witness_public_inputs(&env, &public_inputs);
            if parsed.video_hash != video_hash {
                panic_with_error!(&env, RegistryError::InvalidPublicInputs);
            }
            require_active_credential_root(&env, &parsed.credential_root);

            let verifier: Address = env
                .storage()
                .persistent()
                .get(&DataKey::Verifier)
                .unwrap_or_else(|| panic_with_error!(&env, RegistryError::VerifierNotSet));
            require_verified_proof(
                &env,
                &verifier,
                CIRCUIT_VERSION_SILENT_WITNESS_V1,
                public_inputs,
                proof,
            );

            env.storage()
                .persistent()
                .set(&DataKey::VerifierNullifier(verifier, parsed.nullifier.clone()), &true);

            let expires_at = compute_expires_at(&env);
            save_record(
                &env,
                &proof_id,
                ProofRecord {
                    video_hash,
                    metadata_hash,
                    tier: TIER_SILENT_WITNESS,
                    status: STATUS_REGISTERED,
                    created_at: env.ledger().timestamp(),
                    expires_at,
                    source: None,
                    issuer: None,
                    nullifier: Some(parsed.nullifier),
                    batch_size: 0,
                },
                None,
            )
        } else {
            panic_with_error!(&env, RegistryError::InvalidPublicInputs);
        };

        record
    }

    // -----------------------------------------------------------------------
    // Batch aggregation registration
    // -----------------------------------------------------------------------

    /// Register multiple video hashes under the same credential using a
    /// single aggregated UltraHonk proof produced by the Silent Witness
    /// Aggregator circuit.
    ///
    /// # Arguments
    ///
    /// * `env` – Soroban environment
    /// * `batch_id` – Unique batch identifier (serves as the batch proof_id)
    /// * `metadata_hash` – Shared metadata hash for all elements in the batch
    /// * `public_inputs` – Aggregated public inputs (1 domain separator +
    ///   MAX_AGGREGATION_SIZE × 4 field elements; see AGGREGATED_PUBLIC_INPUT_SIZE)
    /// * `proof` – Aggregated UltraHonk proof bytes
    /// * `video_hashes` – Ordered list of video hashes in the batch (must
    ///   match the order in public_inputs)
    ///
    /// # Panics
    ///
    /// - `BatchSizeExceeded` if `video_hashes.len() > MAX_AGGREGATION_SIZE`
    /// - `BatchCountMismatch` if the number of video hashes doesn't match
    ///   the parsed batch count from public inputs
    /// - `InvalidPublicInputs` if the domain separator or public input layout
    ///   is wrong
    /// - `UnknownCredentialRoot` if the credential root is not registered
    /// - `RevokedCredentialRoot` if the credential root has been revoked
    /// - `DuplicateNullifier` if any nullifier in the batch was already consumed
    /// - `DuplicateProof` if the batch_id was already used
    /// - `DuplicateVideo` if any video hash was already registered
    /// - `VerifierNotSet` if no verifier contract is configured
    /// - `InvalidProof` if the external UltraHonk verifier rejects the proof
    pub fn register_batch_verified(
        env: Env,
        batch_id: BytesN<32>,
        metadata_hash: BytesN<32>,
        public_inputs: Bytes,
        proof: Bytes,
        video_hashes: soroban_sdk::Vec<BytesN<32>>,
    ) -> soroban_sdk::Vec<ProofRecord> {
        let verifier_ctx = VerifierContext::load(&env);
        let batch_size = video_hashes.len();

        if batch_size == 0 || batch_size > MAX_AGGREGATION_SIZE {
            panic_with_error!(&env, RegistryError::BatchSizeExceeded);
        }

        // Parse the aggregated public inputs to extract domain separator and
        // element public inputs.
        let parsed = parse_aggregated_public_inputs(&env, &public_inputs, batch_size);

        // 1. Domain binding — must match the expected aggregation version tag.
        let expected_domain = BytesN::from_array(&env, &AGGREGATION_DOMAIN_SEPARATOR);
        if parsed.domain_separator != expected_domain {
            panic_with_error!(&env, RegistryError::InvalidPublicInputs);
        }

        // 2. Verify the aggregated UltraHonk proof through the configured
        //    verifier contract, validating the aggregation circuit version at
        //    the trust boundary first.
        let verifier = verifier_ctx.verifier(&env);
        verifier_ctx.require_verified_proof(
            &env,
            CIRCUIT_VERSION_AGGREGATION,
            public_inputs,
            proof,
        );

        // 3. Credential root must be registered and active.
        let shared_root = &parsed.elements[0].credential_root;
        require_active_credential_root(&env, shared_root);

        // 4. Verify batch integrity: credential roots must match and the
        //    video hashes must match the parsed public inputs.
        let expires_at = compute_expires_at(&env);
        let now = env.ledger().timestamp();
        let mut results: SorobanVec<ProofRecord> = SorobanVec::new(&env);

        for i in 0..batch_size {
            let element = &parsed.elements[i as usize];

            // All credential roots in the batch must be identical.
            if element.credential_root != *shared_root {
                panic_with_error!(&env, RegistryError::BatchCredentialRootMismatch);
            }

            // Match video hash from the caller's input.
            let video_hash = video_hashes.get(i).unwrap_or_else(|| {
                panic_with_error!(&env, RegistryError::BatchCountMismatch);
            });
            if element.video_hash != video_hash {
                panic_with_error!(&env, RegistryError::InvalidPublicInputs);
            }

            // Derive a deterministic sub-proof_id for each element.
            let element_proof_id = derive_element_proof_id(&env, &batch_id, i);

            // Check proof_id uniqueness within the batch scope.
            if env
                .storage()
                .persistent()
                .has(&DataKey::Proof(element_proof_id.clone()))
            {
                panic_with_error!(&env, RegistryError::DuplicateProof);
            }

            // Check video hash uniqueness.
            if env
                .storage()
                .persistent()
                .has(&DataKey::Video(video_hash.clone()))
            {
                panic_with_error!(&env, RegistryError::DuplicateVideo);
            }

            // Check nullifier uniqueness.
            if verifier_ctx.has_nullifier(&env, &element.nullifier) {
                panic_with_error!(&env, RegistryError::DuplicateNullifier);
            }
        }

        // All checks passed — persist every element.
        for i in 0..batch_size {
            let element = &parsed.elements[i as usize];
            let video_hash = video_hashes.get(i).unwrap();
            let element_proof_id = derive_element_proof_id(&env, &batch_id, i);

            // Consume the nullifier.
            env.storage()
                .persistent()
                .set(&DataKey::VerifierNullifier(verifier.clone(), element.nullifier.clone()), &true);

            let record = save_record(
                &env,
                &element_proof_id,
                ProofRecord {
                    video_hash: video_hash.clone(),
                    metadata_hash: metadata_hash.clone(),
                    tier: TIER_SILENT_WITNESS,
                    status: STATUS_REGISTERED,
                    created_at: now,
                    expires_at,
                    source: None,
                    issuer: None,
                    nullifier: Some(element.nullifier.clone()),
                    batch_size,
                },
                None,
            );

            results.push_back(record);
        }

        // Emit a top-level batch event.
        BatchProofRegistered {
            reg: Symbol::new(&env, "reg"),
            batch_id,
            credential_root: shared_root.clone(),
            count: batch_size,
            tier: TIER_SILENT_WITNESS,
            status: STATUS_REGISTERED,
        }
        .publish(&env);

        results
    }

    pub fn register_source(
        env: Env,
        source: Address,
        video_hash: BytesN<32>,
        metadata_hash: BytesN<32>,
        proof_id: BytesN<32>,
    ) -> ProofRecord {
        require_domain_unpaused(&env, PAUSE_DOMAIN_TIER2_REGISTRATION);
        source.require_auth();
        require_unique(&env, &proof_id, &video_hash);

        let expires_at = compute_expires_at(&env);
        let record = ProofRecord {
            video_hash,
            metadata_hash,
            tier: TIER_CONSISTENT_SOURCE,
            status: STATUS_REGISTERED,
            created_at: env.ledger().timestamp(),
            expires_at,
            source: Some(source.clone()),
            issuer: None,
            nullifier: None,
            batch_size: 0,
        };
        save_record(&env, &proof_id, record.clone(), Some(source.clone()));
        record
    }

    /// Register a Tier 2 source batch root.
    ///
    /// Allows high-volume Tier 2 sources to anchor many items in a single transaction
    /// by committing the root of a binary Merkle tree.
    pub fn register_source_batch_root(
        env: Env,
        source: Address,
        root: BytesN<32>,
        count: u32,
        metadata_hash: BytesN<32>,
    ) -> BatchRecord {
        require_domain_unpaused(&env, PAUSE_DOMAIN_TIER2_REGISTRATION);
        source.require_auth();

        if count < MIN_SOURCE_BATCH_COUNT || count > MAX_SOURCE_BATCH_COUNT {
            panic_with_error!(&env, RegistryError::BatchSizeExceeded);
        }

        if env.storage().persistent().has(&DataKey::SourceBatch(root.clone())) {
            panic_with_error!(&env, RegistryError::DuplicateProof);
        }

        let created_at = env.ledger().timestamp();
        let record = BatchRecord {
            root: root.clone(),
            source: source.clone(),
            count,
            metadata_hash: metadata_hash.clone(),
            created_at,
        };

        env.storage()
            .persistent()
            .set(&DataKey::SourceBatch(root.clone()), &record);

        SourceBatchRootRegistered {
            root,
            source,
            count,
            metadata_hash,
            registered_at: created_at,
        }
        .publish(&env);

        record
    }

    /// Verify cryptographic inclusion of a leaf in a source batch root.
    ///
    /// Evaluates a binary Merkle inclusion proof using SHA-256 with domain-separated
    /// leaf (`0x00`) and node (`0x01`) hashing to prevent second-preimage attacks
    /// by construction.
    pub fn verify_source_batch_inclusion(
        env: Env,
        root: BytesN<32>,
        leaf: BytesN<32>,
        proof: Vec<BytesN<32>>,
        index: u32,
    ) -> bool {
        let proof_len = proof.len();
        if proof_len > MAX_SOURCE_BATCH_PROOF_LEN {
            panic_with_error!(&env, RegistryError::InvalidInclusionProof);
        }

        if proof_len < 32 {
            let max_capacity = 1u64 << proof_len;
            if (index as u64) >= max_capacity {
                panic_with_error!(&env, RegistryError::InvalidInclusionProof);
            }
        }

        // Domain-separated leaf hashing: SHA-256(0x00 || leaf)
        let mut leaf_preimage = Bytes::new(&env);
        leaf_preimage.push_back(SOURCE_BATCH_LEAF_DOMAIN);
        leaf_preimage.extend_from_slice(&leaf.to_array());
        let mut current: BytesN<32> = env.crypto().sha256(&leaf_preimage).into();

        // Walk up the Merkle path
        for i in 0..proof_len {
            let sibling = proof.get(i).unwrap();
            let bit = (index >> i) & 1;

            let mut node_preimage = Bytes::new(&env);
            node_preimage.push_back(SOURCE_BATCH_NODE_DOMAIN);
            if bit == 0 {
                // current is left, sibling is right
                node_preimage.extend_from_slice(&current.to_array());
                node_preimage.extend_from_slice(&sibling.to_array());
            } else {
                // sibling is left, current is right
                node_preimage.extend_from_slice(&sibling.to_array());
                node_preimage.extend_from_slice(&current.to_array());
            }

            current = env.crypto().sha256(&node_preimage).into();
        }

        if current != root {
            panic_with_error!(&env, RegistryError::InvalidInclusionProof);
        }

        true
    }

    /// Read-only query for a stored source batch record.
    pub fn get_source_batch(env: Env, root: BytesN<32>) -> Option<BatchRecord> {
        env.storage()
            .persistent()
            .get(&DataKey::SourceBatch(root))
    }

    pub fn register_seal(
        env: Env,
        issuer: Address,
        video_hash: BytesN<32>,
        metadata_hash: BytesN<32>,
        proof_id: BytesN<32>,
    ) -> ProofRecord {
        require_domain_unpaused(&env, PAUSE_DOMAIN_TIER3_REGISTRATION);
        issuer.require_auth();
        require_issuer_role_available(&env, &issuer);
        require_unique(&env, &proof_id, &video_hash);

        let issuer_record = get_issuer_record(&env, &issuer);
        if !issuer_record.active {
            panic_with_error!(&env, RegistryError::UnknownIssuer);
        }

        let expires_at = compute_expires_at(&env);
        let record = ProofRecord {
            video_hash,
            metadata_hash,
            tier: TIER_PUBLIC_SEAL,
            status: STATUS_REGISTERED,
            created_at: env.ledger().timestamp(),
            expires_at,
            source: None,
            issuer: Some(issuer.clone()),
            nullifier: None,
            batch_size: 0,
        };
        save_record(&env, &proof_id, record.clone(), Some(issuer.clone()));
        record
    }

    // -----------------------------------------------------------------------
    // Constrained issuer and source delegation (#192)
    // -----------------------------------------------------------------------

    /// Grant `delegate` a narrowly scoped, expiring authority to register on
    /// the caller's behalf.
    ///
    /// Requires the grantor's own signature — a delegate can never create or
    /// extend a delegation, which is what makes the mechanism non-transitive.
    ///
    /// `scope` is a non-empty subset of `DELEGATION_SCOPE_ALL`.
    /// `duration_secs` is non-zero and at most `MAX_DELEGATION_DURATION_SECS`.
    ///
    /// Idempotent: re-granting to an existing delegate overwrites that
    /// delegate's record — narrowing or widening scope, extending or shortening
    /// expiry — and does not consume another storage slot. Returns the epoch
    /// second at which the delegation lapses on its own.
    ///
    /// # Reverts
    ///
    /// - `SelfDelegation`              if `grantor == delegate`
    /// - `InvalidDelegationScope`      if `scope` is zero or has unknown bits
    /// - `InvalidDelegationDuration`   if `duration_secs` is zero or over the cap
    /// - `DelegationsSaturated`        if the grantor already holds the maximum
    pub fn grant_delegation(
        env: Env,
        grantor: Address,
        delegate: Address,
        scope: u32,
        duration_secs: u64,
    ) -> u64 {
        grantor.require_auth();

        if grantor == delegate {
            panic_with_error!(&env, RegistryError::SelfDelegation);
        }
        validate_delegation_scope(&env, scope);
        if duration_secs == 0 || duration_secs > MAX_DELEGATION_DURATION_SECS {
            panic_with_error!(&env, RegistryError::InvalidDelegationDuration);
        }

        let key = DataKey::Delegation(grantor.clone(), delegate.clone());
        let is_new = !env.storage().persistent().has(&key);

        if is_new {
            let count = delegation_count(&env, &grantor);
            if count >= MAX_DELEGATIONS_PER_GRANTOR {
                panic_with_error!(&env, RegistryError::DelegationsSaturated);
            }
            env.storage()
                .persistent()
                .set(&DataKey::DelegationCount(grantor.clone()), &(count + 1));
        }

        let granted_at = env.ledger().timestamp();
        let expires_at = granted_at.saturating_add(duration_secs);

        env.storage().persistent().set(
            &key,
            &DelegationRecord {
                grantor: grantor.clone(),
                delegate: delegate.clone(),
                scope,
                granted_at,
                expires_at,
            },
        );

        DelegationGranted {
            grantor,
            delegate,
            scope,
            granted_at,
            expires_at,
        }
        .publish(&env);

        expires_at
    }

    /// Revoke a delegation ahead of its expiry.
    ///
    /// Callable by the grantor (withdrawing authority it issued) or by the
    /// admin (incident response against a compromised delegate). Revoking a
    /// delegation that does not exist is a no-op rather than an error, so
    /// retries and concurrent revocations converge.
    pub fn revoke_delegation(env: Env, revoker: Address, grantor: Address, delegate: Address) {
        revoker.require_auth();

        if revoker != grantor {
            let admin: Address = env
                .storage()
                .persistent()
                .get(&DataKey::Admin)
                .unwrap_or_else(|| panic_with_error!(&env, RegistryError::NotInitialized));
            if revoker != admin {
                panic_with_error!(&env, RegistryError::Unauthorized);
            }
        }

        let key = DataKey::Delegation(grantor.clone(), delegate.clone());
        if !env.storage().persistent().has(&key) {
            return;
        }

        env.storage().persistent().remove(&key);

        // Free the slot so the grantor can delegate to someone else. Saturating
        // so a corrupted counter can never underflow into a huge allowance.
        let count = delegation_count(&env, &grantor);
        env.storage().persistent().set(
            &DataKey::DelegationCount(grantor.clone()),
            &count.saturating_sub(1),
        );

        DelegationRevoked {
            grantor,
            delegate,
            revoked_by: revoker,
            revoked_at: env.ledger().timestamp(),
        }
        .publish(&env);
    }

    /// Read-only: the raw delegation record, if one is stored. A record past
    /// its `expires_at` is still returned so operators can see and prune it;
    /// use `is_delegation_active` to ask whether it currently grants anything.
    pub fn get_delegation(
        env: Env,
        grantor: Address,
        delegate: Address,
    ) -> Option<DelegationRecord> {
        env.storage()
            .persistent()
            .get(&DataKey::Delegation(grantor, delegate))
    }

    /// Read-only: does a live delegation from `grantor` to `delegate` carry
    /// every bit of `scope`? Returns `false` for unknown, expired, or
    /// insufficiently scoped delegations rather than erroring, so callers can
    /// pre-flight without a trial transaction.
    pub fn is_delegation_active(env: Env, grantor: Address, delegate: Address, scope: u32) -> bool {
        if scope == 0 || scope & !DELEGATION_SCOPE_ALL != 0 {
            return false;
        }
        let record: Option<DelegationRecord> = env
            .storage()
            .persistent()
            .get(&DataKey::Delegation(grantor, delegate));
        match record {
            Some(record) => {
                env.ledger().timestamp() < record.expires_at && record.scope & scope == scope
            }
            None => false,
        }
    }

    /// Read-only: how many distinct delegates a grantor currently holds,
    /// against `MAX_DELEGATIONS_PER_GRANTOR`.
    pub fn get_delegation_count(env: Env, grantor: Address) -> u32 {
        delegation_count(&env, &grantor)
    }

    /// Register a Tier 2 consistent-source proof on `source`'s behalf.
    ///
    /// Authorizes the *delegate*, not the source: the source's key is never
    /// required at call time. The stored `ProofRecord` still names `source`,
    /// while the delegate is recorded in the proof's lifecycle history, so the
    /// audit trail distinguishes authority from actor.
    ///
    /// Subject to the same Tier 2 pause domain and uniqueness rules as
    /// `register_source`.
    pub fn register_source_delegated(
        env: Env,
        delegate: Address,
        source: Address,
        video_hash: BytesN<32>,
        metadata_hash: BytesN<32>,
        proof_id: BytesN<32>,
    ) -> ProofRecord {
        require_domain_unpaused(&env, PAUSE_DOMAIN_TIER2_REGISTRATION);
        delegate.require_auth();
        let delegation =
            require_delegation(&env, &source, &delegate, DELEGATION_SCOPE_REGISTER_SOURCE);
        require_unique(&env, &proof_id, &video_hash);

        let expires_at = bounded_delegated_expiry(&env, delegation.expires_at);
        let record = ProofRecord {
            video_hash,
            metadata_hash,
            tier: TIER_CONSISTENT_SOURCE,
            status: STATUS_REGISTERED,
            created_at: env.ledger().timestamp(),
            expires_at,
            source: Some(source.clone()),
            issuer: None,
            nullifier: None,
            batch_size: 0,
        };
        save_record(&env, &proof_id, record.clone(), Some(delegate.clone()));
        DelegationUsed {
            grantor: source,
            delegate,
            scope: DELEGATION_SCOPE_REGISTER_SOURCE,
            proof_id,
        }
        .publish(&env);
        record
    }

    /// Register a Tier 3 public-seal proof on `issuer`'s behalf.
    ///
    /// The issuer must still be a registered, active issuer — a delegation
    /// never substitutes for issuer standing, it only lets someone else
    /// exercise it. Subject to the same Tier 3 pause domain and uniqueness
    /// rules as `register_seal`.
    pub fn register_seal_delegated(
        env: Env,
        delegate: Address,
        issuer: Address,
        video_hash: BytesN<32>,
        metadata_hash: BytesN<32>,
        proof_id: BytesN<32>,
    ) -> ProofRecord {
        require_domain_unpaused(&env, PAUSE_DOMAIN_TIER3_REGISTRATION);
        delegate.require_auth();
        let delegation =
            require_delegation(&env, &issuer, &delegate, DELEGATION_SCOPE_REGISTER_SEAL);
        require_unique(&env, &proof_id, &video_hash);

        let issuer_record = get_issuer_record(&env, &issuer);
        if !issuer_record.active {
            panic_with_error!(&env, RegistryError::UnknownIssuer);
        }

        let expires_at = bounded_delegated_expiry(&env, delegation.expires_at);
        let record = ProofRecord {
            video_hash,
            metadata_hash,
            tier: TIER_PUBLIC_SEAL,
            status: STATUS_REGISTERED,
            created_at: env.ledger().timestamp(),
            expires_at,
            source: None,
            issuer: Some(issuer.clone()),
            nullifier: None,
            batch_size: 0,
        };
        save_record(&env, &proof_id, record.clone(), Some(delegate.clone()));
        DelegationUsed {
            grantor: issuer,
            delegate,
            scope: DELEGATION_SCOPE_REGISTER_SEAL,
            proof_id,
        }
        .publish(&env);
        record
    }

    fn revoke_proof_internal(
        env: &Env,
        admin: &Address,
        proof_id: &BytesN<32>,
        reason_code: u32,
    ) {
        let mut record = get_proof_record(env, proof_id);
        record.status = STATUS_REVOKED;
        env.storage()
            .persistent()
            .set(&DataKey::Proof(proof_id.clone()), &record);
        ProofRevoked {
            proof_id: proof_id.clone(),
            status: STATUS_REVOKED,
        }
        .publish(env);
        record_proof_history(
            env,
            proof_id,
            ProofLifecycleAction::Revoked as u32,
            Some(admin.clone()),
            reason_code,
        );
    }

    pub fn revoke_proof(env: Env, admin: Address, proof_id: BytesN<32>) {
        require_admin(&env, &admin);
        Self::revoke_proof_internal(&env, &admin, &proof_id, 1);
    }

    /// Revoke multiple proofs in a single transaction during incident response.
    ///
    /// Reuses the single-revoke path so history entries and events are identical per proof.
    /// Bounded by [`MAX_REVOKE_PROOFS_BATCH_SIZE`] against the execution budget.
    /// Fails atomically on any invalid proof.
    pub fn revoke_proofs(
        env: Env,
        admin: Address,
        proof_ids: soroban_sdk::Vec<BytesN<32>>,
        reason_code: u32,
    ) {
        require_admin(&env, &admin);

        if proof_ids.len() > MAX_REVOKE_PROOFS_BATCH_SIZE {
            panic_with_error!(&env, RegistryError::BatchTooLarge);
        }

        if reason_code > 255 {
            panic_with_error!(&env, RegistryError::InvalidReasonCode);
        }

        for proof_id in proof_ids.iter() {
            Self::revoke_proof_internal(&env, &admin, &proof_id, reason_code);
        }
    }

    // -----------------------------------------------------------------------
    // Lifecycle history (#90)
    // -----------------------------------------------------------------------

    pub fn verify_proof(env: Env, actor: Address, proof_id: BytesN<32>, reason_code: u32) {
        require_admin(&env, &actor);

        let _record = get_proof_record(&env, &proof_id);

        if reason_code > 255 {
            panic_with_error!(&env, RegistryError::InvalidReasonCode);
        }

        record_proof_history(
            &env,
            &proof_id,
            ProofLifecycleAction::Verified as u32,
            Some(actor),
            reason_code,
        );
    }

    pub fn expire_proof(env: Env, admin: Address, proof_id: BytesN<32>, reason_code: u32) {
        require_admin(&env, &admin);

        let mut record = get_proof_record(&env, &proof_id);
        if record.status == STATUS_REVOKED {
            panic_with_error!(&env, RegistryError::Unauthorized);
        }
        if record.status == STATUS_EXPIRED {
            panic_with_error!(&env, RegistryError::AlreadyExpired);
        }

        record.status = STATUS_EXPIRED;
        env.storage()
            .persistent()
            .set(&DataKey::Proof(proof_id.clone()), &record);

        record_proof_history(
            &env,
            &proof_id,
            ProofLifecycleAction::Expired as u32,
            Some(admin),
            reason_code,
        );
    }

    pub fn correct_proof(
        env: Env,
        admin: Address,
        proof_id: BytesN<32>,
        new_metadata_hash: BytesN<32>,
        reason_code: u32,
    ) {
        require_admin(&env, &admin);

        let mut record = get_proof_record(&env, &proof_id);
        if record.metadata_hash == new_metadata_hash {
            panic_with_error!(&env, RegistryError::NoCorrectionChange);
        }

        record.metadata_hash = new_metadata_hash.clone();
        env.storage()
            .persistent()
            .set(&DataKey::Proof(proof_id.clone()), &record);

        // Keep the versioned envelope hash in sync when present (#317).
        let envelope_key = DataKey::MetadataEnvelope(proof_id.clone());
        if let Some(mut envelope) = env
            .storage()
            .persistent()
            .get::<DataKey, MetadataEnvelope>(&envelope_key)
        {
            envelope.metadata_hash = new_metadata_hash;
            envelope.bound_at = env.ledger().timestamp();
            env.storage().persistent().set(&envelope_key, &envelope);
        }

        record_proof_history(
            &env,
            &proof_id,
            ProofLifecycleAction::Corrected as u32,
            Some(admin),
            reason_code,
        );
    }

    pub fn get_proof_history_at(
        env: Env,
        proof_id: BytesN<32>,
        seq: u32,
    ) -> Option<ProofHistoryEntry> {
        let total: u32 = env
            .storage()
            .persistent()
            .get(&DataKey::ProofHistorySeq(proof_id.clone()))
            .unwrap_or(0);

        if seq == 0 || seq > total {
            return None;
        }

        env.storage()
            .persistent()
            .get(&DataKey::ProofHistoryEntry(proof_id, seq))
    }

    pub fn get_proof_history_count(env: Env, proof_id: BytesN<32>) -> u32 {
        env.storage()
            .persistent()
            .get(&DataKey::ProofHistorySeq(proof_id))
            .unwrap_or(0)
    }

    // -----------------------------------------------------------------------
    // On-chain metadata envelope versioning (#317)
    // -----------------------------------------------------------------------

    /// Bind or upgrade a versioned metadata envelope for an existing proof.
    ///
    /// Compatible callers that only use `register_*` with a bare
    /// `metadata_hash` continue to work: `save_record` stamps V1 automatically.
    /// This entry point is for explicit V2 (or future) bindings and upgrades.
    ///
    /// Rules:
    /// - `version` must be in `1..=METADATA_ENVELOPE_VERSION_MAX`
    /// - `metadata_hash` must be non-zero and match the proof's stored hash
    /// - first bind may set any supported version
    /// - re-bind may only upgrade version (never downgrade)
    ///
    /// Auth: admin, or the proof's source/issuer when present.
    pub fn bind_metadata_envelope(
        env: Env,
        actor: Address,
        proof_id: BytesN<32>,
        version: u32,
        metadata_hash: BytesN<32>,
    ) -> MetadataEnvelope {
        if !env
            .storage()
            .persistent()
            .has(&DataKey::Proof(proof_id.clone()))
        {
            panic_with_error!(&env, RegistryError::MetadataEnvelopeNotFound);
        }

        let proof = get_proof_record(&env, &proof_id);
        require_metadata_envelope_actor(&env, &actor, &proof);
        require_supported_metadata_envelope_version(&env, version);

        let zero = BytesN::from_array(&env, &[0u8; 32]);
        if metadata_hash == zero {
            panic_with_error!(&env, RegistryError::InvalidMetadataEnvelope);
        }
        if metadata_hash != proof.metadata_hash {
            panic_with_error!(&env, RegistryError::MetadataEnvelopeHashMismatch);
        }

        let key = DataKey::MetadataEnvelope(proof_id.clone());
        let previous: Option<MetadataEnvelope> = env.storage().persistent().get(&key);
        if let Some(ref prev) = previous {
            if version < prev.version {
                panic_with_error!(&env, RegistryError::UnsupportedMetadataEnvelopeVersion);
            }
            if version == prev.version && metadata_hash == prev.metadata_hash {
                // Idempotent no-op return.
                return prev.clone();
            }
            if version == prev.version && metadata_hash != prev.metadata_hash {
                // Same-version hash changes go through `correct_proof`.
                panic_with_error!(&env, RegistryError::MetadataEnvelopeHashMismatch);
            }
        }

        let bound_at = env.ledger().timestamp();
        let envelope = MetadataEnvelope {
            proof_id: proof_id.clone(),
            version,
            metadata_hash: metadata_hash.clone(),
            bound_at,
        };
        env.storage().persistent().set(&key, &envelope);

        if let Some(prev) = previous {
            if version > prev.version {
                MetadataEnvelopeUpgraded {
                    upgraded: Symbol::new(&env, "upgraded"),
                    proof_id: proof_id.clone(),
                    previous: prev.version,
                    current: version,
                    metadata_hash: metadata_hash.clone(),
                }
                .publish(&env);
            }
        } else {
            MetadataEnvelopeBound {
                bound: Symbol::new(&env, "bound"),
                proof_id: proof_id.clone(),
                version,
                metadata_hash: metadata_hash.clone(),
                bound_at,
            }
            .publish(&env);
        }

        envelope
    }

    /// Return the versioned metadata envelope for `proof_id`, if stored.
    pub fn get_metadata_envelope(env: Env, proof_id: BytesN<32>) -> Option<MetadataEnvelope> {
        env.storage()
            .persistent()
            .get(&DataKey::MetadataEnvelope(proof_id))
    }

    /// Resolve the envelope version for a proof.
    ///
    /// Returns the stored envelope version when present; otherwise
    /// `METADATA_ENVELOPE_VERSION_DEFAULT` for proofs that exist without an
    /// explicit envelope row (pre-#317 / stamped callers). Returns `0` when
    /// the proof is unknown (callers must treat 0 as not-found).
    pub fn resolve_metadata_envelope_ver(env: Env, proof_id: BytesN<32>) -> u32 {
        if let Some(envelope) = env
            .storage()
            .persistent()
            .get::<DataKey, MetadataEnvelope>(&DataKey::MetadataEnvelope(proof_id.clone()))
        {
            return envelope.version;
        }
        if env.storage().persistent().has(&DataKey::Proof(proof_id)) {
            return METADATA_ENVELOPE_VERSION_DEFAULT;
        }
        0
    }

    /// Whether `version` is accepted by this wasm build.
    pub fn is_supported_envelope_version(_env: Env, version: u32) -> bool {
        version >= METADATA_ENVELOPE_V1 && version <= METADATA_ENVELOPE_VERSION_MAX
    }

    pub fn get_proof(env: Env, proof_id: BytesN<32>) -> Option<ProofRecord> {
        env.storage().persistent().get(&DataKey::Proof(proof_id))
    }

    pub fn get_by_video(env: Env, video_hash: BytesN<32>) -> Option<ProofRecord> {
        let proof_id: Option<BytesN<32>> =
            env.storage().persistent().get(&DataKey::Video(video_hash));
        proof_id.and_then(|id| env.storage().persistent().get(&DataKey::Proof(id)))
    }

    pub fn has_nullifier(env: Env, verifier: Address, nullifier: BytesN<32>) -> bool {
        if env.storage().persistent().has(&DataKey::VerifierNullifier(verifier, nullifier.clone())) {
            true
        } else {
            env.storage().persistent().has(&DataKey::Nullifier(nullifier))
        }
    }

    pub fn get_issuer(env: Env, issuer: Address) -> Option<IssuerRecord> {
        env.storage().persistent().get(&DataKey::Issuer(issuer))
    }

    /// Record a verifiable derivative of one or more existing artefacts, and
    /// persist the parent content commitments for privacy-preserving public
    /// boundaries (#332, #333).
    ///
    /// Parent commitments are derived on-chain from each parent's stored public
    /// fields so callers cannot supply forged bindings. `depth` is the depth the
    /// caller believes this derivative sits at: it is checked against the depth
    /// implied by the parents rather than trusted, so a caller cannot claim a
    /// shallow position to slip past `MAX_LINEAGE_DEPTH`; the stored record and
    /// the published event always carry the derived depth.
    ///
    /// Fails with `LineageFanOutExceeded` (#60) when the parent set exceeds
    /// `MAX_LINEAGE_FANOUT`, `LineageFanOutSaturated` (#79) when a parent
    /// already has `MAX_LINEAGE_FANOUT` derivatives, `LineageCycle` (#58) for a
    /// self-referential edge, `LineageTooDeep` (#59) past `MAX_LINEAGE_DEPTH`,
    /// `LineageDepthMismatch` (#80) for a forged depth, `DuplicateLineage` (#78)
    /// for an output digest that is already recorded, `LineageEmptyParents`
    /// (#76) for an empty parent set, `LineageParentUnavailable` (#77) for a
    /// revoked or expired proof parent, and `InvalidLineage` (#57) for a
    /// duplicated or unknown parent set.
    pub fn register_lineage(
        env: Env,
        actor: Address,
        parent_proof_ids: soroban_sdk::Vec<BytesN<32>>,
        manifest_digest: BytesN<32>,
        operation_type: Symbol,
        output_digest: BytesN<32>,
        depth: u32,
    ) -> LineageRecord {
        actor.require_auth();

        // A lineage record is immutable evidence. Re-registering an output
        // digest would let any caller overwrite a recorded derivation and spend
        // a parent's fan-out budget without producing a new derivative.
        if env
            .storage()
            .persistent()
            .has(&DataKey::Lineage(output_digest.clone()))
        {
            panic_with_error!(&env, RegistryError::DuplicateLineage);
        }

        let parent_commitments = collect_lineage_parent_commitments(&env, &parent_proof_ids);

        let record = LineageRecord {
            parent_proof_ids: parent_proof_ids.clone(),
            parent_commitments: parent_commitments.clone(),
            manifest_digest: manifest_digest.clone(),
            actor: actor.clone(),
            operation_type: operation_type.clone(),
            output_digest: output_digest.clone(),
            depth: derived_depth,
        };
        env.storage()
            .persistent()
            .set(&DataKey::Lineage(output_digest.clone()), &record);

        LineageRegistered {
            output_digest: output_digest.clone(),
            manifest_digest: manifest_digest.clone(),
            actor: actor.clone(),
            operation_type: operation_type.clone(),
            depth: derived_depth,
            parent_commitments,
        }
        .publish(&env);

        // Index this derivative under each parent for reverse (children) queries (#335).
        for parent in parent_proof_ids.iter() {
            append_lineage_child(&env, &parent, &output_digest);
        }

        record
    }

    pub fn get_lineage(env: Env, output_digest: BytesN<32>) -> Option<LineageRecord> {
        env.storage()
            .persistent()
            .get(&DataKey::Lineage(output_digest))
    }

    // -----------------------------------------------------------------------
    // Independent timestamp claims (#339)
    // -----------------------------------------------------------------------

    /// Anchor an independent timestamp claim for an existing proof.
    ///
    /// Always records the current ledger timestamp/sequence as a Stellar
    /// independent source. Optional `claimed_time` and RFC 3161 commitment
    /// raise assurance without storing raw tokens or private material.
    ///
    /// Re-anchoring is allowed only when the new claim is a strict assurance
    /// upgrade (or adds an RFC 3161 commitment). Compatible callers that omit
    /// timestamp claims are unaffected.
    pub fn anchor_timestamp_claim(
        env: Env,
        actor: Address,
        proof_id: BytesN<32>,
        attestation_digest: BytesN<32>,
        claimed_time: u64,
        rfc3161_commitment: BytesN<32>,
    ) -> TimestampClaim {
        // Proof must exist.
        if !env
            .storage()
            .persistent()
            .has(&DataKey::Proof(proof_id.clone()))
        {
            panic_with_error!(&env, RegistryError::TimestampClaimNotFound);
        }

        let proof = get_proof_record(&env, &proof_id);
        require_timestamp_claim_actor(&env, &actor, &proof);

        // Reject zero attestation digest (must bind to off-chain envelope).
        let zero = BytesN::from_array(&env, &[0u8; 32]);
        if attestation_digest == zero {
            panic_with_error!(&env, RegistryError::InvalidTimestampClaim);
        }

        let now = env.ledger().timestamp();
        if claimed_time > 0 && claimed_time > now.saturating_add(MAX_TIMESTAMP_FUTURE_DRIFT_SECS) {
            panic_with_error!(&env, RegistryError::InvalidTimestampClaim);
        }

        let has_rfc3161 = rfc3161_commitment != zero;
        // Empty commitment is fine; non-empty is treated as RFC 3161 present.
        // (No further parsing on-chain — resource-bounded by fixed 32 bytes.)

        let mut sources = TIMESTAMP_SOURCE_STELLAR;
        if claimed_time > 0 {
            sources |= TIMESTAMP_SOURCE_CLAIMED;
        }
        if has_rfc3161 {
            sources |= TIMESTAMP_SOURCE_RFC3161;
        }

        let assurance = compute_timestamp_assurance(sources);
        let ledger_sequence = env.ledger().sequence();

        let claim = TimestampClaim {
            proof_id: proof_id.clone(),
            attestation_digest: attestation_digest.clone(),
            claimed_time,
            anchored_at: now,
            ledger_sequence,
            sources,
            rfc3161_commitment: if has_rfc3161 {
                rfc3161_commitment
            } else {
                zero
            },
            actor: actor.clone(),
            assurance,
        };

        let key = DataKey::TimestampClaim(proof_id.clone());
        if let Some(existing) = env
            .storage()
            .persistent()
            .get::<DataKey, TimestampClaim>(&key)
        {
            // Allow only upgrades: higher assurance, or same assurance with new RFC3161.
            let adds_rfc3161 = has_rfc3161 && (existing.sources & TIMESTAMP_SOURCE_RFC3161) == 0;
            if assurance < existing.assurance || (assurance == existing.assurance && !adds_rfc3161)
            {
                panic_with_error!(&env, RegistryError::TimestampClaimAlreadyAnchored);
            }
        }

        env.storage().persistent().set(&key, &claim);

        TimestampClaimAnchored {
            proof_id: proof_id.clone(),
            attestation_digest: attestation_digest.clone(),
            sources,
            assurance,
            anchored_at: now,
            ledger_sequence,
        }
        .publish(&env);

        claim
    }

    /// Return the timestamp claim for `proof_id`, if any.
    pub fn get_timestamp_claim(env: Env, proof_id: BytesN<32>) -> Option<TimestampClaim> {
        env.storage()
            .persistent()
            .get(&DataKey::TimestampClaim(proof_id))
    }

    /// Whether the proof has an independently verifiable on-chain timestamp
    /// source (Stellar ledger and/or RFC 3161 commitment).
    pub fn has_independent_timestamp_anchor(env: Env, proof_id: BytesN<32>) -> bool {
        match env
            .storage()
            .persistent()
            .get::<DataKey, TimestampClaim>(&DataKey::TimestampClaim(proof_id))
        {
            Some(claim) => {
                (claim.sources & (TIMESTAMP_SOURCE_STELLAR | TIMESTAMP_SOURCE_RFC3161)) != 0
            }
            None => false,
        }
    }
    /// Return only the stored parent commitments for `output_digest` (#332).
    ///
    /// Useful for interoperable consumers that must not pull full lineage
    /// topology (parent proof ids) across a trust boundary.
    pub fn get_lineage_parent_commitments(
        env: Env,
        output_digest: BytesN<32>,
    ) -> Option<soroban_sdk::Vec<BytesN<32>>> {
        let record: Option<LineageRecord> = env
            .storage()
            .persistent()
            .get(&DataKey::Lineage(output_digest));
        record.map(|r| r.parent_commitments)
    }

    /// Return how many child digests are indexed under `parent_proof_id` (#335).
    pub fn get_lineage_children_count(env: Env, parent_proof_id: BytesN<32>) -> u32 {
        env.storage()
            .persistent()
            .get(&DataKey::LineageChildSeq(parent_proof_id))
            .unwrap_or(0)
    }

    /// Paginate child output digests for a parent proof or lineage digest (#335).
    ///
    /// - `offset` is 0-based into the stable registration order.
    /// - `limit` must be in `1..=MAX_LINEAGE_CHILDREN_PAGE`.
    /// - Missing parents yield an empty page with `total == 0` (privacy-safe).
    pub fn list_lineage_children(
        env: Env,
        parent_proof_id: BytesN<32>,
        offset: u32,
        limit: u32,
    ) -> LineageChildrenPage {
        if limit == 0 || limit > MAX_LINEAGE_CHILDREN_PAGE {
            panic_with_error!(&env, RegistryError::LineageChildrenLimitExceeded);
        }

        let total: u32 = env
            .storage()
            .persistent()
            .get(&DataKey::LineageChildSeq(parent_proof_id.clone()))
            .unwrap_or(0);

        let mut children = SorobanVec::new(&env);
        if offset >= total {
            return LineageChildrenPage {
                children,
                next_offset: total,
                total,
            };
        }

        let end = if total - offset < limit {
            total
        } else {
            offset + limit
        };

        let mut idx = offset;
        while idx < end {
            let seq = idx + 1; // 1-based storage keys
            if let Some(child) = env
                .storage()
                .persistent()
                .get::<DataKey, BytesN<32>>(&DataKey::LineageChild(parent_proof_id.clone(), seq))
            {
                children.push_back(child);
            }
            idx += 1;
        }

        LineageChildrenPage {
            children,
            next_offset: end,
            total,
        }
    }

    // -----------------------------------------------------------------------
    // Revocation-witness root management (#98)
    // -----------------------------------------------------------------------

    pub fn set_revocation_root(env: Env, admin: Address, revocation_root: BytesN<32>) {
        require_admin(&env, &admin);
        env.storage()
            .persistent()
            .set(&DataKey::RevocationRoot, &revocation_root);
        RevocationRootSet { revocation_root }.publish(&env);
    }

    pub fn get_revocation_root(env: Env) -> Option<BytesN<32>> {
        env.storage().persistent().get(&DataKey::RevocationRoot)
    }

    /// Verify a non-revocation proof produced by the `revocation_witness`
    /// Noir circuit.
    ///
    /// The proof demonstrates that `credential_root` is **not** a member of
    /// the currently-published revocation tree (`revocation_root`) without
    /// revealing which revoked credentials exist or which identity is acting.
    ///
    /// # Public input layout (128 bytes, 4 x BN254 field elements)
    ///
    /// ```text
    /// [  0.. 32)  revocation_root   - must match the on-chain stored root
    /// [ 32.. 64)  nullifier         - one-use replay guard
    /// [ 64.. 96)  domain_separator  - must match REVOCATION_DOMAIN_SEPARATOR
    /// [ 96..128)  credential_root   - must be registered & active on-chain
    /// ```
    ///
    /// # Reverts
    ///
    /// - `NotInitialized`      if no revocation root has been published yet
    /// - `VerifierNotSet`       if no external verifier contract is configured
    /// - `InvalidPublicInputs`  if the domain separator or layout is wrong
    /// - `UnknownCredentialRoot` if the credential has not been registered
    /// - `RevokedCredentialRoot` if the credential root has been revoked
    /// - `DuplicateNullifier`   if this nullifier was already consumed
    /// - `InvalidProof`         if the external verifier rejects the proof
    pub fn check_non_revocation(env: Env, public_inputs: Bytes, proof: Bytes) {
        let parsed = parse_revocation_public_inputs(&env, &public_inputs);

        // 1. Domain binding - must match the expected version tag.
        let expected_domain = BytesN::from_array(&env, &REVOCATION_DOMAIN_SEPARATOR);
        if parsed.domain_separator != expected_domain {
            panic_with_error!(&env, RegistryError::InvalidPublicInputs);
        }

        // 2. Revocation root - must match the currently published root.
        let stored_root: BytesN<32> = env
            .storage()
            .persistent()
            .get(&DataKey::RevocationRoot)
            .unwrap_or_else(|| panic_with_error!(&env, RegistryError::NotInitialized));
        if parsed.revocation_root != stored_root {
            panic_with_error!(&env, RegistryError::InvalidPublicInputs);
        }

        require_active_credential_root(&env, &parsed.credential_root);

        let verifier: Address = env
            .storage()
            .persistent()
            .get(&DataKey::Verifier)
            .unwrap_or_else(|| panic_with_error!(&env, RegistryError::VerifierNotSet));
        require_verified_proof(
            &env,
            &verifier,
            CIRCUIT_VERSION_REVOCATION_WITNESS,
            public_inputs,
            proof,
        );

        env.storage()
            .persistent()
            .set(&DataKey::VerifierNullifier(verifier, parsed.nullifier.clone()), &true);

        NonRevocationChecked {
            credential_root: parsed.credential_root,
            nullifier: parsed.nullifier,
            revocation_root: parsed.revocation_root,
        }
        .publish(&env);
    }

    // -----------------------------------------------------------------------
    // Scoped emergency pause controls (#87)
    // -----------------------------------------------------------------------

    /// Assign the address permitted to trigger emergency pauses without
    /// holding the admin key. Admin-only. Pass the admin's own address to
    /// revoke the guardian role.
    pub fn set_guardian(env: Env, admin: Address, guardian: Address) {
        require_admin(&env, &admin);
        env.storage()
            .persistent()
            .set(&DataKey::Guardian, &guardian);
        GuardianSet { guardian }.publish(&env);
    }

    /// Remove the emergency-pause guardian role. Admin-only.
    pub fn clear_guardian(env: Env, admin: Address) {
        require_admin(&env, &admin);
        env.storage().persistent().remove(&DataKey::Guardian);
        GuardianCleared {}.publish(&env);
    }

    /// The currently configured guardian, if any.
    pub fn get_guardian(env: Env) -> Option<Address> {
        env.storage().persistent().get(&DataKey::Guardian)
    }

    /// Pause one or more registration domains (`PAUSE_DOMAIN_*`, or their
    /// bitwise-OR combination) for `duration_secs`. Callable by the admin or
    /// the guardian; the admin is capped at `MAX_PAUSE_DURATION_SECS`, the
    /// guardian at `MAX_GUARDIAN_PAUSE_DURATION_SECS`. Re-pausing an
    /// already-paused domain extends (overwrites) its expiry rather than
    /// erroring, so retries are idempotent. Reads and non-registration admin
    /// entry points are never affected. Returns the epoch-second timestamp
    /// at which the pause auto-expires.
    pub fn pause(env: Env, caller: Address, domain: u32, duration_secs: u64) -> u64 {
        validate_domain(&env, domain);
        let is_admin = require_pauser(&env, &caller);
        let max_duration = if is_admin {
            MAX_PAUSE_DURATION_SECS
        } else {
            MAX_GUARDIAN_PAUSE_DURATION_SECS
        };
        if duration_secs == 0 || duration_secs > max_duration {
            panic_with_error!(&env, RegistryError::InvalidPauseDuration);
        }

        let paused_at = env.ledger().timestamp();
        let expires_at = paused_at.saturating_add(duration_secs);

        for bit in domain_bits(domain) {
            env.storage().persistent().set(
                &DataKey::Pause(bit),
                &PauseRecord {
                    paused_by: caller.clone(),
                    paused_at,
                    expires_at,
                },
            );
        }

        DomainPaused {
            domain,
            paused_by: caller,
            paused_at,
            expires_at,
        }
        .publish(&env);

        expires_at
    }

    /// Lift a pause early. Admin-only — a guardian can raise the alarm but
    /// only the admin can stand it down before the bounded expiry. Unpausing
    /// a domain that is not currently stored as paused is a no-op.
    pub fn unpause(env: Env, admin: Address, domain: u32) {
        validate_domain(&env, domain);
        require_admin(&env, &admin);

        let unpaused_at = env.ledger().timestamp();
        let mut changed = false;
        for bit in domain_bits(domain) {
            if env.storage().persistent().has(&DataKey::Pause(bit)) {
                env.storage().persistent().remove(&DataKey::Pause(bit));
                changed = true;
            }
        }

        if changed {
            DomainUnpaused {
                domain,
                unpaused_by: admin,
                unpaused_at,
            }
            .publish(&env);
        }
    }

    /// Read-only: is any bit of `domain` currently paused (i.e. has an
    /// unexpired pause record)? A domain past its `expires_at` is treated as
    /// unpaused even if a stale record has not yet been cleared.
    pub fn is_paused(env: Env, domain: u32) -> bool {
        validate_domain(&env, domain);
        let now = env.ledger().timestamp();
        domain_bits(domain).any(|bit| domain_is_paused(&env, bit, now))
    }

    /// Read-only: the raw pause record for a single domain bit, if one is
    /// currently stored (including a stale record past its `expires_at`
    /// that has not yet been cleared by `unpause`).
    pub fn get_pause_state(env: Env, domain: u32) -> Option<PauseRecord> {
        validate_single_domain(&env, domain);
        env.storage().persistent().get(&DataKey::Pause(domain))
    }

    // -----------------------------------------------------------------------
    // Cross-layer verifier-input conformance
    // -----------------------------------------------------------------------

    /// Classify verifier material against the canonical `hpx-vi/1` codec.
    ///
    /// Read-only, side-effect free, and bounded: the work is O(1) in the frame
    /// size and no storage is touched, so it is safe to expose publicly and
    /// safe to call while any domain is paused.
    ///
    /// `schema_id` is [`SCHEMA_ID_SILENT_WITNESS`],
    /// [`SCHEMA_ID_SILENT_WITNESS_V2`], or [`SCHEMA_ID_REVOCATION_WITNESS`].
    /// `proof_len` is the length of the proof blob the caller intends to submit
    /// — passed as a length rather than the blob itself so classification never
    /// transports proof material.
    ///
    /// Returns [`verifier_inputs::ACCEPTED_CODE`] (`0`) when the material is
    /// canonical, otherwise the stable [`RejectCode::as_code`] value. This is
    /// the on-chain half of the cross-layer conformance corpus in
    /// `zk/vectors/verifier_conformance_v1.json`.
    ///
    /// Compatibility: this entry point is purely additive. The registration
    /// paths still apply the v1-lenient rules described in
    /// `docs/zk-conformance-vectors.md`; promoting the codec to enforcement is
    /// a separate, versioned migration.
    pub fn classify_public_inputs(
        _env: Env,
        schema_id: u32,
        public_inputs: Bytes,
        proof_len: u32,
    ) -> u32 {
        // Schema dispatch precedes the length check, matching the Python and
        // TypeScript layers: an unrecognised schema is reported as such even
        // when the frame is also the wrong length.
        if schema_id != SCHEMA_ID_SILENT_WITNESS
            && schema_id != SCHEMA_ID_SILENT_WITNESS_V2
            && schema_id != SCHEMA_ID_REVOCATION_WITNESS
        {
            return RejectCode::UnknownSchema.as_code();
        }

        // Each schema has its own frame length (silent witness v1 160 bytes,
        // the circuit-versioned v2 envelope 256 bytes, revocation 128 bytes),
        // matching `verifier_inputs::classify`.
        let silent_v1 = schema_id == SCHEMA_ID_SILENT_WITNESS;
        let silent_v2 = schema_id == SCHEMA_ID_SILENT_WITNESS_V2;
        let expected_len: u32 = if silent_v1 {
            SILENT_WITNESS_V1_INPUT_LEN
        } else if silent_v2 {
            verifier_inputs::SILENT_WITNESS_V2_PUBLIC_INPUTS_LEN as u32
        } else {
            REVOCATION_PUBLIC_INPUTS_LEN as u32
        };
        if public_inputs.len() != expected_len {
            return RejectCode::Length.as_code();
        }

        let parsed = if silent_v1 {
            let mut frame = [0u8; PUBLIC_INPUTS_LEN];
            public_inputs.copy_into_slice(&mut frame);
            verifier_inputs::parse_silent_witness(
                &frame,
                &verifier_inputs::SILENT_WITNESS_DOMAIN_TAG_BE,
            )
            .map(|_| ())
        } else if silent_v2 {
            let mut frame = [0u8; verifier_inputs::SILENT_WITNESS_V2_PUBLIC_INPUTS_LEN];
            public_inputs.copy_into_slice(&mut frame);
            verifier_inputs::parse_silent_witness_v2(
                &frame,
                &verifier_inputs::SILENT_WITNESS_DOMAIN_TAG_BE,
            )
            .map(|_| ())
        } else {
            let mut frame = [0u8; REVOCATION_PUBLIC_INPUTS_LEN];
            public_inputs.copy_into_slice(&mut frame);
            verifier_inputs::parse_revocation_witness(&frame, &REVOCATION_DOMAIN_SEPARATOR)
                .map(|_| ())
        };

        if let Err(code) = parsed {
            return code.as_code();
        }

        match verifier_inputs::check_proof_bounds(proof_len) {
            Ok(()) => verifier_inputs::ACCEPTED_CODE,
            Err(code) => code.as_code(),
        }
    }

    // -----------------------------------------------------------------------
    // Schema management (issuer-certified attribute schemas)
    // -----------------------------------------------------------------------

    pub fn add_schema(
        env: Env,
        admin: Address,
        schema_hash: BytesN<32>,
        issuer_namespace: BytesN<32>,
        version: u32,
        attribute_count: u32,
    ) {
        require_admin(&env, &admin);

        if env
            .storage()
            .persistent()
            .has(&DataKey::Schema(schema_hash.clone()))
        {
            panic_with_error!(&env, RegistryError::DuplicateProof);
        }

        if attribute_count == 0 || attribute_count > 16 {
            panic_with_error!(&env, RegistryError::InvalidPublicInputs);
        }

        let created_at = env.ledger().timestamp();
        env.storage().persistent().set(
            &DataKey::Schema(schema_hash.clone()),
            &SchemaRecord {
                schema_hash: schema_hash.clone(),
                issuer_namespace: issuer_namespace.clone(),
                version,
                active: true,
                attribute_count,
                created_at,
            },
        );
        SchemaAdded {
            schema_hash,
            issuer_namespace,
            version,
            attribute_count,
        }
        .publish(&env);
    }

    pub fn deprecate_schema(env: Env, admin: Address, schema_hash: BytesN<32>) {
        require_admin(&env, &admin);

        let mut record = get_schema_record(&env, &schema_hash);
        record.active = false;
        env.storage()
            .persistent()
            .set(&DataKey::Schema(schema_hash.clone()), &record);
        SchemaDeprecated { schema_hash }.publish(&env);
    }

    pub fn get_schema(env: Env, schema_hash: BytesN<32>) -> Option<SchemaRecord> {
        env.storage()
            .persistent()
            .get(&DataKey::Schema(schema_hash))
    }

    // -----------------------------------------------------------------------
    // Selective disclosure verification
    // -----------------------------------------------------------------------

    pub fn verify_selective_disclosure(env: Env, public_inputs: Bytes, proof: Bytes) {
        let parsed = parse_selective_disclosure_inputs(&env, &public_inputs);

        if parsed.circuit_version != CURRENT_SELECTIVE_DISCLOSURE_VERSION as u32 {
            panic_with_error!(&env, RegistryError::SchemaVersionMismatch);
        }

        let schema = get_schema_record(&env, &parsed.schema_hash);
        if !schema.active {
            panic_with_error!(&env, RegistryError::InactiveSchema);
        }

        if schema.version != parsed.schema_version {
            panic_with_error!(&env, RegistryError::SchemaVersionMismatch);
        }

        if schema.issuer_namespace != parsed.issuer_namespace {
            panic_with_error!(&env, RegistryError::InvalidPublicInputs);
        }

        require_active_credential_root(&env, &parsed.credential_root);

        let verifier: Address = env
            .storage()
            .persistent()
            .get(&DataKey::Verifier)
            .unwrap_or_else(|| panic_with_error!(&env, RegistryError::VerifierNotSet));
        require_verified_proof(
            &env,
            &verifier,
            CIRCUIT_VERSION_SELECTIVE_DISCLOSURE,
            public_inputs,
            proof,
        );

        env.storage()
            .persistent()
            .set(&DataKey::VerifierNullifier(verifier, parsed.nullifier.clone()), &true);

        SelectiveDisclosureVerified {
            schema_hash: parsed.schema_hash,
            credential_root: parsed.credential_root,
            nullifier: parsed.nullifier,
            evidence_digest: parsed.evidence_digest,
        }
        .publish(&env);
    }

    // -----------------------------------------------------------------------
    // Paginated verifier-set inspection
    // -----------------------------------------------------------------------

    /// Return a bounded, stable page of the current verifier configuration.
    ///
    /// Slots are ordered: **Active → Pending → Previous**. Only non-None
    /// slots appear in `entries`. `cursor` is a 0-based slot index; pass
    /// `next_cursor` from the previous response to continue paging.
    ///
    /// # Arguments
    ///
    /// * `cursor` – starting slot index (0 = first populated slot). A cursor
    ///   beyond the end of the populated list returns an empty page.
    /// * `limit`  – maximum entries per page. Must be non-zero and at most
    ///   `MAX_VERIFIER_LIST_LIMIT`. Returns `ListLimitExceeded` otherwise.
    ///
    /// # Privacy
    ///
    /// This is a read-only query equivalent to `get_verifier` — no private
    /// witness values, credential secrets, nullifiers, or video hashes are
    /// surfaced. An out-of-range cursor produces an empty page rather than a
    /// revealing error, so a scanner cannot enumerate capacity by probing.
    ///
    /// # Migration / compatibility
    ///
    /// Additive: before any verifier is configured, returns an empty page.
    /// Callers that only need the active verifier should use `get_verifier`.
    pub fn list_verifiers(env: Env, cursor: u32, limit: u32) -> VerifierPage {
        if limit == 0 || limit > MAX_VERIFIER_LIST_LIMIT {
            panic_with_error!(&env, RegistryError::ListLimitExceeded);
        }

        // Build the ordered, flattened slot list from storage.
        // Slots are built deterministically: Active → Pending → Previous.
        // This avoids heap allocation of a variable-length list in no_std by
        // using a fixed-size array of Option<VerifierEntry>.
        let slots = collect_verifier_slots(&env);

        // Count the total populated (non-None) slots across all positions.
        let total_populated: u32 = slots.iter().filter(|s| s.is_some()).count() as u32;

        let slot_len = slots.len() as u32;

        // A cursor beyond the slot list always returns an empty page.
        // This is intentional: it does not reveal the set size via an error.
        let mut entries: SorobanVec<VerifierEntry> = SorobanVec::new(&env);
        if cursor >= slot_len {
            return VerifierPage {
                entries,
                next_cursor: None,
                total_populated,
            };
        }

        // Walk from `cursor` up to `limit` items, skipping None slots.
        let mut idx = cursor;
        let mut filled: u32 = 0;
        while idx < slot_len && filled < limit {
            if let Some(entry) = slots[idx as usize].clone() {
                entries.push_back(entry);
                filled += 1;
            }
            idx += 1;
        }

        // `next_cursor` is Some if there are any remaining slots (None or Some)
        // that we have not yet reached. We only set it if there is actually
        // a remaining populated slot; empty slots beyond are not worth paging.
        let next_cursor = if idx < slot_len {
            // Check whether any remaining slot is populated.
            let has_more = slots[idx as usize..].iter().any(|s| s.is_some());
            if has_more { Some(idx) } else { None }
        } else {
            None
        };

        VerifierPage {
            entries,
            next_cursor,
            total_populated,
        }
    }

    // -----------------------------------------------------------------------
    // Dispute / correction state machine (#dispute)
    // -----------------------------------------------------------------------

    /// Open a new dispute against a registered proof.
    ///
    /// # Parameters
    /// - `reporter`:        The reporter's address (requires auth; proves liveness).
    /// - `reporter_hash`:   Privacy-safe commitment H(reporter_address || proof_id),
    ///   computed off-chain by the reporter. The raw reporter address is never
    ///   stored in contract state or events.
    /// - `dispute_id`:      Caller-chosen 32-byte unique identifier.
    /// - `proof_id`:        The proof being challenged.
    /// - `reason`:          Categorised dispute reason.
    /// - `commitment_hash`: Off-chain commitment to the reporter's submission.
    ///
    /// # Guards
    /// - Proof must exist.
    /// - `dispute_id` must not already be used.
    /// - Proof must have fewer than `MAX_OPEN_DISPUTES_PER_PROOF` open disputes.
    /// - Reporter must not be on cooldown for this proof.
    pub fn open_dispute(
        env: Env,
        reporter: Address,
        reporter_hash: BytesN<32>,
        dispute_id: BytesN<32>,
        proof_id: BytesN<32>,
        reason: DisputeReason,
        commitment_hash: BytesN<32>,
    ) -> DisputeRecord {
        reporter.require_auth();

        // 1. Proof must exist.
        if !env
            .storage()
            .persistent()
            .has(&DataKey::Proof(proof_id.clone()))
        {
            panic_with_error!(&env, RegistryError::DisputeNotFound);
        }

        // 2. dispute_id must be fresh.
        if env
            .storage()
            .persistent()
            .has(&DataKey::Dispute(dispute_id.clone()))
        {
            panic_with_error!(&env, RegistryError::DuplicateProof);
        }

        // 3. Cap open disputes per proof.
        let open_count: u32 = env
            .storage()
            .persistent()
            .get(&DataKey::ProofOpenDisputeCount(proof_id.clone()))
            .unwrap_or(0u32);
        if open_count >= MAX_OPEN_DISPUTES_PER_PROOF {
            panic_with_error!(&env, RegistryError::TooManyOpenDisputes);
        }

        // 3b. Cap open disputes per reporter across all proofs.
        let reporter_count_key = DataKey::ReporterOpenDisputeCount(reporter.clone());
        let reporter_open_count: u32 = env
            .storage()
            .persistent()
            .get(&reporter_count_key)
            .unwrap_or(0u32);
        if reporter_open_count >= MAX_OPEN_DISPUTES_PER_REPORTER {
            panic_with_error!(&env, RegistryError::ReporterDisputesSaturated);
        }

        // 4. Reporter cooldown (keyed by the privacy-safe reporter_hash).
        // Uses temporary storage so entries do not consume persistent rent unnecessarily
        // and are automatically reclaimed after the cooldown window.
        let cooldown_key = DataKey::ReporterCooldown(reporter_hash.clone());
        let last_open: u64 = env
            .storage()
            .temporary()
            .get(&cooldown_key)
            .unwrap_or(0u64);
        let now = env.ledger().timestamp();
        if last_open > 0 && now.saturating_sub(last_open) < REPORTER_COOLDOWN_SECS {
            panic_with_error!(&env, RegistryError::ReporterOnCooldown);
        }

        // 5. Store cooldown timestamp in temporary storage with TTL matching the cooldown window.
        env.storage().temporary().set(&cooldown_key, &now);
        const REPORTER_COOLDOWN_LEDGERS: u32 = (REPORTER_COOLDOWN_SECS / 5) as u32;
        env.storage().temporary().extend_ttl(
            &cooldown_key,
            REPORTER_COOLDOWN_LEDGERS,
            REPORTER_COOLDOWN_LEDGERS,
        );

        // 6. Compute deadlines.
        let respond_deadline = now.saturating_add(RESPOND_DEADLINE_SECS);

        // 7. Build and store the dispute record.
        let record = DisputeRecord {
            dispute_id: dispute_id.clone(),
            proof_id: proof_id.clone(),
            reason,
            reporter_hash: reporter_hash.clone(),
            commitment_hash: commitment_hash.clone(),
            reporter: reporter.clone(),
            status: DisputeStatus::Open,
            opened_at: now,
            respond_deadline,
            resolve_deadline: 0,
            response_commitment: None,
            resolved_at: 0,
            superseded_by: None,
        };
        let dispute_key = DataKey::Dispute(dispute_id.clone());
        env.storage()
            .persistent()
            .set(&dispute_key, &record);
        env.storage()
            .persistent()
            .extend_ttl(&dispute_key, BUMP_THRESHOLD_LEDGERS, BUMP_TARGET_LEDGERS);

        // 8. Increment open-dispute counters (per proof and per reporter).
        let proof_dispute_count_key = DataKey::ProofOpenDisputeCount(proof_id.clone());
        env.storage().persistent().set(
            &proof_dispute_count_key,
            &(open_count + 1),
        );
        env.storage().persistent().extend_ttl(
            &proof_dispute_count_key,
            BUMP_THRESHOLD_LEDGERS,
            BUMP_TARGET_LEDGERS,
        );
        env.storage()
            .persistent()
            .set(&reporter_count_key, &(reporter_open_count + 1));
        env.storage().persistent().extend_ttl(
            &reporter_count_key,
            BUMP_THRESHOLD_LEDGERS,
            BUMP_TARGET_LEDGERS,
        );

        // 8b. Append dispute to per-proof dispute index.
        append_proof_dispute(&env, &proof_id, &dispute_id);

        // 9. Emit event.
        DisputeOpened {
            dispute_id,
            proof_id,
            reason,
            reporter_hash,
            commitment_hash,
            respond_deadline,
        }
        .publish(&env);

        record
    }

    /// Submit a response commitment to an open dispute.
    ///
    /// Only the issuer (Tier 3) or source (Tier 2) of the disputed proof may
    /// respond. Tier 1 (Silent Witness) proofs have no on-chain identity, so
    /// the admin acts as the sole responder for anonymous proofs.
    ///
    /// # Guards
    /// - Dispute must be in `Open` state.
    /// - Must be within `respond_deadline`.
    /// - Caller must be the issuer, source, or (for anonymous proofs) admin.
    pub fn respond_dispute(
        env: Env,
        responder: Address,
        dispute_id: BytesN<32>,
        response_commitment: BytesN<32>,
    ) -> DisputeRecord {
        responder.require_auth();

        let mut record = get_dispute_record(&env, &dispute_id);

        // Must be Open.
        if record.status != DisputeStatus::Open {
            panic_with_error!(&env, RegistryError::InvalidDisputeTransition);
        }

        let now = env.ledger().timestamp();

        // Must be within respond_deadline.
        if now > record.respond_deadline {
            panic_with_error!(&env, RegistryError::DisputeWindowExpired);
        }

        // Authorise: issuer, source, or admin.
        let proof: ProofRecord = env
            .storage()
            .persistent()
            .get(&DataKey::Proof(record.proof_id.clone()))
            .unwrap_or_else(|| panic_with_error!(&env, RegistryError::DisputeNotFound));

        let admin: Address = env
            .storage()
            .persistent()
            .get(&DataKey::Admin)
            .unwrap_or_else(|| panic_with_error!(&env, RegistryError::NotInitialized));

        let is_authorised = match (proof.issuer.as_ref(), proof.source.as_ref()) {
            (Some(issuer), _) => &responder == issuer || &responder == &admin,
            (_, Some(source)) => &responder == source || &responder == &admin,
            _ => &responder == &admin, // Tier 1: admin only
        };

        if !is_authorised {
            panic_with_error!(&env, RegistryError::UnauthorizedResponder);
        }

        // Transition -> Responded.
        record.status = DisputeStatus::Responded;
        record.response_commitment = Some(response_commitment.clone());
        record.resolve_deadline = now.saturating_add(RESOLVE_DEADLINE_SECS);

        let dispute_key = DataKey::Dispute(dispute_id.clone());
        env.storage()
            .persistent()
            .set(&dispute_key, &record);
        env.storage()
            .persistent()
            .extend_ttl(&dispute_key, BUMP_THRESHOLD_LEDGERS, BUMP_TARGET_LEDGERS);

        let proof_dispute_count_key = DataKey::ProofOpenDisputeCount(record.proof_id.clone());
        if env.storage().persistent().has(&proof_dispute_count_key) {
            env.storage().persistent().extend_ttl(
                &proof_dispute_count_key,
                BUMP_THRESHOLD_LEDGERS,
                BUMP_TARGET_LEDGERS,
            );
        }

        DisputeResponded {
            dispute_id,
            proof_id: record.proof_id.clone(),
            response_commitment,
            resolve_deadline: record.resolve_deadline,
        }
        .publish(&env);

        record
    }

    /// Resolve a responded dispute (admin only).
    ///
    /// Resolution indicates that the admin has reviewed both the dispute and
    /// the response commitments and has taken (or noted) any appropriate
    /// corrective action. The original proof record is **not** modified.
    ///
    /// # Guards
    /// - Dispute must be in `Responded` state.
    /// - Must be within `resolve_deadline`.
    pub fn resolve_dispute(env: Env, admin: Address, dispute_id: BytesN<32>) -> DisputeRecord {
        require_admin(&env, &admin);

        let mut record = get_dispute_record(&env, &dispute_id);

        // Must be Responded.
        if record.status != DisputeStatus::Responded {
            panic_with_error!(&env, RegistryError::InvalidDisputeTransition);
        }

        let now = env.ledger().timestamp();

        if now > record.resolve_deadline {
            panic_with_error!(&env, RegistryError::DisputeWindowExpired);
        }

        // Transition -> Resolved.
        record.status = DisputeStatus::Resolved;
        record.resolved_at = now;

        let dispute_key = DataKey::Dispute(dispute_id.clone());
        env.storage()
            .persistent()
            .set(&dispute_key, &record);
        env.storage()
            .persistent()
            .extend_ttl(&dispute_key, BUMP_THRESHOLD_LEDGERS, BUMP_TARGET_LEDGERS);

        // Decrement open-dispute counters (per proof and per reporter).
        decrement_open_dispute_count(&env, &record.proof_id);
        decrement_reporter_open_dispute_count(&env, &record.reporter);

        DisputeResolved {
            dispute_id,
            proof_id: record.proof_id.clone(),
            resolved_at: now,
        }
        .publish(&env);

        record
    }

    /// Dismiss a dispute (admin only).
    ///
    /// Dismissal is valid from both `Open` and `Responded` states. A dismissed
    /// dispute is permanently closed with no corrective action.
    pub fn dismiss_dispute(env: Env, admin: Address, dispute_id: BytesN<32>) -> DisputeRecord {
        require_admin(&env, &admin);

        let mut record = get_dispute_record(&env, &dispute_id);

        // Must be non-terminal.
        match record.status {
            DisputeStatus::Open | DisputeStatus::Responded => {}
            _ => panic_with_error!(&env, RegistryError::DisputeAlreadyClosed),
        }

        let now = env.ledger().timestamp();

        // Transition -> Dismissed.
        record.status = DisputeStatus::Dismissed;
        record.resolved_at = now;

        let dispute_key = DataKey::Dispute(dispute_id.clone());
        env.storage()
            .persistent()
            .set(&dispute_key, &record);
        env.storage()
            .persistent()
            .extend_ttl(&dispute_key, BUMP_THRESHOLD_LEDGERS, BUMP_TARGET_LEDGERS);

        // Decrement open-dispute counters (per proof and per reporter).
        decrement_open_dispute_count(&env, &record.proof_id);
        decrement_reporter_open_dispute_count(&env, &record.reporter);

        DisputeDismissed {
            dispute_id,
            proof_id: record.proof_id.clone(),
            resolved_at: now,
        }
        .publish(&env);

        record
    }

    /// Supersede a disputed proof by linking a corrected proof (admin only).
    ///
    /// This marks the dispute as `Superseded` and records the correcting proof
    /// ID. The original disputed proof is **not** revoked - callers should use
    /// `revoke_proof` separately if revocation is also desired.
    ///
    /// # Guards
    /// - Dispute must be in `Open` or `Responded` state.
    /// - `superseding_proof_id` must exist in the registry.
    /// - It must not equal the disputed `proof_id` (trivial cycle).
    /// - It must not already point back to the disputed proof (depth-1 cycle).
    pub fn supersede_dispute(
        env: Env,
        admin: Address,
        dispute_id: BytesN<32>,
        superseding_proof_id: BytesN<32>,
    ) -> DisputeRecord {
        require_admin(&env, &admin);

        let mut record = get_dispute_record(&env, &dispute_id);

        // Must be non-terminal.
        match record.status {
            DisputeStatus::Open | DisputeStatus::Responded => {}
            _ => panic_with_error!(&env, RegistryError::DisputeAlreadyClosed),
        }

        // Superseding proof must exist.
        if !env
            .storage()
            .persistent()
            .has(&DataKey::Proof(superseding_proof_id.clone()))
        {
            panic_with_error!(&env, RegistryError::DisputeNotFound);
        }

        // Trivial self-cycle.
        if superseding_proof_id == record.proof_id {
            panic_with_error!(&env, RegistryError::DisputeCyclicSupersession);
        }

        // Depth-1 cycle guard via the compact reverse index.
        if check_supersession_cycle(&env, &record.proof_id, &superseding_proof_id) {
            panic_with_error!(&env, RegistryError::DisputeCyclicSupersession);
        }

        let now = env.ledger().timestamp();

        // Transition -> Superseded.
        record.status = DisputeStatus::Superseded;
        record.superseded_by = Some(superseding_proof_id.clone());
        record.resolved_at = now;

        let dispute_key = DataKey::Dispute(dispute_id.clone());
        env.storage()
            .persistent()
            .set(&dispute_key, &record);
        env.storage()
            .persistent()
            .extend_ttl(&dispute_key, BUMP_THRESHOLD_LEDGERS, BUMP_TARGET_LEDGERS);

        // Record the reverse supersession direction for cycle detection.
        record_supersession_direction(&env, &record.proof_id, &superseding_proof_id);

        // Decrement open-dispute counters (per proof and per reporter).
        decrement_open_dispute_count(&env, &record.proof_id);
        decrement_reporter_open_dispute_count(&env, &record.reporter);

        DisputeSuperseded {
            dispute_id,
            proof_id: record.proof_id.clone(),
            superseded_by: superseding_proof_id,
            resolved_at: now,
        }
        .publish(&env);

        record
    }

    /// Retrieve a dispute record by its dispute_id.
    pub fn get_dispute(env: Env, dispute_id: BytesN<32>) -> Option<DisputeRecord> {
        let key = DataKey::Dispute(dispute_id);
        let record: Option<DisputeRecord> = env.storage().persistent().get(&key);
        if let Some(ref rec) = record {
            env.storage()
                .persistent()
                .extend_ttl(&key, BUMP_THRESHOLD_LEDGERS, BUMP_TARGET_LEDGERS);
            let count_key = DataKey::ProofOpenDisputeCount(rec.proof_id.clone());
            if env.storage().persistent().has(&count_key) {
                env.storage()
                    .persistent()
                    .extend_ttl(&count_key, BUMP_THRESHOLD_LEDGERS, BUMP_TARGET_LEDGERS);
            }
        }
        record
    }

    /// Return the number of currently Open disputes for a given proof.
    pub fn get_open_dispute_count(env: Env, proof_id: BytesN<32>) -> u32 {
        let key = DataKey::ProofOpenDisputeCount(proof_id);
        if env.storage().persistent().has(&key) {
            env.storage()
                .persistent()
                .extend_ttl(&key, BUMP_THRESHOLD_LEDGERS, BUMP_TARGET_LEDGERS);
        }
        env.storage()
            .persistent()
            .get(&key)
            .unwrap_or(0u32)
    }

    /// Return the number of currently open (non-terminal) disputes opened by
    /// `reporter` across all proofs.
    pub fn get_reporter_open_dispute_count(env: Env, reporter: Address) -> u32 {
        env.storage()
            .persistent()
            .get(&DataKey::ReporterOpenDisputeCount(reporter))
            .unwrap_or(0u32)
    }

    /// Return the total number of disputes ever opened for a given proof.
    pub fn get_proof_dispute_count(env: Env, proof_id: BytesN<32>) -> u32 {
        env.storage()
            .persistent()
            .get(&DataKey::ProofDisputeSeq(proof_id))
            .unwrap_or(0u32)
    }

    /// Return dispute IDs for a proof in creation order with pagination.
    ///
    /// - `cursor` is the zero-based offset into the proof's disputes.
    /// - `limit` is the maximum number of dispute IDs to return, capped by
    ///   `MAX_PROOF_DISPUTES_PAGE`.
    /// - Missing proofs or proofs without disputes yield an empty list (privacy-safe).
    pub fn list_proof_disputes(
        env: Env,
        proof_id: BytesN<32>,
        cursor: u32,
        limit: u32,
    ) -> SorobanVec<BytesN<32>> {
        let total: u32 = env
            .storage()
            .persistent()
            .get(&DataKey::ProofDisputeSeq(proof_id.clone()))
            .unwrap_or(0);

        let mut disputes = SorobanVec::new(&env);
        if cursor >= total {
            return disputes;
        }

        let effective_limit = if limit > MAX_PROOF_DISPUTES_PAGE {
            MAX_PROOF_DISPUTES_PAGE
        } else {
            limit
        };

        if effective_limit == 0 {
            return disputes;
        }

        let remaining = total - cursor;
        let count = if remaining < effective_limit {
            remaining
        } else {
            effective_limit
        };

        let end = cursor + count;
        let mut idx = cursor;
        while idx < end {
            let seq = idx + 1; // 1-based storage keys
            if let Some(dispute_id) = env
                .storage()
                .persistent()
                .get::<DataKey, BytesN<32>>(&DataKey::ProofDispute(proof_id.clone(), seq))
            {
                disputes.push_back(dispute_id);
            }
            idx += 1;
        }

        disputes
    }

fn require_admin(env: &Env, candidate: &Address) {
    let admin: Option<Address> = env.storage().persistent().get(&DataKey::Admin);
    let admin = admin.unwrap_or_else(|| panic_with_error!(env, RegistryError::NotInitialized));

    candidate.require_auth();
    if &admin != candidate {
        panic_with_error!(env, RegistryError::Unauthorized);
    }
}

/// Reject issuer role assignment to an address that currently holds registry
/// administrator authority. Callers that create pending state must separately
/// check the pending address so a proposal cannot be used to stage a conflict.
fn require_issuer_role_available(env: &Env, issuer: &Address) {
    let admin: Address = env
        .storage()
        .persistent()
        .get(&DataKey::Admin)
        .unwrap_or_else(|| panic_with_error!(env, RegistryError::NotInitialized));
    if issuer == &admin {
        panic_with_error!(env, RegistryError::RoleConflict);
    }
}

/// Reject transferring admin authority to an address with active issuer
/// authority. Revoked issuer records remain safe to transfer into and preserve
/// the historical metadata returned by `get_issuer`.
fn require_admin_role_available(env: &Env, candidate: &Address) {
    require_issuer_role_available(env, candidate);
    let issuer_record: Option<IssuerRecord> = env
        .storage()
        .persistent()
        .get(&DataKey::Issuer(candidate.clone()));
    if matches!(
        issuer_record,
        Some(IssuerRecord {
            active: true,
            ..
        })
    ) {
        panic_with_error!(env, RegistryError::RoleConflict);
    }
}

/// Require that `caller` is either the admin or the configured guardian, and
/// authorize the call. Returns `true` when the caller is the admin, so
/// callers can apply role-specific limits (e.g. pause duration caps).
fn require_pauser(env: &Env, caller: &Address) -> bool {
    let admin: Address = env
        .storage()
        .persistent()
        .get(&DataKey::Admin)
        .unwrap_or_else(|| panic_with_error!(env, RegistryError::NotInitialized));

    caller.require_auth();

    if caller == &admin {
        return true;
    }

    let guardian: Option<Address> = env.storage().persistent().get(&DataKey::Guardian);
    match guardian {
        Some(g) if &g == caller => false,
        _ => panic_with_error!(env, RegistryError::Unauthorized),
    }
}

/// Require that `caller` may commit a receipt digest for `record`: either the
/// registry admin (any tier) or the proof's own tier-2 source / tier-3 issuer.
/// Tier 1 proofs carry no on-chain identity, so they are admin-only — the
/// same precedent `respond_dispute` uses for anonymous proofs.
///
/// `caller.require_auth()` must already have run; this function only decides
/// whether the (public) proof record names the caller.
fn require_receipt_actor(env: &Env, caller: &Address, record: &ProofRecord) {
    let admin: Address = env
        .storage()
        .persistent()
        .get(&DataKey::Admin)
        .unwrap_or_else(|| panic_with_error!(env, RegistryError::NotInitialized));
    if caller == &admin {
        return;
    }

    let matches_subject = match record.tier {
        TIER_CONSISTENT_SOURCE => record.source.as_ref() == Some(caller),
        TIER_PUBLIC_SEAL => record.issuer.as_ref() == Some(caller),
        _ => false,
    };
    if !matches_subject {
        panic_with_error!(env, RegistryError::Unauthorized);
    }
}

/// Number of currently active receipt-signing keys.
fn receipt_signer_count(env: &Env) -> u32 {
    env.storage()
        .persistent()
        .get(&DataKey::ReceiptSignerCount)
        .unwrap_or(0u32)
}

/// Domain-separated digest a receipt signer must sign for
/// `commit_receipt_digest` to accept a commitment.
///
/// Preimage layout (129 bytes, see `RECEIPT_ATTEST_PREIMAGE_LEN`):
///
/// ```text
/// [  0.. 29)  RECEIPT_ATTEST_DOMAIN  "harpocrates:receipt-digest:v1"
/// [ 29.. 65)  XDR of the calling contract's address
///             (4-byte big-endian discriminant 1 || 32-byte contract id)
/// [ 65.. 97)  proof_id
/// [ 97..129)  receipt_digest
/// ```
///
/// Binding the contract address keeps an attestation issued for one
/// deployment from being replayed against another registry that happens to
/// register the same signer key.
fn receipt_attestation_digest(
    env: &Env,
    proof_id: &BytesN<32>,
    receipt_digest: &BytesN<32>,
) -> Hash<32> {
    let mut preimage = Bytes::new(env);
    preimage.extend_from_slice(&RECEIPT_ATTEST_DOMAIN);
    // `to_xdr` serializes an Address as an ScVal: a 4-byte ScVal type tag
    // followed by the ScAddress XDR (4-byte discriminant 1 || 32-byte
    // contract id) that the attestation binds to. Keep only the ScAddress arm.
    let contract_xdr = env.current_contract_address().to_xdr(env);
    preimage.append(&contract_xdr.slice(4..40));
    preimage.extend_from_slice(&proof_id.to_array());
    preimage.extend_from_slice(&receipt_digest.to_array());

    if preimage.len() != RECEIPT_ATTEST_PREIMAGE_LEN {
        panic_with_error!(env, RegistryError::InvalidPublicInputs);
    }

    env.crypto().sha256(&preimage)
}

/// Reject `scope` unless it is nonzero and composed only of known
/// `DELEGATION_SCOPE_*` bits.
fn validate_delegation_scope(env: &Env, scope: u32) {
    if scope == 0 || scope & !DELEGATION_SCOPE_ALL != 0 {
        panic_with_error!(env, RegistryError::InvalidDelegationScope);
    }
}

fn delegation_count(env: &Env, grantor: &Address) -> u32 {
    env.storage()
        .persistent()
        .get(&DataKey::DelegationCount(grantor.clone()))
        .unwrap_or(0)
}

/// Require a live delegation from `grantor` to `delegate` carrying every bit of
/// `scope`, and authorize the call.
///
/// The three failure modes are kept distinct — absent, expired, and
/// insufficiently scoped — because an operator responding to a failed
/// registration needs to know which one happened, and none of the three
/// discloses anything about the media or the proof.
/// Resolve the caller's live delegation and require it to carry `scope`.
///
/// Returns the record so the caller can also bound its own artifact by the
/// delegation's expiry (#338). Reverts with the stable `DelegationNotFound`,
/// `DelegationExpired`, or `DelegationScopeExceeded` code.
fn require_delegation(
    env: &Env,
    grantor: &Address,
    delegate: &Address,
    scope: u32,
) -> DelegationRecord {
    validate_delegation_scope(env, scope);

    let record: DelegationRecord = env
        .storage()
        .persistent()
        .get(&DataKey::Delegation(grantor.clone(), delegate.clone()))
        .unwrap_or_else(|| panic_with_error!(env, RegistryError::DelegationNotFound));

    if env.ledger().timestamp() >= record.expires_at {
        panic_with_error!(env, RegistryError::DelegationExpired);
    }

    if record.scope & scope != scope {
        panic_with_error!(env, RegistryError::DelegationScopeExceeded);
    }

    record
}

/// Bound a delegated registration's lifetime by the delegation that authorized
/// it (#338).
///
/// A non-zero proof TTL is capped at the delegation's `expires_at`; an eternal
/// proof (TTL `0`) becomes exactly the delegation's expiry instead of `0`. The
/// delegation has already been checked live, so the result is strictly in the
/// future and can never be zero. Direct, non-delegated registration is
/// untouched.
fn bounded_delegated_expiry(env: &Env, delegation_expires_at: u64) -> u64 {
    let ttl_expiry = compute_expires_at(env);
    if ttl_expiry == 0 {
        delegation_expires_at
    } else {
        ttl_expiry.min(delegation_expires_at)
    }
}

/// Reject `domain` unless it is nonzero and composed only of known
/// `PAUSE_DOMAIN_*` bits. Accepts single domains and their bitwise-OR
/// combination (e.g. `PAUSE_DOMAIN_ALL_REGISTRATION`).
fn validate_domain(env: &Env, domain: u32) {
    if domain == 0 || domain & !PAUSE_DOMAIN_ALL_REGISTRATION != 0 {
        panic_with_error!(env, RegistryError::InvalidPauseDomain);
    }
}

/// Reject `domain` unless it is exactly one known `PAUSE_DOMAIN_*` bit.
fn validate_single_domain(env: &Env, domain: u32) {
    if !PAUSE_DOMAIN_SINGLE_BITS.contains(&domain) {
        panic_with_error!(env, RegistryError::InvalidPauseDomain);
    }
}

/// Iterate the single-bit domains present in `domain` (already validated by
/// `validate_domain`/`validate_single_domain`).
fn domain_bits(domain: u32) -> impl Iterator<Item = u32> {
    PAUSE_DOMAIN_SINGLE_BITS
        .into_iter()
        .filter(move |bit| domain & bit != 0)
}

fn domain_is_paused(env: &Env, domain_bit: u32, now: u64) -> bool {
    let record: Option<PauseRecord> = env.storage().persistent().get(&DataKey::Pause(domain_bit));
    match record {
        Some(r) => now < r.expires_at,
        None => false,
    }
}

fn require_domain_unpaused(env: &Env, domain_bit: u32) {
    let now = env.ledger().timestamp();
    if domain_is_paused(env, domain_bit, now) {
        panic_with_error!(env, RegistryError::Paused);
    }
}

/// Compute the `expires_at` value for a freshly registered proof.
///
/// Returns `created_at + ttl` when a non-zero TTL is configured, or `0`
/// (no expiration) otherwise.  Uses saturating addition to avoid overflow on
/// extreme inputs.
fn compute_expires_at(env: &Env) -> u64 {
    let ttl: u64 = env
        .storage()
        .persistent()
        .get(&DataKey::ProofTtl)
        .unwrap_or(DEFAULT_PROOF_TTL_SECS);
    if ttl == 0 {
        0
    } else {
        env.ledger().timestamp().saturating_add(ttl)
    }
}

fn require_unique(env: &Env, proof_id: &BytesN<32>, video_hash: &BytesN<32>) {
    if env
        .storage()
        .persistent()
        .has(&DataKey::Proof(proof_id.clone()))
    {
        panic_with_error!(env, RegistryError::DuplicateProof);
    }

    if env
        .storage()
        .persistent()
        .has(&DataKey::Video(video_hash.clone()))
    {
        panic_with_error!(env, RegistryError::DuplicateVideo);
    }
}

fn get_proof_record(env: &Env, proof_id: &BytesN<32>) -> ProofRecord {
    env.storage()
        .persistent()
        .get(&DataKey::Proof(proof_id.clone()))
        .unwrap_or_else(|| panic_with_error!(env, RegistryError::DuplicateProof))
}

fn get_issuer_record(env: &Env, issuer: &Address) -> IssuerRecord {
    env.storage()
        .persistent()
        .get(&DataKey::Issuer(issuer.clone()))
        .unwrap_or_else(|| panic_with_error!(env, RegistryError::UnknownIssuer))
}

fn get_credential_root_record_opt(
    env: &Env,
    credential_root: &BytesN<32>,
) -> Option<CredentialRootRecord> {
    let key_v2 = DataKey::CredentialRootV2(credential_root.clone());
    if let Some(record) = env.storage().persistent().get(&key_v2) {
        return Some(record);
    }
    let key_v1 = DataKey::CredentialRoot(credential_root.clone());
    if let Some(v1) = env.storage().persistent().get::<_, CredentialRootRecordV1>(&key_v1) {
        return Some(CredentialRootRecord {
            metadata_hash: v1.metadata_hash,
            status: if v1.active { STATUS_REGISTERED } else { STATUS_REVOKED },
            issued_at: v1.issued_at,
            expires_at: 0,
        });
    }
    None
}

fn get_credential_root_record(env: &Env, credential_root: &BytesN<32>) -> CredentialRootRecord {
    get_credential_root_record_opt(env, credential_root)
        .unwrap_or_else(|| panic_with_error!(env, RegistryError::UnknownCredentialRoot))
}

fn index_credential_root(env: &Env, root: &BytesN<32>) -> bool {
    let indexed_key = DataKey::CredentialRootIndexed(root.clone());
    if env.storage().persistent().has(&indexed_key) {
        return false;
    }
    let seq_key = DataKey::CredentialRootSeq;
    let seq: u32 = env.storage().persistent().get(&seq_key).unwrap_or(0);
    let next_seq = seq.saturating_add(1);
    env.storage()
        .persistent()
        .set(&DataKey::CredentialRootIndex(next_seq), root);
    env.storage().persistent().set(&seq_key, &next_seq);
    env.storage().persistent().set(&indexed_key, &next_seq);
    true
}

fn backfill_credential_roots_step(env: &Env) {
    let backfill_key = DataKey::CredentialRootsBackfillQueue;
    let queue_opt: Option<SorobanVec<BytesN<32>>> = env
        .storage()
        .persistent()
        .get(&backfill_key)
        .or_else(|| env.storage().persistent().get(&DataKey::CredentialRootsBackfill));

    if let Some(queue) = queue_opt {
        let cursor_key = DataKey::CredentialRootsBackfillCursor;
        let mut cursor: u32 = env.storage().persistent().get(&cursor_key).unwrap_or(0);
        let total = queue.len();
        let mut processed = 0u32;
        while cursor < total && processed < MAX_ROOTS_BACKFILL_BATCH {
            let root = queue.get(cursor).unwrap();
            index_credential_root(env, &root);
            cursor += 1;
            processed += 1;
        }
        env.storage().persistent().set(&cursor_key, &cursor);
    }
}

fn get_active_verifier(env: &Env) -> Address {
    env.storage()
        .persistent()
        .get(&DataKey::Verifier)
        .unwrap_or_else(|| panic_with_error!(env, RegistryError::VerifierNotSet))
}

fn get_verifier_rotation_state(env: &Env) -> VerifierState {
    env.storage()
        .persistent()
        .get(&DataKey::VerifierState)
        .unwrap_or(VerifierState {
            active_verifier: env.storage().persistent().get(&DataKey::Verifier),
            pending_verifier: None,
            previous_verifier: None,
            activation_ledger: 0,
            overlap_window: 0,
            rollback_window: 0,
            rollback_window_end: 0,
        })
}

/// Build the ordered, fixed-size slot list for `list_verifiers`.
///
/// Returns exactly 3 entries in role order: [Active, Pending, Previous].
/// Each entry is `None` if the corresponding slot is unpopulated.
///
/// The active slot is read from `DataKey::Verifier` (the canonical active
/// address) first. If `DataKey::VerifierState` is present the pending and
/// previous slots are taken from it. When the VerifierState carries an
/// `active_verifier` that differs from `DataKey::Verifier` (e.g. mid-
/// rotation) the `DataKey::Verifier` value is authoritative for the Active
/// slot, matching the semantics of `get_verifier`.
fn collect_verifier_slots(env: &Env) -> [Option<VerifierEntry>; 3] {
    let active_addr: Option<Address> = env.storage().persistent().get(&DataKey::Verifier);

    let state_opt: Option<VerifierState> =
        env.storage().persistent().get(&DataKey::VerifierState);

    let active_entry = active_addr.map(|addr| VerifierEntry {
        address: addr,
        role: VerifierRole::Active,
    });

    let (pending_entry, previous_entry) = match state_opt {
        Some(state) => {
            let pending = state.pending_verifier.map(|addr| VerifierEntry {
                address: addr,
                role: VerifierRole::Pending,
            });
            let previous = state.previous_verifier.map(|addr| VerifierEntry {
                address: addr,
                role: VerifierRole::Previous,
            });
            (pending, previous)
        }
        None => (None, None),
    };

    [active_entry, pending_entry, previous_entry]
}

fn require_active_credential_root(env: &Env, credential_root: &BytesN<32>) {
    let record = get_credential_root_record(env, credential_root);
    if record.status == STATUS_REVOKED {
        panic_with_error!(env, RegistryError::RevokedCredentialRoot);
    }
    if record.status == STATUS_EXPIRED || (record.expires_at > 0 && env.ledger().timestamp() >= record.expires_at) {
        panic_with_error!(env, RegistryError::ExpiredCredentialRoot);
    }
}

fn append_lineage_child(env: &Env, parent: &BytesN<32>, child: &BytesN<32>) {
    let seq_key = DataKey::LineageChildSeq(parent.clone());
    let current: u32 = env.storage().persistent().get(&seq_key).unwrap_or(0);
    if current >= MAX_LINEAGE_CHILDREN_PER_PARENT {
        panic_with_error!(env, RegistryError::LineageChildrenSaturated);
    }
    let next = current + 1;
    env.storage()
        .persistent()
        .set(&DataKey::LineageChild(parent.clone(), next), child);
    env.storage().persistent().set(&seq_key, &next);
}

fn append_proof_dispute(env: &Env, proof_id: &BytesN<32>, dispute_id: &BytesN<32>) {
    let seq_key = DataKey::ProofDisputeSeq(proof_id.clone());
    let current: u32 = env.storage().persistent().get(&seq_key).unwrap_or(0);
    let next = current + 1;
    env.storage()
        .persistent()
        .set(&DataKey::ProofDispute(proof_id.clone(), next), dispute_id);
    env.storage().persistent().set(&seq_key, &next);
}

fn save_record(
    env: &Env,
    proof_id: &BytesN<32>,
    record: ProofRecord,
    actor: Option<Address>,
) -> ProofRecord {
    env.storage()
        .persistent()
        .set(&DataKey::Proof(proof_id.clone()), &record);
    env.storage()
        .persistent()
        .set(&DataKey::Video(record.video_hash.clone()), proof_id);
    ProofRegistered {
        proof_id: proof_id.clone(),
        video_hash: record.video_hash.clone(),
        tier: record.tier,
        status: record.status,
        batch_size: record.batch_size,
    }
    .publish(env);
    // Registration has one canonical observable order: the domain event is
    // emitted first, followed by the append-only lifecycle history event.
    // Keeping both emissions here also covers aggregated registrations and
    // prevents a new registration path from silently omitting history.
    record_proof_history(
        env,
        proof_id,
        ProofLifecycleAction::Registered as u32,
        actor,
        record.tier,
    );
    // Stamp a V1 metadata envelope for bare-hash registrations (#317).
    // Explicit V2+ bindings use `bind_metadata_envelope` after register.
    stamp_default_metadata_envelope(env, proof_id, &record.metadata_hash);
    record
}

/// Append a bounded, privacy-safe lifecycle entry to a proof's history (#90).
///
/// Enforces `MAX_HISTORY_ENTRIES_PER_PROOF`, rejects unknown actions and
/// out-of-range reason codes, and emits only the `ProofHistoryEvent`
/// (`["proof", "history", proof_id]`). No media, proof bytes, witnesses,
/// nullifiers, or metadata hashes are written or emitted here.
fn record_proof_history(
    env: &Env,
    proof_id: &BytesN<32>,
    action: u32,
    actor: Option<Address>,
    reason_code: u32,
) {
    if !(1..=6).contains(&action) {
        panic_with_error!(env, RegistryError::InvalidHistoryAction);
    }
    if reason_code > 255 {
        panic_with_error!(env, RegistryError::InvalidReasonCode);
    }

    let seq_key = DataKey::ProofHistorySeq(proof_id.clone());
    let seq: u32 = env.storage().persistent().get(&seq_key).unwrap_or(0);

    if seq >= MAX_HISTORY_ENTRIES_PER_PROOF {
        panic_with_error!(env, RegistryError::HistorySaturated);
    }

    let next_seq = seq + 1;
    let now = env.ledger().timestamp();
    env.storage().persistent().set(
        &DataKey::ProofHistoryEntry(proof_id.clone(), next_seq),
        &ProofHistoryEntry {
            action,
            timestamp: now,
            actor: actor.clone(),
            reason_code,
        },
    );
    env.storage().persistent().set(&seq_key, &next_seq);

    ProofHistoryEvent {
        proof_id: proof_id.clone(),
        action,
        timestamp: now,
        actor,
        reason_code,
    }
    .publish(env);
}

fn require_timestamp_claim_actor(env: &Env, actor: &Address, proof: &ProofRecord) {
    actor.require_auth();

    let admin: Address = env
        .storage()
        .persistent()
        .get(&DataKey::Admin)
        .unwrap_or_else(|| panic_with_error!(env, RegistryError::NotInitialized));
    if actor == &admin {
        return;
    }
    if let Some(ref source) = proof.source {
        if actor == source {
            return;
        }
    }
    if let Some(ref issuer) = proof.issuer {
        if actor == issuer {
            return;
        }
    }
    panic_with_error!(env, RegistryError::UnauthorizedTimestampActor);
}

fn compute_timestamp_assurance(sources: u32) -> u32 {
    let independent = (sources & (TIMESTAMP_SOURCE_STELLAR | TIMESTAMP_SOURCE_RFC3161)) != 0;
    if independent {
        return TIMESTAMP_ASSURANCE_INDEPENDENT;
    }
    if (sources & TIMESTAMP_SOURCE_CLAIMED) != 0 {
        return TIMESTAMP_ASSURANCE_CLAIMED;
    }
    TIMESTAMP_ASSURANCE_NONE
}

/// Validate a lineage edge set: bounded fan-out and depth, no self-reference,
/// and every parent must already be a known proof or lineage record.
/// Validate a lineage edge set: non-empty, bounded fan-out and depth, no
/// self-reference, and every parent must already be a usable proof or lineage
/// record (proofs must not be revoked/expired).

/// Derivatives already recorded against `parent` (#333).
fn lineage_child_count(env: &Env, parent: &BytesN<32>) -> u32 {
    env.storage()
        .persistent()
        .get(&DataKey::LineageChildCount(parent.clone()))
        .unwrap_or(0u32)
}

/// Validate a lineage edge set and return the depth it implies (#333).
///
/// Every bound is checked before anything is written, so a rejected edge never
/// leaves a parent charged for a derivative that was not recorded:
///
/// - The parent set is non-empty (`LineageEmptyParents`), at most
///   `MAX_LINEAGE_FANOUT` long (in-degree), and contains no repeated digest, so
///   the cap counts distinct edges rather than duplicate entries.
/// - The output digest is not one of its own parents, and every parent is
///   already a known proof or lineage record, so an edge can only ever point at
///   evidence that exists. A proof parent must still be usable: a revoked or
///   expired proof cannot anchor a derivative (`LineageParentUnavailable`).
/// - The depth derived from the parents is within `MAX_LINEAGE_DEPTH` and equal
///   to `claimed_depth`, so a caller cannot claim a shallow position to slip
///   past the cap (`LineageDepthMismatch`).
/// - Every parent still has out-degree budget left under `MAX_LINEAGE_FANOUT`
///   (`LineageFanOutSaturated`).
fn require_supported_metadata_envelope_version(env: &Env, version: u32) {
    if version < METADATA_ENVELOPE_V1 || version > METADATA_ENVELOPE_VERSION_MAX {
        panic_with_error!(env, RegistryError::UnsupportedMetadataEnvelopeVersion);
    }
}

fn require_metadata_envelope_actor(env: &Env, actor: &Address, proof: &ProofRecord) {
    actor.require_auth();

    let admin: Address = env
        .storage()
        .persistent()
        .get(&DataKey::Admin)
        .unwrap_or_else(|| panic_with_error!(env, RegistryError::NotInitialized));
    if *actor == admin {
        return;
    }
    if let Some(ref source) = proof.source {
        if *actor == *source {
            return;
        }
    }
    if let Some(ref issuer) = proof.issuer {
        if *actor == *issuer {
            return;
        }
    }
    panic_with_error!(env, RegistryError::Unauthorized);
}

/// Idempotently stamp a V1 envelope for newly registered proofs.
fn stamp_default_metadata_envelope(env: &Env, proof_id: &BytesN<32>, metadata_hash: &BytesN<32>) {
    let key = DataKey::MetadataEnvelope(proof_id.clone());
    if env.storage().persistent().has(&key) {
        return;
    }
    let zero = BytesN::from_array(env, &[0u8; 32]);
    // Zero hash still gets a version stamp so resolve_* stays consistent;
    // bind_metadata_envelope rejects zero for explicit upgrades.
    let bound_at = env.ledger().timestamp();
    let envelope = MetadataEnvelope {
        proof_id: proof_id.clone(),
        version: METADATA_ENVELOPE_VERSION_DEFAULT,
        metadata_hash: if *metadata_hash == zero {
            zero
        } else {
            metadata_hash.clone()
        },
        bound_at,
    };
    env.storage().persistent().set(&key, &envelope);
    MetadataEnvelopeBound {
        bound: Symbol::new(&env, "bound"),
        proof_id: proof_id.clone(),
        version: METADATA_ENVELOPE_VERSION_DEFAULT,
        metadata_hash: envelope.metadata_hash.clone(),
        bound_at,
    }
    .publish(env);
}
fn validate_lineage(
    env: &Env,
    parent_proof_ids: &Vec<BytesN<32>>,
    output_digest: &BytesN<32>,
    claimed_depth: u32,
) -> u32 {
    let parent_count = parent_proof_ids.len();

    // A derivative with no parents is a registration, not a lineage edge.
    if parent_count == 0 {
        panic_with_error!(env, RegistryError::LineageEmptyParents);
    }
    if parent_count > MAX_LINEAGE_FANOUT {
        panic_with_error!(env, RegistryError::LineageFanOutExceeded);
    }

    let mut max_parent_depth: u32 = 0;
    for cursor in 0..parent_count {
        let parent = parent_proof_ids.get(cursor).unwrap();

        if parent == *output_digest {
            panic_with_error!(env, RegistryError::LineageCycle);
        }
        if env
            .storage()
            .persistent()
            .has(&DataKey::Proof(parent.clone()))
        {
            let status = HarpocratesRegistry::get_proof_status(env.clone(), parent.clone());
            if status != ProofVerificationStatus::Valid {
                panic_with_error!(env, RegistryError::LineageParentUnavailable);
            }
            continue;
        }
        if env
            .storage()
            .persistent()
            .has(&DataKey::Lineage(parent.clone()))
        {
            continue;
        }
        panic_with_error!(env, RegistryError::InvalidLineage);
    }

    let derived_depth = max_parent_depth.saturating_add(1);
    if derived_depth > MAX_LINEAGE_DEPTH {
        panic_with_error!(env, RegistryError::LineageTooDeep);
    }
    if claimed_depth != derived_depth {
        panic_with_error!(env, RegistryError::LineageDepthMismatch);
    }

    // Charge every parent's out-degree budget. Budgets are read before any is
    // written so a saturated parent cannot leave the earlier parents charged.
    for parent in parent_proof_ids.iter() {
        if lineage_child_count(env, &parent) >= MAX_LINEAGE_FANOUT {
            panic_with_error!(env, RegistryError::LineageFanOutSaturated);
        }
    }
    for parent in parent_proof_ids.iter() {
        let key = DataKey::LineageChildCount(parent.clone());
        let used = lineage_child_count(env, &parent);
        env.storage().persistent().set(&key, &(used + 1));
    }

    derived_depth
}

/// Derive the domain-separated parent content commitment (#332).
///
/// `SHA-256("harp_lin_pc" ‖ binding_a ‖ binding_b)` — opaque, reproducible,
/// and free of private media / witness material.
fn derive_lineage_parent_commitment(
    env: &Env,
    binding_a: &BytesN<32>,
    binding_b: &BytesN<32>,
) -> BytesN<32> {
    const PREFIX: [u8; 11] = *b"harp_lin_pc";
    let mut pre_image = [0u8; 75];
    pre_image[..11].copy_from_slice(&PREFIX);
    pre_image[11..43].copy_from_slice(&binding_a.to_array());
    pre_image[43..75].copy_from_slice(&binding_b.to_array());
    let pre_image_bytes = Bytes::from_array(env, &pre_image);
    env.crypto().sha256(&pre_image_bytes).into()
}

/// Build the parallel parent-commitment vector for a validated parent set.
fn collect_lineage_parent_commitments(
    env: &Env,
    parent_proof_ids: &SorobanVec<BytesN<32>>,
) -> SorobanVec<BytesN<32>> {
    let mut commitments = SorobanVec::new(env);
    for parent in parent_proof_ids.iter() {
        if let Some(proof) = env
            .storage()
            .persistent()
            .get::<DataKey, ProofRecord>(&DataKey::Proof(parent.clone()))
        {
            commitments.push_back(derive_lineage_parent_commitment(
                env,
                &proof.video_hash,
                &proof.metadata_hash,
            ));
            continue;
        }
        if let Some(lineage) = env
            .storage()
            .persistent()
            .get::<DataKey, LineageRecord>(&DataKey::Lineage(parent.clone()))
        {
            commitments.push_back(derive_lineage_parent_commitment(
                env,
                &lineage.manifest_digest,
                &lineage.output_digest,
            ));
            continue;
        }
        if check_lineage_cycle(env, &parent, output_digest) {
            panic_with_error!(env, RegistryError::LineageCycle);
        }
    }
}

fn check_lineage_cycle(env: &Env, proof_id: &BytesN<32>, target: &BytesN<32>) -> bool {
    let mut visited = SorobanVec::new(env);
    check_lineage_cycle_internal(env, proof_id, target, &mut visited, 1)
}

fn check_lineage_cycle_internal(
    env: &Env,
    proof_id: &BytesN<32>,
    target: &BytesN<32>,
    visited: &mut SorobanVec<BytesN<32>>,
    depth: u32,
) -> bool {
    if depth > MAX_LINEAGE_DEPTH {
        return false;
    }

    if visited.iter().any(|v| v == *proof_id) {
        return false;
    }
    visited.push_back(proof_id.clone());

    if *proof_id == *target {
        return true;
    }

    let lineage_key = DataKey::Lineage(proof_id.clone());
    if env.storage().persistent().has(&lineage_key) {
        let lineage: LineageRecord = env.storage().persistent().get(&lineage_key).unwrap();
        for parent in lineage.parent_proof_ids.iter() {
            if check_lineage_cycle_internal(env, &parent, target, visited, depth + 1) {
                return true;
            }
        }
    }

    false
}

/// Derive the deterministic sub-proof_id for batch element `index`.
///
/// Uses a full 32-byte XOR spread of the batch id so sibling elements never
/// collide while remaining reproducible from `(batch_id, index)` alone.
fn derive_element_proof_id(env: &Env, batch_id: &BytesN<32>, index: u32) -> BytesN<32> {
    let mut bytes = [0u8; 32];
    batch_id.copy_into_slice(&mut bytes);

    let index_byte = (index & 0xFF) as u8;
    for j in 0..32 {
        bytes[j] ^= index_byte.wrapping_mul((j as u8).wrapping_add(1));
    }

    BytesN::from_array(env, &bytes)
}

// ---------------------------------------------------------------------------
// Silent Witness v1 public input parsing (backward compatible)
// ---------------------------------------------------------------------------

struct SilentWitnessInputs {
    video_hash: BytesN<32>,
    credential_root: BytesN<32>,
    nullifier: BytesN<32>,
    domain_tag: BytesN<32>,
}

/// Compute the expected domain tag for this contract deployment.
///
/// The tag is BN254 Pedersen([DOMAIN_PROTOCOL_FIELD, DOMAIN_VERSION_FIELD, DOMAIN_NETWORK_FIELD]).
/// Because Soroban does not expose a Pedersen precompile we use SHA-256 as a
/// structurally equivalent binding: SHA-256(protocol_bytes || version_bytes || network_bytes).
/// The circuit constants (DOMAIN_*_FIELD) are derived from the same SHA-256 inputs so the
/// contract check mirrors the circuit constraint.
///
/// Concretely, the contract checks:
///   SHA-256(DOMAIN_PROTOCOL_FIELD || DOMAIN_VERSION_FIELD || DOMAIN_NETWORK_FIELD) == domain_tag
///
/// The off-chain prover populates domain_tag from the Noir helper circuit which uses
/// Pedersen; the two approaches diverge in algorithm but both bind to the same constants,
/// ensuring cross-version and cross-network rejection.
pub(crate) fn expected_domain_tag(env: &Env) -> BytesN<32> {
    let mut preimage = Bytes::new(env);
    preimage.extend_from_array(&DOMAIN_PROTOCOL_FIELD);
    preimage.extend_from_array(&DOMAIN_VERSION_FIELD);
    preimage.extend_from_array(&DOMAIN_NETWORK_FIELD);
    env.crypto().sha256(&preimage).into()
}

/// Parse the legacy (v1-lenient) silent-witness layout.
///
/// Behaviour is unchanged from the pre-codec implementation: only the frame
/// length is enforced. Field-level canonicity, half padding, and zero-field
/// rules are defined by [`verifier_inputs`] and surfaced through
/// [`HarpocratesRegistry::classify_public_inputs`]; see
/// `docs/zk-conformance-vectors.md` for the migration that promotes them to
/// enforcement on this path.
fn parse_silent_witness_public_inputs(env: &Env, public_inputs: &Bytes) -> SilentWitnessInputs {
    if public_inputs.len() != SILENT_WITNESS_V1_INPUT_LEN {
        panic_with_error!(env, RegistryError::InvalidPublicInputs);
    }
    let mut frame = [0u8; 160];
    public_inputs.copy_into_slice(&mut frame);

    let mut video_hash = [0u8; 32];
    video_hash[..16].copy_from_slice(&frame[16..32]);
    video_hash[16..].copy_from_slice(&frame[48..64]);

    let mut credential_root = [0u8; 32];
    credential_root.copy_from_slice(&frame[64..96]);

    let mut nullifier = [0u8; 32];
    nullifier.copy_from_slice(&frame[96..128]);

    let mut domain_tag = [0u8; 32];
    domain_tag.copy_from_slice(&frame[128..160]);

    SilentWitnessInputs {
        video_hash: BytesN::from_array(env, &video_hash),
        credential_root: BytesN::from_array(env, &credential_root),
        nullifier: BytesN::from_array(env, &nullifier),
        domain_tag: BytesN::from_array(env, &domain_tag),
    }
}

struct BrowserSilentWitnessInputs {
    video_hash: BytesN<32>,
    credential_root: BytesN<32>,
    nullifier: BytesN<32>,
}

/// Parse the 128-byte public-input blob produced by the browser silent_witness Noir circuit
/// (frontend/public/noir/silent_witness.json).
///
/// Layout (4 x BN254 field elements, 32 bytes each):
///   [ 0.. 32)  video_hash_hi (low 16 bytes)
///   [32.. 64)  video_hash_lo (low 16 bytes)
///   [64.. 96)  credential_root
///   [96..128)  nullifier
fn parse_browser_silent_witness_public_inputs(
    env: &Env,
    public_inputs: &Bytes,
) -> BrowserSilentWitnessInputs {
    if public_inputs.len() != SILENT_WITNESS_BROWSER_V1_INPUT_LEN {
        panic_with_error!(env, RegistryError::InvalidPublicInputs);
    }
    let mut frame = [0u8; 128];
    public_inputs.copy_into_slice(&mut frame);

    let mut video_hash = [0u8; 32];
    video_hash[..16].copy_from_slice(&frame[16..32]);
    video_hash[16..].copy_from_slice(&frame[48..64]);

    let mut credential_root = [0u8; 32];
    credential_root.copy_from_slice(&frame[64..96]);

    let mut nullifier = [0u8; 32];
    nullifier.copy_from_slice(&frame[96..128]);

    BrowserSilentWitnessInputs {
        video_hash: BytesN::from_array(env, &video_hash),
        credential_root: BytesN::from_array(env, &credential_root),
        nullifier: BytesN::from_array(env, &nullifier),
    }
}


// ---------------------------------------------------------------------------
// Silent Witness v2 (scoped) public input parsing
// ---------------------------------------------------------------------------

struct ScopedSilentWitnessInputs {
    video_hash: BytesN<32>,
    credential_root: BytesN<32>,
    nullifier: BytesN<32>,
    verifier_scope: BytesN<32>,
    epoch: u64,
    domain_tag: BytesN<32>,
}

/// Parse the public-input blob produced by the v2 scoped silent_witness Noir
/// circuit: the 256-byte envelope carrying the circuit-version trailer (#368).
///
/// The envelope appends a 32-byte `circuit_version` field that the producing
/// circuit asserted in-circuit, so the proof names its own circuit; it must
/// decode to [`verifier_inputs::EXPECTED_CIRCUIT_VERSION`] or the registration
/// is rejected with [`RegistryError::CircuitVersionMismatch`]. The superseded
/// bare 224-byte frame is rejected at the dispatch in
/// [`HarpocratesRegistry::register_anonymous_verified`] before this parser runs,
/// so no proof can skip the version commitment.
fn parse_scoped_silent_witness_public_inputs(
    env: &Env,
    public_inputs: &Bytes,
) -> ScopedSilentWitnessInputs {
    let input_len = public_inputs.len();
    if input_len != SILENT_WITNESS_V2_ENVELOPED_INPUT_LEN {
        panic_with_error!(env, RegistryError::InvalidPublicInputs);
    }

    let mut bytes = [0u8; verifier_inputs::SILENT_WITNESS_V2_PUBLIC_INPUTS_LEN];
    public_inputs.copy_into_slice(&mut bytes);

    let mut trailer = [0u8; verifier_inputs::FIELD_LEN];
    trailer.copy_from_slice(&bytes[CIRCUIT_VERSION_TRAILER_OFFSET..]);
    if verifier_inputs::circuit_version_of(&trailer) != verifier_inputs::EXPECTED_CIRCUIT_VERSION {
        panic_with_error!(env, RegistryError::CircuitVersionMismatch);
    }

    // Reassemble video_hash: hi occupies bytes 16..32 of the first field word,
    // lo occupies bytes 48..64 of the second field word (UltraHonk packs 128-bit
    // values in the low half of a 256-bit field element).
    let mut video_hash = [0u8; 32];
    video_hash[..16].copy_from_slice(&bytes[16..32]);
    video_hash[16..].copy_from_slice(&bytes[48..64]);

    let mut credential_root = [0u8; 32];
    credential_root.copy_from_slice(&bytes[64..96]);

    let mut nullifier = [0u8; 32];
    nullifier.copy_from_slice(&bytes[96..128]);

    let mut verifier_scope = [0u8; 32];
    verifier_scope.copy_from_slice(&bytes[128..160]);

    let mut epoch_bytes = [0u8; 32];
    epoch_bytes.copy_from_slice(&bytes[160..192]);
    let epoch = bytes_to_u64_be(&epoch_bytes);

    let mut domain_tag = [0u8; 32];
    domain_tag.copy_from_slice(&bytes[192..224]);

    ScopedSilentWitnessInputs {
        video_hash: BytesN::from_array(env, &video_hash),
        credential_root: BytesN::from_array(env, &credential_root),
        nullifier: BytesN::from_array(env, &nullifier),
        verifier_scope: BytesN::from_array(env, &verifier_scope),
        epoch,
        domain_tag: BytesN::from_array(env, &domain_tag),
    }
}

/// Convert a 32-byte big-endian value to a u64.
/// Only the last 8 bytes are used; upper bytes must be zero for valid epochs.
fn bytes_to_u64_be(bytes: &[u8; 32]) -> u64 {
    // Check that upper bytes are zero (epoch must fit in u64)
    for b in &bytes[..24] {
        if *b != 0 {
            // Epoch value overflows u64 — treat as invalid (max)
            return u64::MAX;
        }
    }
    let mut val: u64 = 0;
    for b in &bytes[24..32] {
        val = (val << 8) | (*b as u64);
    }
    val
}

/// Get the raw scope epoch value for a scope field element.
fn get_scope_epoch_raw(env: &Env, scope: &BytesN<32>) -> u64 {
    env.storage()
        .persistent()
        .get(&DataKey::ScopeEpoch(scope.clone()))
        .unwrap_or(DEFAULT_SCOPE_EPOCH)
}

fn verify_external_proof(
    env: &Env,
    verifier: &Address,
    public_inputs: Bytes,
    proof: Bytes,
) -> bool {
    let mut args: SorobanVec<Val> = SorobanVec::new(env);
    args.push_back(public_inputs.into_val(env));
    args.push_back(proof.into_val(env));

    match env.try_invoke_contract::<(), InvokeError>(
        verifier,
        &Symbol::new(env, "verify_proof"),
        args,
    ) {
        Ok(Ok(_)) => true,
        _ => false,
    }
}

/// The active verifier's declared circuit-version window, defaulting to the
/// full built-in range so an undeclared window preserves pre-#343 behaviour.
fn get_verifier_circuit_versions_raw(env: &Env) -> (u32, u32) {
    match env
        .storage()
        .persistent()
        .get::<DataKey, VerifierCircuitVersions>(&DataKey::VerifierCircuitVersions)
    {
        Some(record) => (record.min_version, record.max_version),
        None => (MIN_SUPPORTED_CIRCUIT_VERSION, MAX_SUPPORTED_CIRCUIT_VERSION),
    }
}

/// Validate `circuit_version` against both authorities: this wasm build's own
/// framable range and the configured verifier's declared window.
///
/// Fails closed with the stable `UnsupportedCircuitVersion` code, and is always
/// called before the external verifier so an unsupported version never leaves
/// the contract.
fn require_supported_circuit_version(env: &Env, circuit_version: u32) {
    if circuit_version < MIN_SUPPORTED_CIRCUIT_VERSION
        || circuit_version > MAX_SUPPORTED_CIRCUIT_VERSION
    {
        panic_with_error!(env, RegistryError::UnsupportedCircuitVersion);
    }

    let (min_version, max_version) = get_verifier_circuit_versions_raw(env);
    if circuit_version < min_version || circuit_version > max_version {
        panic_with_error!(env, RegistryError::UnsupportedCircuitVersion);
    }
}

/// Enforce the active verifier's verdict, gated on the verifier's declared
/// circuit-version window (#343).
///
/// `circuit_version` is the version implied by the caller's frame layout (or,
/// for selective disclosure, carried in the frame). It is validated at the
/// trust boundary *before* the verifier is invoked, so an unsupported version
/// fails closed with the stable `UnsupportedCircuitVersion` code instead of
/// reaching a dependency that cannot answer it.
///
/// The verdict itself fails closed with the stable `InvalidProof` code when the
/// active verifier rejects the proof or the call itself fails (dependency
/// failure). Only the active verifier decides: once a rotation is activated the
/// replacement is enforced immediately, so a proof minted for the outgoing
/// circuit is not carried across the swap.
///
/// Every verified entry point funnels through here so the trust boundary
/// behaves identically.
fn require_verified_proof(
    env: &Env,
    active: &Address,
    circuit_version: u32,
    public_inputs: Bytes,
    proof: Bytes,
) {
    require_supported_circuit_version(env, circuit_version);

    if proof.is_empty() {
        panic_with_error!(env, RegistryError::InvalidProof);
    }

    if !verify_external_proof(env, active, public_inputs, proof) {
        panic_with_error!(env, RegistryError::InvalidProof);
    }
}

struct RevocationPublicInputs {
    revocation_root: BytesN<32>,
    nullifier: BytesN<32>,
    domain_separator: BytesN<32>,
    credential_root: BytesN<32>,
}

/// Parse the 128-byte public-input blob produced by the revocation_witness
/// Noir circuit.
///
/// Layout (4 x BN254 field elements, 32 bytes each):
///   [  0.. 32)  revocation_root
///   [ 32.. 64)  nullifier
///   [ 64.. 96)  domain_separator
///   [ 96..128)  credential_root
fn parse_revocation_public_inputs(env: &Env, public_inputs: &Bytes) -> RevocationPublicInputs {
    // Revocation frames are 4 × 32-byte fields (128 bytes), not the 160-byte
    // silent-witness length.
    if public_inputs.len() as usize != REVOCATION_PUBLIC_INPUTS_LEN {
        panic_with_error!(env, RegistryError::InvalidPublicInputs);
    }
    let mut frame = [0u8; REVOCATION_PUBLIC_INPUTS_LEN];
    public_inputs.copy_into_slice(&mut frame);

    let mut revocation_root = [0u8; 32];
    revocation_root.copy_from_slice(&frame[0..32]);

    let mut nullifier = [0u8; 32];
    nullifier.copy_from_slice(&frame[32..64]);

    let mut domain_separator = [0u8; 32];
    domain_separator.copy_from_slice(&frame[64..96]);

    let mut credential_root = [0u8; 32];
    credential_root.copy_from_slice(&frame[96..128]);

    RevocationPublicInputs {
        revocation_root: BytesN::from_array(env, &revocation_root),
        nullifier: BytesN::from_array(env, &nullifier),
        domain_separator: BytesN::from_array(env, &domain_separator),
        credential_root: BytesN::from_array(env, &credential_root),
    }
}

/// Parsed element of an aggregated batch proof.
///
/// NOTE: `BytesN` does not implement `Copy`, so the parsing function below
/// initializes the element array with `core::array::from_fn` instead of
/// `[value; N]` repetition.
#[derive(Clone)]
struct AggregatedBatchElement {
    video_hash: BytesN<32>,
    credential_root: BytesN<32>,
    nullifier: BytesN<32>,
}

/// Parsed aggregated batch public inputs.
struct AggregatedPublicInputs {
    domain_separator: BytesN<32>,
    elements: [AggregatedBatchElement; MAX_AGGREGATION_SIZE as usize],
}

/// Parse aggregated batch public inputs.
///
/// Avoids large stack allocations by parsing elements directly from the
/// `Bytes` reference element-by-element, using a small 128-byte temp buffer.
///
/// Layout:
///   [   0..  32)  domain_separator      – 32 bytes
///   [  32.. 160)  element_0             – 128 bytes (4 × 32 byte fields)
///   [ 160.. 288)  element_1
///   ...
///   [ 928..1056)  element_7
///
/// Each element is 128 bytes with the same layout as `single_witness`:
///   [  0.. 32)  video_hash_hi     → reconstructed into video_hash (hi 16 bytes → [0..16], lo 16 bytes → [16..32])
///   [ 32.. 64)  video_hash_lo
///   [ 64.. 96)  credential_root
///   [ 96..128)  nullifier
fn parse_aggregated_public_inputs(
    env: &Env,
    public_inputs: &Bytes,
    batch_size: u32,
) -> AggregatedPublicInputs {
    let expected_len = 32 + (batch_size * 128);
    if public_inputs.len() != expected_len {
        panic_with_error!(env, RegistryError::InvalidPublicInputs);
    }

    // Parse domain separator from the first 32 bytes (small stack buffer).
    // NOTE: We must slice first because Bytes.copy_into_slice expects the
    // destination to match the full Bytes length.
    let domain_slice = public_inputs.slice(0..32);
    let mut domain_bytes = [0u8; 32];
    domain_slice.copy_into_slice(&mut domain_bytes);
    let domain_separator = BytesN::from_array(env, &domain_bytes);

    // Initialize default elements.  `BytesN` is not `Copy`, so build each
    // slot with `core::array::from_fn` instead of `[value; N]` repetition.
    let mut elements = core::array::from_fn(|_| AggregatedBatchElement {
        video_hash: BytesN::from_array(env, &[0u8; 32]),
        credential_root: BytesN::from_array(env, &[0u8; 32]),
        nullifier: BytesN::from_array(env, &[0u8; 32]),
    });

    // Parse each batch element using a small 128-byte temp buffer.
    // We slice the Bytes at the element offset to avoid allocating a full
    // buffer for the entire public input blob.
    let mut element_bytes = [0u8; 128];
    for i in 0..batch_size {
        let element_start = 32 + (i * 128);
        let element_slice = public_inputs.slice(element_start..element_start + 128);
        element_slice.copy_into_slice(&mut element_bytes);

        // Reconstruct video hash from the two limbs (same as silent witness parsing).
        let mut video_hash = [0u8; 32];
        video_hash[..16].copy_from_slice(&element_bytes[16..32]);
        video_hash[16..].copy_from_slice(&element_bytes[48..64]);

        let mut credential_root = [0u8; 32];
        credential_root.copy_from_slice(&element_bytes[64..96]);

        let mut nullifier = [0u8; 32];
        nullifier.copy_from_slice(&element_bytes[96..128]);

        elements[i as usize] = AggregatedBatchElement {
            video_hash: BytesN::from_array(env, &video_hash),
            credential_root: BytesN::from_array(env, &credential_root),
            nullifier: BytesN::from_array(env, &nullifier),
        };
    }

    AggregatedPublicInputs {
        domain_separator,
        elements,
    }
}

fn verify_demo_zk_boundary(proof: &Bytes, credential_root: &BytesN<32>) -> bool {
    !proof.is_empty() && credential_root.len() == 32
}

// ---------------------------------------------------------------------------
// Dispute helper functions
// ---------------------------------------------------------------------------

/// Retrieve a dispute record, panicking with `DisputeNotFound` if absent.
fn get_dispute_record(env: &Env, dispute_id: &BytesN<32>) -> DisputeRecord {
    env.storage()
        .persistent()
        .get(&DataKey::Dispute(dispute_id.clone()))
        .unwrap_or_else(|| panic_with_error!(env, RegistryError::DisputeNotFound))
}

/// Decrement the open-dispute counter for a proof.  Saturates at 0 to avoid
/// underflow on double-close (which should never happen under correct logic
/// but is defended against for safety).
fn decrement_open_dispute_count(env: &Env, proof_id: &BytesN<32>) {
    let key = DataKey::ProofOpenDisputeCount(proof_id.clone());
    let count: u32 = env.storage().persistent().get(&key).unwrap_or(0u32);
    let new_count = count.saturating_sub(1);
    if new_count == 0 {
        env.storage().persistent().remove(&key);
    } else {
        env.storage().persistent().set(&key, &new_count);
        env.storage()
            .persistent()
            .extend_ttl(&key, BUMP_THRESHOLD_LEDGERS, BUMP_TARGET_LEDGERS);
    }
}

/// Decrement the per-reporter open-dispute counter. Saturates at 0 and
/// removes the key when it reaches zero so idle reporters hold no storage.
fn decrement_reporter_open_dispute_count(env: &Env, reporter: &Address) {
    let key = DataKey::ReporterOpenDisputeCount(reporter.clone());
    let count: u32 = env.storage().persistent().get(&key).unwrap_or(0u32);
    let new_count = count.saturating_sub(1);
    if new_count == 0 {
        env.storage().persistent().remove(&key);
    } else {
        env.storage().persistent().set(&key, &new_count);
        env.storage()
            .persistent()
            .extend_ttl(&key, BUMP_THRESHOLD_LEDGERS, BUMP_TARGET_LEDGERS);
    }
}

/// Depth-1 cycle guard for supersession.
///
/// Returns `true` if allowing `superseding_proof_id` to supersede
/// `disputed_proof_id` would create a cycle. Two conditions are rejected:
///
/// 1. **Duplicate edge** - an arrow `disputed_proof_id -> superseding_proof_id`
///    already exists, so re-recording it is a no-op that could mask corruption.
/// 2. **Reverse edge (2-cycle)** - an arrow `superseding_proof_id ->
///    disputed_proof_id` already exists, so the proposed edge would close a
///    length-2 cycle.
///
/// The reverse index maps a superseding proof to the proof it corrected:
///   DataKey::Dispute(SHA-256("harp_sup_rev" ‖ superseding_proof_id)) -> disputed_proof_id
fn check_supersession_cycle(
    env: &Env,
    disputed_proof_id: &BytesN<32>,
    superseding_proof_id: &BytesN<32>,
) -> bool {
    // 1. Duplicate edge: reverse[superseding] == disputed.
    let forward_rev = supersession_reverse_key(env, superseding_proof_id);
    if let Some(recorded_original) = env
        .storage()
        .persistent()
        .get::<DataKey, BytesN<32>>(&DataKey::Dispute(forward_rev))
    {
        if recorded_original == *disputed_proof_id {
            return true;
        }
    }

    // 2. Reverse edge: reverse[disputed] == superseding.
    let reverse_rev = supersession_reverse_key(env, disputed_proof_id);
    if let Some(recorded_superseder) = env
        .storage()
        .persistent()
        .get::<DataKey, BytesN<32>>(&DataKey::Dispute(reverse_rev))
    {
        if recorded_superseder == *superseding_proof_id {
            return true;
        }
    }

    false
}

/// Record the supersession direction in the reverse index.
/// Called from `supersede_dispute` after all guards pass.
fn record_supersession_direction(
    env: &Env,
    disputed_proof_id: &BytesN<32>,
    superseding_proof_id: &BytesN<32>,
) {
    let rev_key_hash = supersession_reverse_key(env, superseding_proof_id);
    env.storage()
        .persistent()
        .set(&DataKey::Dispute(rev_key_hash), disputed_proof_id);
}

/// Compute the reverse-index key for a supersession:
///   SHA-256("harp_sup_rev" ‖ superseding_proof_id_bytes)
///
/// "harp_sup_rev" is a 12-byte domain prefix that avoids key collisions with
/// legitimate dispute_id keys.  The 12-byte prefix + 32-byte suffix = 44
/// bytes of pre-image, hashed to a 32-byte key.
fn supersession_reverse_key(env: &Env, superseding_proof_id: &BytesN<32>) -> BytesN<32> {
    // domain prefix: ASCII "harp_sup_rev" = 12 bytes
    const PREFIX: [u8; 12] = *b"harp_sup_rev";

    // Build a 44-byte pre-image: [PREFIX (12)] ‖ [superseding_proof_id (32)]
    let mut pre_image = [0u8; 44];
    pre_image[..12].copy_from_slice(&PREFIX);
    let mut proof_id_bytes = [0u8; 32];
    superseding_proof_id.copy_into_slice(&mut proof_id_bytes);
    pre_image[12..].copy_from_slice(&proof_id_bytes);

    let pre_image_bytes = Bytes::from_array(env, &pre_image);
    env.crypto().sha256(&pre_image_bytes).into()
}

// ---------------------------------------------------------------------------
// Timelock proposal helpers (#86)
// ---------------------------------------------------------------------------

fn get_timelock_min_delay(env: &Env) -> u64 {
    env.storage()
        .persistent()
        .get(&DataKey::TimelockMinDelay)
        .unwrap_or(DEFAULT_TIMELOCK_MIN_DELAY_SECS)
}

fn get_timelock_proposal_or_panic(env: &Env, proposal_id: u32) -> TimelockProposal {
    env.storage()
        .persistent()
        .get(&DataKey::Proposal(proposal_id))
        .unwrap_or_else(|| panic_with_error!(env, RegistryError::ProposalNotFound))
}

fn next_proposal_id(env: &Env) -> u32 {
    let current: u32 = env
        .storage()
        .persistent()
        .get(&DataKey::ProposalSeq)
        .unwrap_or(0u32);
    let next = current.saturating_add(1);
    env.storage().persistent().set(&DataKey::ProposalSeq, &next);
    next
}

fn count_pending_proposals(env: &Env) -> u32 {
    let count: u32 = env
        .storage()
        .persistent()
        .get(&DataKey::ProposalSeq)
        .unwrap_or(0u32);
    if count == 0 {
        return 0;
    }
    let mut pending = 0u32;
    for pid in 1..=count {
        if let Some(proposal) = env
            .storage()
            .persistent()
            .get::<DataKey, TimelockProposal>(&DataKey::Proposal(pid))
        {
            if !proposal.executed && !proposal.cancelled {
                pending += 1;
            }
        }
    }
    pending
}

fn dispatch_timelocked_action(env: &Env, proposal: &TimelockProposal) {
    match proposal.action {
        1 => {
            env.storage()
                .persistent()
                .set(&DataKey::Verifier, &proposal.target);
            env.storage().persistent().remove(&DataKey::VerifierState);
            VerifierSet {
                verifier: proposal.target.clone(),
            }
            .publish(env);
        }
        2 => {
            let mut record = get_issuer_record(env, &proposal.target);
            record.active = false;
            env.storage()
                .persistent()
                .set(&DataKey::Issuer(proposal.target.clone()), &record);
            // A timelocked revocation clears any rotation grace record too: the
            // two retirements must never contradict each other (#323).
            env.storage()
                .persistent()
                .remove(&DataKey::IssuerRotation(proposal.target.clone()));
            IssuerRevoked {
                issuer: proposal.target.clone(),
            }
            .publish(env);
        }
        3 => {
            // `payload` is 32 bytes; the TTL is stored big-endian in the
            // first 8 bytes (see `ttl_payload` in test_timelock.rs).
            let mut payload_bytes = [0u8; 32];
            proposal.payload.copy_into_slice(&mut payload_bytes);
            let mut ttl_bytes = [0u8; 8];
            ttl_bytes.copy_from_slice(&payload_bytes[..8]);
            let ttl_secs = u64::from_be_bytes(ttl_bytes);
            env.storage()
                .persistent()
                .set(&DataKey::ProofTtl, &ttl_secs);
        }
        4 => {
            let mut record = get_credential_root_record(env, &proposal.payload);
            record.status = STATUS_REVOKED;
            env.storage()
                .persistent()
                .set(&DataKey::CredentialRootV2(proposal.payload.clone()), &record);
            CredentialRootRevoked {
                credential_root: proposal.payload.clone(),
            }
            .publish(env);
        }
        5 => {
            let mut record = get_credential_root_record(env, &proposal.payload);
            record.status = STATUS_EXPIRED;
            record.expires_at = env.ledger().timestamp();
            env.storage()
                .persistent()
                .set(&DataKey::CredentialRootV2(proposal.payload.clone()), &record);
            CredentialRootExpired {
                credential_root: proposal.payload.clone(),
                expired_at: record.expires_at,
            }
            .publish(env);
        }
        6 => {
            let old_wasm_hash = env
                .storage()
                .persistent()
                .get(&DataKey::WasmHash)
                .unwrap_or_else(|| BytesN::from_array(env, &[0u8; 32]));
            let new_wasm_hash = proposal.payload.clone();
            env.deployer()
                .update_current_contract_wasm(new_wasm_hash.clone());
            env.storage()
                .persistent()
                .set(&DataKey::WasmHash, &new_wasm_hash);
            ContractUpgraded {
                old_wasm_hash,
                new_wasm_hash,
            }
            .publish(env);
        }
        _ => panic_with_error!(env, RegistryError::InvalidProposalAction),
    }
}

// ---------------------------------------------------------------------------
// Selective disclosure helpers
// ---------------------------------------------------------------------------

/// Current version of the selective disclosure circuit.
const CURRENT_SELECTIVE_DISCLOSURE_VERSION: u32 = 1;

fn get_schema_record(env: &Env, schema_hash: &BytesN<32>) -> SchemaRecord {
    env.storage()
        .persistent()
        .get(&DataKey::Schema(schema_hash.clone()))
        .unwrap_or_else(|| panic_with_error!(env, RegistryError::UnknownSchema))
}

struct SelectiveDisclosureInputs {
    schema_hash: BytesN<32>,
    issuer_namespace: BytesN<32>,
    schema_version: u32,
    credential_root: BytesN<32>,
    nullifier: BytesN<32>,
    video_hash_hi: BytesN<32>,
    video_hash_lo: BytesN<32>,
    verifier_digest: BytesN<32>,
    circuit_version: u32,
    evidence_digest: BytesN<32>,
    predicate_commitment: BytesN<32>,
}

fn parse_selective_disclosure_inputs(
    env: &Env,
    public_inputs: &Bytes,
) -> SelectiveDisclosureInputs {
    if public_inputs.len() != 352 {
        panic_with_error!(env, RegistryError::InvalidPublicInputs);
    }

    let mut bytes = [0u8; 352];
    public_inputs.copy_into_slice(&mut bytes);

    let schema_hash = BytesN::from_array(env, &read_32(&bytes[0..32]));
    let issuer_namespace = BytesN::from_array(env, &read_32(&bytes[32..64]));
    let schema_version = u32_from_be_bytes(&read_32(&bytes[64..96]));
    let credential_root = BytesN::from_array(env, &read_32(&bytes[96..128]));
    let nullifier = BytesN::from_array(env, &read_32(&bytes[128..160]));
    let video_hash_hi = BytesN::from_array(env, &read_32(&bytes[160..192]));
    let video_hash_lo = BytesN::from_array(env, &read_32(&bytes[192..224]));
    let verifier_digest = BytesN::from_array(env, &read_32(&bytes[224..256]));
    let circuit_version = u32_from_be_bytes(&read_32(&bytes[256..288]));
    let evidence_digest = BytesN::from_array(env, &read_32(&bytes[288..320]));
    let predicate_commitment = BytesN::from_array(env, &read_32(&bytes[320..352]));

    SelectiveDisclosureInputs {
        schema_hash,
        issuer_namespace,
        schema_version,
        credential_root,
        nullifier,
        video_hash_hi,
        video_hash_lo,
        verifier_digest,
        circuit_version,
        evidence_digest,
        predicate_commitment,
    }
}

fn array_from_slice<const N: usize>(slice: &[u8]) -> [u8; N] {
    let mut arr = [0u8; N];
    arr.copy_from_slice(slice);
    arr
}

fn read_32(slice: &[u8]) -> [u8; 32] {
    array_from_slice(slice)
}

fn u32_from_be_bytes(bytes: &[u8; 32]) -> u32 {
    u32::from_be_bytes([bytes[28], bytes[29], bytes[30], bytes[31]])
}

/// Test-only helpers for reading contract events.
///
/// `env.events().all()` only reflects the most recent invocation, so callers
/// must capture events immediately after the call under test.
#[cfg(test)]
pub(crate) mod event_test_utils {
    use crate::Env;
    use soroban_sdk::testutils::Events as _;
    use soroban_sdk::xdr::{ContractEventBody, ScVal};
    use std::format;
    use std::string::String;
    use std::vec::Vec;

    /// Symbolic topics of one XDR contract event, in order. Non-symbol topics
    /// are skipped.
    pub fn symbol_topics(event: &soroban_sdk::xdr::ContractEvent) -> Vec<String> {
        let mut out = Vec::new();
        let ContractEventBody::V0(v0) = &event.body;
        {
            for topic in v0.topics.iter() {
                if let ScVal::Symbol(s) = topic {
                    out.push(format!("{}", s.0));
                }
            }
        }
        out
    }

    /// Number of events from the most recent invocation whose leading symbol
    /// topics equal `prefix`.
    pub fn count_events(env: &Env, prefix: &[&str]) -> u32 {
        let mut count = 0u32;
        for event in env.events().all().events() {
            let topics = symbol_topics(event);
            if topics.len() >= prefix.len()
                && topics
                    .iter()
                    .zip(prefix.iter())
                    .all(|(t, p)| t.as_str() == *p)
            {
                count = count.saturating_add(1);
            }
        }
        count
    }

    /// True when the most recent invocation emitted at least one event whose
    /// leading symbol topics equal `prefix`.
    pub fn has_event(env: &Env, prefix: &[&str]) -> bool {
        count_events(env, prefix) > 0
    }
}

#[cfg(test)]
mod test;
#[cfg(test)]
mod test_aggregation;
#[cfg(test)]
mod test_auth;
#[cfg(test)]
mod test_budget;
#[cfg(test)]
mod test_conformance;
#[cfg(test)]
mod test_delegation;
#[cfg(test)]
mod test_deployment_fixture;
#[cfg(test)]
mod test_dispute;
#[cfg(test)]
mod test_error_abi;
#[cfg(test)]
mod test_expiry;
#[cfg(test)]
mod test_fuzz;
#[cfg(test)]
mod test_identity_tier_properties;
#[cfg(test)]
mod test_invariants;
#[cfg(test)]
mod test_issuer_rotation;
#[cfg(test)]
mod test_lifecycle;
#[cfg(test)]
mod test_lineage;
#[cfg(test)]
mod test_metadata_envelope;
#[cfg(test)]
mod test_pause;
#[cfg(test)]
mod test_receipt;
#[cfg(test)]
mod test_registration_replay;
#[cfg(test)]
mod test_revocation;
#[cfg(test)]
mod test_roles;
#[cfg(test)]
mod test_schema;
#[cfg(test)]
mod test_scoped_nullifier;
#[cfg(test)]
mod test_selective_disclosure;
#[cfg(test)]
mod test_state_machine;
#[cfg(test)]
pub mod test_timelock;
#[cfg(test)]
mod test_threshold_seal;
#[cfg(test)]
mod test_timestamp_claim;
#[cfg(test)]
mod test_upgrade_compat;
#[cfg(test)]
mod test_verifier_versions;
#[cfg(test)]
mod test_ttl;
#[cfg(test)]
mod test_list_credential_roots;

