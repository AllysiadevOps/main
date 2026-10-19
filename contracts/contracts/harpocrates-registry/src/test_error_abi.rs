//! Stable contract error ABI (`hpx-err/1`) lock test - issue #344.
//!
//! `contracts/ERROR_ABI.md` is the published ABI. This suite reads it at compile
//! time and fails if it drifts from `RegistryError`: a renamed, renumbered, dropped,
//! or duplicated variant, a class outside the documented set, or an unpublishable
//! retry hint all fail here rather than reaching a deployed caller.
//!
//! `canonical_name` below matches exhaustively on purpose: adding a
//! `RegistryError` variant without publishing its name is a compile error, so an
//! undocumented error cannot ship.
//!
//! Failure messages in this suite print codes, names, and classes only. They never
//! print proof bytes, public inputs, witnesses, nullifiers, media, credentials,
//! signatures, or private keys.

#[cfg(test)]
use super::*;
#[cfg(test)]
use std::string::{String, ToString};
#[cfg(test)]
use std::vec::Vec;

#[cfg(test)]
/// Published ABI document (single source of truth for names and classes).
const ABI_DOC: &str = include_str!("../../../../contracts/ERROR_ABI.md");

#[cfg(test)]
/// ABI version this suite pins. Bumping it is a deliberate, reviewed change to both
/// the document and the enum.
const ABI_VERSION: u32 = 1;

#[cfg(test)]
/// Every class the ABI may publish.
const CLASSES: &[&str] = &[
    "malformed",
    "oversized",
    "expired",
    "revoked",
    "unsupported",
    "dependency",
    "auth",
    "conflict",
    "resource",
    "state",
];

#[cfg(test)]
/// The six failure classes named explicitly in the issue scope; at least one code
/// must be published for each.
const REQUIRED_CLASSES: &[&str] = &[
    "malformed",
    "oversized",
    "expired",
    "revoked",
    "unsupported",
    "dependency",
];

#[cfg(test)]
/// Canonical name of every variant, in the same spelling the ABI publishes.
fn canonical_name(err: RegistryError) -> &'static str {
    match err {
        RegistryError::AlreadyInitialized => "AlreadyInitialized",
        RegistryError::NotInitialized => "NotInitialized",
        RegistryError::Unauthorized => "Unauthorized",
        RegistryError::DuplicateProof => "DuplicateProof",
        RegistryError::DuplicateVideo => "DuplicateVideo",
        RegistryError::DuplicateNullifier => "DuplicateNullifier",
        RegistryError::InvalidProof => "InvalidProof",
        RegistryError::UnknownIssuer => "UnknownIssuer",
        RegistryError::VerifierNotSet => "VerifierNotSet",
        RegistryError::InvalidPublicInputs => "InvalidPublicInputs",
        RegistryError::UnknownCredentialRoot => "UnknownCredentialRoot",
        RegistryError::RevokedCredentialRoot => "RevokedCredentialRoot",
        RegistryError::HistorySaturated => "HistorySaturated",
        RegistryError::InvalidHistoryAction => "InvalidHistoryAction",
        RegistryError::InvalidReasonCode => "InvalidReasonCode",
        RegistryError::HistoryLimitExceeded => "HistoryLimitExceeded",
        RegistryError::AlreadyExpired => "AlreadyExpired",
        RegistryError::NoCorrectionChange => "NoCorrectionChange",
        RegistryError::HistoryCorruption => "HistoryCorruption",
        RegistryError::NoPendingAdmin => "NoPendingAdmin",
        RegistryError::Paused => "Paused",
        RegistryError::InvalidPauseDomain => "InvalidPauseDomain",
        RegistryError::InvalidPauseDuration => "InvalidPauseDuration",
        RegistryError::InvalidDelegationScope => "InvalidDelegationScope",
        RegistryError::InvalidDelegationDuration => "InvalidDelegationDuration",
        RegistryError::DelegationNotFound => "DelegationNotFound",
        RegistryError::DelegationExpired => "DelegationExpired",
        RegistryError::DelegationScopeExceeded => "DelegationScopeExceeded",
        RegistryError::DelegationsSaturated => "DelegationsSaturated",
        RegistryError::SelfDelegation => "SelfDelegation",
        RegistryError::ProposalNotFound => "ProposalNotFound",
        RegistryError::ProposalNotReady => "ProposalNotReady",
        RegistryError::ProposalAlreadyExecuted => "ProposalAlreadyExecuted",
        RegistryError::ProposalCancelled => "ProposalCancelled",
        RegistryError::InvalidProposalAction => "InvalidProposalAction",
        RegistryError::InvalidProposalPayload => "InvalidProposalPayload",
        RegistryError::ProposalsSaturated => "ProposalsSaturated",
        RegistryError::InvalidTimelockDelay => "InvalidTimelockDelay",
        RegistryError::AlreadyCancelled => "AlreadyCancelled",
        RegistryError::RotationNotScheduled => "RotationNotScheduled",
        RegistryError::RotationNotReady => "RotationNotReady",
        RegistryError::RotationWindowClosed => "RotationWindowClosed",
        RegistryError::BatchTooLarge => "BatchTooLarge",
        RegistryError::InvalidScopeEpoch => "InvalidScopeEpoch",
        RegistryError::DisputeNotFound => "DisputeNotFound",
        RegistryError::DisputeAlreadyResolved => "DisputeAlreadyResolved",
        RegistryError::SupersessionCycleDetected => "SupersessionCycleDetected",
        RegistryError::SupersessionNotFound => "SupersessionNotFound",
        RegistryError::DomainTagMismatch => "DomainTagMismatch",
        RegistryError::UnknownSchema => "UnknownSchema",
        RegistryError::InactiveSchema => "InactiveSchema",
        RegistryError::SchemaVersionMismatch => "SchemaVersionMismatch",
        RegistryError::StaleEpoch => "StaleEpoch",
        RegistryError::BatchSizeExceeded => "BatchSizeExceeded",
        RegistryError::BatchCredentialRootMismatch => "BatchCredentialRootMismatch",
        RegistryError::BatchCountMismatch => "BatchCountMismatch",
        RegistryError::InvalidLineage => "InvalidLineage",
        RegistryError::LineageCycle => "LineageCycle",
        RegistryError::LineageTooDeep => "LineageTooDeep",
        RegistryError::LineageFanOutExceeded => "LineageFanOutExceeded",
        RegistryError::TooManyOpenDisputes => "TooManyOpenDisputes",
        RegistryError::DisputeWindowExpired => "DisputeWindowExpired",
        RegistryError::DisputeAlreadyClosed => "DisputeAlreadyClosed",
        RegistryError::DisputeCyclicSupersession => "DisputeCyclicSupersession",
        RegistryError::UnauthorizedResponder => "UnauthorizedResponder",
        RegistryError::ReporterOnCooldown => "ReporterOnCooldown",
        RegistryError::InvalidDisputeTransition => "InvalidDisputeTransition",
        RegistryError::UnsupportedMetadataEnvelopeVersion => "UnsupportedMetadataEnvelopeVersion",
        RegistryError::InvalidMetadataEnvelope => "InvalidMetadataEnvelope",
        RegistryError::MetadataEnvelopeNotFound => "MetadataEnvelopeNotFound",
        RegistryError::MetadataEnvelopeHashMismatch => "MetadataEnvelopeHashMismatch",
        RegistryError::InvalidTimestampClaim => "InvalidTimestampClaim",
        RegistryError::TimestampClaimNotFound => "TimestampClaimNotFound",
        RegistryError::TimestampClaimAlreadyAnchored => "TimestampClaimAlreadyAnchored",
        RegistryError::UnauthorizedTimestampActor => "UnauthorizedTimestampActor",
        RegistryError::LineageEmptyParents => "LineageEmptyParents",
        RegistryError::LineageParentUnavailable => "LineageParentUnavailable",
        RegistryError::DuplicateLineage => "DuplicateLineage",
        RegistryError::LineageChildrenLimitExceeded => "LineageChildrenLimitExceeded",
        RegistryError::LineageChildrenSaturated => "LineageChildrenSaturated",
        RegistryError::UnsupportedCircuitVersion => "UnsupportedCircuitVersion",
        RegistryError::InvalidCircuitVersionRange => "InvalidCircuitVersionRange",
        RegistryError::InvalidIssuerRotationGrace => "InvalidIssuerRotationGrace",
        RegistryError::InvalidIssuerRotation => "InvalidIssuerRotation",
        RegistryError::IssuerRotationNotFound => "IssuerRotationNotFound",
        RegistryError::IssuerRotationGraceStillActive => "IssuerRotationGraceStillActive",
        RegistryError::CircuitVersionMismatch => "CircuitVersionMismatch",
        RegistryError::ReporterDisputesSaturated => "ReporterDisputesSaturated",
    }
}

#[cfg(test)]
/// Every variant, ascending by code. Keep in sync with `RegistryError`; the
/// exhaustive `canonical_name` match above makes a missing variant a compile error.
const ALL_VARIANTS: &[RegistryError] = &[
    RegistryError::AlreadyInitialized,
    RegistryError::NotInitialized,
    RegistryError::Unauthorized,
    RegistryError::DuplicateProof,
    RegistryError::DuplicateVideo,
    RegistryError::DuplicateNullifier,
    RegistryError::InvalidProof,
    RegistryError::UnknownIssuer,
    RegistryError::VerifierNotSet,
    RegistryError::InvalidPublicInputs,
    RegistryError::UnknownCredentialRoot,
    RegistryError::RevokedCredentialRoot,
    RegistryError::HistorySaturated,
    RegistryError::InvalidHistoryAction,
    RegistryError::InvalidReasonCode,
    RegistryError::HistoryLimitExceeded,
    RegistryError::AlreadyExpired,
    RegistryError::NoCorrectionChange,
    RegistryError::HistoryCorruption,
    RegistryError::NoPendingAdmin,
    RegistryError::Paused,
    RegistryError::InvalidPauseDomain,
    RegistryError::InvalidPauseDuration,
    RegistryError::InvalidDelegationScope,
    RegistryError::InvalidDelegationDuration,
    RegistryError::DelegationNotFound,
    RegistryError::DelegationExpired,
    RegistryError::DelegationScopeExceeded,
    RegistryError::DelegationsSaturated,
    RegistryError::SelfDelegation,
    RegistryError::ProposalNotFound,
    RegistryError::ProposalNotReady,
    RegistryError::ProposalAlreadyExecuted,
    RegistryError::ProposalCancelled,
    RegistryError::InvalidProposalAction,
    RegistryError::InvalidProposalPayload,
    RegistryError::ProposalsSaturated,
    RegistryError::InvalidTimelockDelay,
    RegistryError::AlreadyCancelled,
    RegistryError::RotationNotScheduled,
    RegistryError::RotationNotReady,
    RegistryError::RotationWindowClosed,
    RegistryError::BatchTooLarge,
    RegistryError::InvalidScopeEpoch,
    RegistryError::DisputeNotFound,
    RegistryError::DisputeAlreadyResolved,
    RegistryError::SupersessionCycleDetected,
    RegistryError::SupersessionNotFound,
    RegistryError::DomainTagMismatch,
    RegistryError::UnknownSchema,
    RegistryError::InactiveSchema,
    RegistryError::SchemaVersionMismatch,
    RegistryError::StaleEpoch,
    RegistryError::BatchSizeExceeded,
    RegistryError::BatchCredentialRootMismatch,
    RegistryError::BatchCountMismatch,
    RegistryError::InvalidLineage,
    RegistryError::LineageCycle,
    RegistryError::LineageTooDeep,
    RegistryError::LineageFanOutExceeded,
    RegistryError::TooManyOpenDisputes,
    RegistryError::DisputeWindowExpired,
    RegistryError::DisputeAlreadyClosed,
    RegistryError::DisputeCyclicSupersession,
    RegistryError::UnauthorizedResponder,
    RegistryError::ReporterOnCooldown,
    RegistryError::InvalidDisputeTransition,
    RegistryError::UnsupportedMetadataEnvelopeVersion,
    RegistryError::InvalidMetadataEnvelope,
    RegistryError::MetadataEnvelopeNotFound,
    RegistryError::MetadataEnvelopeHashMismatch,
    RegistryError::InvalidTimestampClaim,
    RegistryError::TimestampClaimNotFound,
    RegistryError::TimestampClaimAlreadyAnchored,
    RegistryError::UnauthorizedTimestampActor,
    RegistryError::LineageEmptyParents,
    RegistryError::LineageParentUnavailable,
    RegistryError::DuplicateLineage,
    RegistryError::LineageChildrenLimitExceeded,
    RegistryError::LineageChildrenSaturated,
    RegistryError::UnsupportedCircuitVersion,
    RegistryError::InvalidCircuitVersionRange,
    RegistryError::InvalidIssuerRotationGrace,
    RegistryError::InvalidIssuerRotation,
    RegistryError::IssuerRotationNotFound,
    RegistryError::IssuerRotationGraceStillActive,
    RegistryError::CircuitVersionMismatch,
    RegistryError::ReporterDisputesSaturated,
];

#[cfg(test)]
#[derive(Debug)]
struct AbiRow {
    code: u32,
    name: String,
    class: String,
    retryable: String,
    meaning: String,
}

#[cfg(test)]
/// Parse the `| Code | Variant | Class | Retryable | Meaning |` rows of the
/// published document. Non-numeric rows (headers and the class table) are skipped.
fn published_rows() -> Vec<AbiRow> {
    let mut rows = Vec::new();
    for line in ABI_DOC.lines() {
        let cells: Vec<&str> = line.split('|').map(|cell| cell.trim()).collect();
        if cells.len() != 7 {
            continue;
        }
        let Ok(code) = cells[1].parse::<u32>() else {
            continue;
        };
        rows.push(AbiRow {
            code,
            name: cells[2].trim_matches('`').to_string(),
            class: cells[3].to_string(),
            retryable: cells[4].to_string(),
            meaning: cells[5].to_string(),
        });
    }
    rows
}

#[cfg(test)]
#[test]
fn abi_version_is_published() {
    assert_eq!(
        ABI_VERSION, 1,
        "ABI version bumped without updating this suite"
    );
    assert!(
        ABI_DOC.contains("ABI version: 1"),
        "ERROR_ABI.md must publish the ABI version"
    );
}

#[cfg(test)]
#[test]
fn every_variant_is_published_exactly_once() {
    let rows = published_rows();
    assert_eq!(
        rows.len(),
        ALL_VARIANTS.len(),
        "published rows and RegistryError variants disagree"
    );
    for (index, variant) in ALL_VARIANTS.iter().enumerate() {
        let row = &rows[index];
        let code = *variant as u32;
        assert_eq!(
            row.code,
            code,
            "code {} drifted from RegistryError::{}",
            row.code,
            canonical_name(*variant)
        );
        assert_eq!(
            row.name,
            canonical_name(*variant),
            "name for code {} drifted from the enum",
            code
        );
    }
}

#[cfg(test)]
#[test]
fn codes_are_contiguous_and_ascending_from_one() {
    for (index, row) in published_rows().iter().enumerate() {
        assert_eq!(
            row.code,
            index as u32 + 1,
            "codes must be contiguous and never renumbered"
        );
    }
}

#[cfg(test)]
#[test]
fn classes_and_retry_hints_are_bounded() {
    for row in published_rows() {
        assert!(
            CLASSES.contains(&row.class.as_str()),
            "code {} publishes undocumented class {}",
            row.code,
            row.class
        );
        assert!(
            row.retryable == "yes" || row.retryable == "no",
            "code {} has an invalid retry hint",
            row.code
        );
        assert!(
            !row.meaning.is_empty() && !row.meaning.contains("TODO"),
            "code {} has no published meaning",
            row.code
        );
    }
}

#[cfg(test)]
#[test]
fn every_scope_failure_class_is_covered() {
    let rows = published_rows();
    for class in REQUIRED_CLASSES {
        assert!(
            rows.iter().any(|row| row.class == *class),
            "no published error covers the {} failure class",
            class
        );
    }
}

#[cfg(test)]
#[test]
fn retryable_codes_require_external_condition_only() {
    // The published retry hints are the only ones callers may auto-retry on, so the
    // set is pinned here explicitly. Extending it is an ABI review decision.
    let mut retryable: Vec<u32> = Vec::new();
    for row in published_rows() {
        if row.retryable == "yes" {
            retryable.push(row.code);
        }
    }
    let expected: &[u32] = &[21, 32, 41, 66, 86];
    assert_eq!(
        retryable.as_slice(),
        expected,
        "retryable set changed without updating this test"
    );
}

#[cfg(test)]
#[test]
fn published_rows_carry_no_input_material() {
    // A failure response is (code, name, class, retryable). A published row must
    // never embed reusable evidence such as a hex blob or a PEM header.
    for row in published_rows() {
        for token in ["0x", "BEGIN", "base64"] {
            assert!(
                !row.meaning.contains(token),
                "code {} publishes input material: {}",
                row.code,
                token
            );
        }
    }
    assert!(
        !ABI_DOC.contains("-----BEGIN"),
        "ABI must not embed key material"
    );
}
