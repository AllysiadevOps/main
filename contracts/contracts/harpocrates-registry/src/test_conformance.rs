//! Cross-layer verifier conformance (`hpx-vi/1`).
//!
//! Drives the shared corpus in `zk/vectors/verifier_conformance_v1.json`
//! through **both** contract-side boundaries:
//!
//! 1. the pure [`verifier_inputs`] codec, and
//! 2. the real on-chain `classify_public_inputs` entry point, invoked through
//!    the generated contract client.
//!
//! The Python (`backend/test_conformance_vectors.py`) and TypeScript
//! (`frontend/src/verifierInputs.conformance.test.ts`) runners drive the same
//! file. A divergence in any layer fails exactly one of the three suites and
//! names the offending case id, so mismatch diagnosis does not require
//! re-deriving which layer is wrong.
//!
//! The companion malformed-hex corpus
//! (`zk/vectors/malformed_public_inputs_v1.json`) is driven too: every case is
//! asserted to fail the strict hex boundary with its expected
//! `malformed_hex` category, and the raw presentation bytes of every case are
//! fed to `classify_public_inputs` to prove the on-chain classifier never
//! accepts a smuggled presentation for any schema.
//!
//! The corpus is deliberately dependency-free: it is scanned with a small
//! line-oriented reader rather than a JSON crate, so conformance adds no
//! third-party code to a contract crate.

#[cfg(test)]
use super::*;
#[cfg(test)]
use soroban_sdk::{testutils::Address as _, Address, Bytes, Env};
#[cfg(test)]
use std::string::{String, ToString};
#[cfg(test)]
use std::vec::Vec;
#[cfg(test)]
use std::{format, vec};

#[cfg(test)]
const CORPUS: &str = include_str!("../../../../zk/vectors/verifier_conformance_v1.json");

/// Circuit-versioned envelope corpus (`hpx-vi/2`, #368).
#[cfg(test)]
const CORPUS_V2: &str = include_str!("../../../../zk/vectors/verifier_conformance_v2.json");

/// Companion malformed public-input hex corpus (`#353`, `#809`).
#[cfg(test)]
const MALFORMED_CORPUS: &str =
    include_str!("../../../../zk/vectors/malformed_public_inputs_v1.json");

#[cfg(test)]
#[derive(Debug)]
struct ConformanceCase {
    id: String,
    schema: String,
    public_inputs_hex: String,
    proof_hex: String,
    accept: bool,
    reject_code: Option<String>,
}

/// One case from the malformed public-input hex corpus. `value` is the raw
/// wire *presentation*; it is never valid hex, so it never decodes to bytes.
#[cfg(test)]
#[derive(Debug)]
struct MalformedCase {
    id: String,
    field: String,
    value: String,
    reject_code: String,
}

/// Extract the value of `"<key>": <value>` from a single corpus line.
#[cfg(test)]
fn field_value(line: &str, key: &str) -> Option<String> {
    let trimmed = line.trim();
    let prefix = format!("\"{}\":", key);
    let rest = trimmed.strip_prefix(prefix.as_str())?;
    let rest = rest.trim().trim_end_matches(',').trim();
    if rest == "null" {
        return Some("null".to_string());
    }
    Some(rest.trim_matches('"').to_string())
}

/// Line-oriented reader for the generated corpus.
///
/// The generator emits each case with a stable key order ending in
/// `reject_code`, which is what closes a case here. Any structural drift
/// (missing key, reordered keys) surfaces as a zero-case corpus, which the
/// `corpus_is_non_empty_and_versioned` test rejects.
#[cfg(test)]
fn parse_corpus() -> Vec<ConformanceCase> {
    parse_corpus_from(CORPUS)
}

#[cfg(test)]
fn parse_corpus_v2() -> Vec<ConformanceCase> {
    parse_corpus_from(CORPUS_V2)
}

#[cfg(test)]
fn parse_corpus_from(source: &str) -> Vec<ConformanceCase> {
    let mut cases = Vec::new();
    let mut current: Option<(String, String, String, String, bool)> = None;

    for line in source.lines() {
        if let Some(id) = field_value(line, "id") {
            current = Some((id, String::new(), String::new(), String::new(), false));
            continue;
        }
        let Some(state) = current.as_mut() else {
            continue;
        };
        if let Some(schema) = field_value(line, "schema") {
            state.1 = schema;
        } else if let Some(public_inputs) = field_value(line, "public_inputs_hex") {
            state.2 = public_inputs;
        } else if let Some(proof) = field_value(line, "proof_hex") {
            state.3 = proof;
        } else if let Some(accept) = field_value(line, "accept") {
            state.4 = accept == "true";
        } else if let Some(reject_code) = field_value(line, "reject_code") {
            let (id, schema, public_inputs_hex, proof_hex, accept) = current.take().unwrap();
            cases.push(ConformanceCase {
                id,
                schema,
                public_inputs_hex,
                proof_hex,
                accept,
                reject_code: if reject_code == "null" {
                    None
                } else {
                    Some(reject_code)
                },
            });
        }
    }

    cases
}

/// Line-oriented reader for the malformed-hex corpus. Cases end at
/// `reject_code` (inside `expect`), matching the generator's key order; any
/// structural drift surfaces as a short corpus, which the integrity test
/// rejects against the raw `"id"` count.
#[cfg(test)]
fn parse_malformed_corpus() -> Vec<MalformedCase> {
    let mut cases = Vec::new();
    let mut current: Option<(String, String, String)> = None;

    for line in MALFORMED_CORPUS.lines() {
        if let Some(id) = field_value(line, "id") {
            current = Some((id, String::new(), String::new()));
            continue;
        }
        let Some(state) = current.as_mut() else {
            continue;
        };
        if let Some(field) = field_value(line, "field") {
            state.1 = field;
        } else if let Some(value) = field_value(line, "value") {
            state.2 = value;
        } else if let Some(reject_code) = field_value(line, "reject_code") {
            let (id, field, value) = current.take().unwrap();
            cases.push(MalformedCase {
                id,
                field,
                value,
                reject_code,
            });
        }
    }

    cases
}

#[cfg(test)]
fn decode_hex(value: &str) -> Vec<u8> {
    assert!(value.len() % 2 == 0, "corpus hex must be even length");
    let raw = value.as_bytes();
    let mut out = Vec::with_capacity(value.len() / 2);
    for chunk in raw.chunks(2) {
        let high = (chunk[0] as char).to_digit(16).expect("corpus hex digit");
        let low = (chunk[1] as char).to_digit(16).expect("corpus hex digit");
        out.push((high * 16 + low) as u8);
    }
    out
}

/// Strict hex decoder for the malformed-hex boundary: odd length or any
/// byte outside the ASCII `0-9a-fA-F` alphabet fails. `None` is the
/// `malformed_hex` category — the same contract the Python `decode_hex` and
/// the TypeScript `decodeHex` enforce before framing checks run.
#[cfg(test)]
fn try_decode_hex(value: &str) -> Option<Vec<u8>> {
    if value.len() % 2 != 0 {
        return None;
    }
    let raw = value.as_bytes();
    let mut out = Vec::with_capacity(value.len() / 2);
    for chunk in raw.chunks(2) {
        let high = (chunk[0] as char).to_digit(16)?;
        let low = (chunk[1] as char).to_digit(16)?;
        out.push((high * 16 + low) as u8);
    }
    Some(out)
}

#[cfg(test)]
fn schema_id(schema: &str) -> u32 {
    match schema {
        "silent_witness/v1" => SCHEMA_ID_SILENT_WITNESS,
        "silent_witness/v2" => SCHEMA_ID_SILENT_WITNESS_V2,
        "revocation_witness/v1" => SCHEMA_ID_REVOCATION_WITNESS,
        other => panic!("corpus references unknown schema: {}", other),
    }
}

/// Expected domain for a schema: the silent-witness domain tags are shared by
/// the v1 and v2 codecs (v2 changes only the appended version field).
#[cfg(test)]
fn expected_domain_for(schema: &str) -> &'static [u8; 32] {
    if schema == verifier_inputs::SCHEMA_SILENT_WITNESS
        || schema == verifier_inputs::SCHEMA_SILENT_WITNESS_V2
    {
        &verifier_inputs::SILENT_WITNESS_DOMAIN_TAG_BE
    } else {
        &REVOCATION_DOMAIN_SEPARATOR
    }
}

/// Expected numeric code for a case: 0 when accepted, otherwise the stable
/// [`RejectCode`] discriminant.
#[cfg(test)]
fn expected_code(case: &ConformanceCase) -> u32 {
    match (&case.reject_code, case.accept) {
        (None, true) => verifier_inputs::ACCEPTED_CODE,
        (Some(code), false) => RejectCode::from_wire(code)
            .unwrap_or_else(|| panic!("corpus uses unknown reject code: {}", code))
            .as_code(),
        _ => panic!("case {} has inconsistent accept/reject_code", case.id),
    }
}

// ---------------------------------------------------------------------------
// Corpus integrity
// ---------------------------------------------------------------------------

#[test]
fn corpus_is_non_empty_and_versioned() {
    assert!(
        CORPUS.contains("\"codec\": \"hpx-vi/1\""),
        "corpus codec id drifted from the contract implementation"
    );
    assert!(
        CORPUS.contains("\"version\": 1"),
        "corpus version drifted; bump the runners alongside the format"
    );

    let cases = parse_corpus();
    assert!(
        cases.len() >= 20,
        "expected a substantive corpus, parsed {} cases",
        cases.len()
    );
    assert!(
        cases.iter().any(|case| case.accept),
        "corpus must contain positive cases"
    );
    assert!(
        cases.iter().any(|case| !case.accept),
        "corpus must contain negative cases"
    );
}

#[test]
fn v2_corpus_is_non_empty_and_versioned() {
    assert!(
        CORPUS_V2.contains("\"codec\": \"hpx-vi/2\""),
        "v2 corpus codec id drifted from the contract implementation"
    );
    assert!(
        CORPUS_V2.contains("\"version\": 2"),
        "v2 corpus version drifted; bump the runners alongside the format"
    );
    assert!(
        CORPUS_V2.contains("\"version_mismatch\""),
        "v2 corpus must exercise the version_mismatch reject code"
    );

    let cases = parse_corpus_v2();
    assert!(
        cases.len() >= 10,
        "expected a substantive v2 corpus, parsed {} cases",
        cases.len()
    );
    assert!(
        cases.iter().any(|case| case.accept),
        "v2 corpus must contain positive cases"
    );
    assert!(
        cases.iter().any(|case| !case.accept),
        "v2 corpus must contain negative cases"
    );
    for case in &cases {
        assert_eq!(
            case.schema,
            verifier_inputs::SCHEMA_SILENT_WITNESS_V2,
            "v2 corpus must only reference the v2 schema (case {})",
            case.id
        );
    }
}

#[test]
fn corpus_constants_match_contract_constants() {
    // The domain separator is the one value that must be byte-identical
    // between the corpus and the deployed contract, so it is asserted
    // directly rather than through a case.
    let mut hex = String::new();
    for byte in REVOCATION_DOMAIN_SEPARATOR.iter() {
        hex.push_str(&format!("{:02x}", byte));
    }
    assert!(
        CORPUS.contains(hex.as_str()),
        "corpus revocation domain separator does not match REVOCATION_DOMAIN_SEPARATOR"
    );
}

// ---------------------------------------------------------------------------
// Companion malformed public-input hex corpus (#353, #809)
// ---------------------------------------------------------------------------

#[test]
fn malformed_corpus_is_versioned_and_rejects_only_malformed_hex() {
    assert!(
        MALFORMED_CORPUS.contains("\"format\": \"harpocrates.malformed-public-inputs\""),
        "malformed corpus format drifted from the other layers"
    );
    assert!(
        MALFORMED_CORPUS.contains("\"version\": 1"),
        "malformed corpus version drifted; bump the runners alongside the format"
    );
    assert!(
        MALFORMED_CORPUS.contains("\"codec\": \"hpx-vi/1\""),
        "malformed corpus codec id drifted from the contract implementation"
    );

    let cases = parse_malformed_corpus();
    // Every case must be accounted for: a dropped `reject_code` line (or any
    // other structural drift) would otherwise silently shrink the corpus and
    // stop asserting cases the other layers still exercise.
    assert_eq!(
        cases.len(),
        MALFORMED_CORPUS.matches("\"id\":").count(),
        "malformed corpus parser dropped cases; structural drift in the generator"
    );
    assert!(
        cases.len() >= 10,
        "expected a substantive malformed corpus, parsed {} cases",
        cases.len()
    );

    let mut ids: Vec<&str> = cases.iter().map(|case| case.id.as_str()).collect();
    ids.sort_unstable();
    ids.dedup();
    assert_eq!(
        ids.len(),
        cases.len(),
        "malformed corpus case ids must be unique"
    );

    for case in &cases {
        assert_eq!(
            case.field, "public_inputs",
            "{}: this runner classifies public inputs only",
            case.id
        );
        assert_eq!(
            case.reject_code, "malformed_hex",
            "{}: the companion corpus must only carry malformed_hex cases",
            case.id
        );
    }
}

#[test]
fn strict_hex_boundary_rejects_every_malformed_case_with_its_expected_category() {
    let mut mismatches: Vec<String> = vec![];

    for case in parse_malformed_corpus() {
        let expected = RejectCode::from_wire(&case.reject_code)
            .unwrap_or_else(|| panic!("{}: unknown reject code {}", case.id, case.reject_code));
        let actual = match try_decode_hex(&case.value) {
            Some(_) => panic!(
                "{}: corpus value is well-formed hex; the malformed corpus must only carry rejections",
                case.id
            ),
            None => RejectCode::MalformedHex,
        };
        if actual != expected {
            mismatches.push(format!(
                "{}: expected code {} ({}), got {}",
                case.id,
                expected.as_code(),
                case.reject_code,
                actual.as_code()
            ));
        }
    }

    assert!(
        mismatches.is_empty(),
        "malformed hex mismatches: {:?}",
        mismatches
    );
}

// ---------------------------------------------------------------------------
// Boundary 1: the pure codec
// ---------------------------------------------------------------------------

#[test]
fn codec_agrees_with_every_corpus_case() {
    assert_codec_agrees(&parse_corpus());
}

#[test]
fn codec_agrees_with_v2_corpus_cases() {
    assert_codec_agrees(&parse_corpus_v2());
}

fn assert_codec_agrees(cases: &[ConformanceCase]) {
    let mut mismatches: Vec<String> = vec![];

    for case in cases {
        let public_inputs = decode_hex(&case.public_inputs_hex);
        // Only the length of the proof blob is semantically relevant, so the
        // blob itself is never materialised — this keeps the oversize case
        // cheap and keeps proof material out of the test process.
        let proof_len = (case.proof_hex.len() / 2) as u32;

        let expected_domain = expected_domain_for(&case.schema);

        let actual = match verifier_inputs::classify(
            &case.schema,
            &public_inputs,
            proof_len,
            expected_domain,
        ) {
            Ok(()) => verifier_inputs::ACCEPTED_CODE,
            Err(code) => code.as_code(),
        };
        let expected = expected_code(case);

        if actual != expected {
            mismatches.push(format!(
                "{}: expected code {} ({:?}), got {}",
                case.id, expected, case.reject_code, actual
            ));
        }
    }

    assert!(mismatches.is_empty(), "codec mismatches: {:?}", mismatches);
}

// ---------------------------------------------------------------------------
// Boundary 2: the real on-chain entry point
// ---------------------------------------------------------------------------

#[test]
fn on_chain_entry_point_agrees_with_every_corpus_case() {
    let env = Env::default();
    env.mock_all_auths();
    let contract_id = env.register(HarpocratesRegistry, ());
    let client = HarpocratesRegistryClient::new(&env, &contract_id);
    client.init(&Address::generate(&env));
    assert_on_chain_agrees(&client, &env, &parse_corpus());
}

#[test]
fn on_chain_entry_point_agrees_with_v2_corpus_cases() {
    let env = Env::default();
    env.mock_all_auths();
    let contract_id = env.register(HarpocratesRegistry, ());
    let client = HarpocratesRegistryClient::new(&env, &contract_id);
    client.init(&Address::generate(&env));
    assert_on_chain_agrees(&client, &env, &parse_corpus_v2());
}

fn assert_on_chain_agrees(
    client: &HarpocratesRegistryClient,
    env: &Env,
    cases: &[ConformanceCase],
) {
    let mut mismatches: Vec<String> = vec![];

    for case in cases {
        let public_inputs = Bytes::from_slice(env, &decode_hex(&case.public_inputs_hex));
        let proof_len = (case.proof_hex.len() / 2) as u32;

        let actual =
            client.classify_public_inputs(&schema_id(&case.schema), &public_inputs, &proof_len);
        let expected = expected_code(case);

        if actual != expected {
            mismatches.push(format!(
                "{}: expected code {} ({:?}), got {}",
                case.id, expected, case.reject_code, actual
            ));
        }
    }

    assert!(
        mismatches.is_empty(),
        "on-chain mismatches: {:?}",
        mismatches
    );
}

/// `malformed_hex` is layer-local — hex decoding only happens where material
/// arrives as a string — but that locality is only safe if no byte-level
/// interpretation of a malformed presentation can be accepted on chain. Each
/// case's raw presentation bytes are therefore pushed through
/// `classify_public_inputs` for every schema: the entry point must reject
/// them, and must agree with the pure codec about the rejection (#809).
#[test]
fn on_chain_classifier_never_accepts_a_malformed_presentation() {
    let env = Env::default();
    env.mock_all_auths();
    let contract_id = env.register(HarpocratesRegistry, ());
    let client = HarpocratesRegistryClient::new(&env, &contract_id);
    client.init(&Address::generate(&env));

    let schemas = [
        (
            verifier_inputs::SCHEMA_SILENT_WITNESS,
            SCHEMA_ID_SILENT_WITNESS,
        ),
        (
            verifier_inputs::SCHEMA_SILENT_WITNESS_V2,
            SCHEMA_ID_SILENT_WITNESS_V2,
        ),
        (
            verifier_inputs::SCHEMA_REVOCATION_WITNESS,
            SCHEMA_ID_REVOCATION_WITNESS,
        ),
    ];

    let mut mismatches: Vec<String> = vec![];

    for case in parse_malformed_corpus() {
        let presentation = Bytes::from_slice(&env, case.value.as_bytes());
        // A proof length inside the accepted window, so the frame is the only
        // thing that can cause a rejection.
        let proof_len: u32 = 128;

        for (schema, schema_id) in schemas {
            let pure = match verifier_inputs::classify(
                schema,
                case.value.as_bytes(),
                proof_len,
                expected_domain_for(schema),
            ) {
                Ok(()) => verifier_inputs::ACCEPTED_CODE,
                Err(code) => code.as_code(),
            };
            let actual = client.classify_public_inputs(&schema_id, &presentation, &proof_len);
            if actual == verifier_inputs::ACCEPTED_CODE || actual != pure {
                mismatches.push(format!(
                    "{} ({}): expected a rejection matching the pure codec (code {}), got {}",
                    case.id, schema, pure, actual
                ));
            }
        }
    }

    assert!(
        mismatches.is_empty(),
        "on-chain malformed-presentation mismatches: {:?}",
        mismatches
    );
}

#[test]
fn classification_is_idempotent_and_side_effect_free() {
    let env = Env::default();
    env.mock_all_auths();
    let contract_id = env.register(HarpocratesRegistry, ());
    let client = HarpocratesRegistryClient::new(&env, &contract_id);
    let admin = Address::generate(&env);
    client.init(&admin);

    let case = parse_corpus()
        .into_iter()
        .find(|case| case.accept)
        .expect("corpus must contain a positive case");
    let public_inputs = Bytes::from_slice(&env, &decode_hex(&case.public_inputs_hex));
    let proof_len = (case.proof_hex.len() / 2) as u32;

    let first = client.classify_public_inputs(&schema_id(&case.schema), &public_inputs, &proof_len);
    let second =
        client.classify_public_inputs(&schema_id(&case.schema), &public_inputs, &proof_len);

    assert_eq!(first, verifier_inputs::ACCEPTED_CODE);
    assert_eq!(first, second, "classification must be deterministic");
    // Classification must not consume a nullifier or otherwise mutate state.
    assert_eq!(client.get_verifier(), None);
}

#[test]
fn unknown_schema_is_rejected_without_panicking() {
    let env = Env::default();
    env.mock_all_auths();
    let contract_id = env.register(HarpocratesRegistry, ());
    let client = HarpocratesRegistryClient::new(&env, &contract_id);
    client.init(&Address::generate(&env));

    let frame = Bytes::from_array(&env, &[0u8; 128]);
    assert_eq!(
        client.classify_public_inputs(&9_999, &frame, &128),
        RejectCode::UnknownSchema.as_code()
    );
}
