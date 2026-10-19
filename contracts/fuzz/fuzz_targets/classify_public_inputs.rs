#![no_main]
use libfuzzer_sys::fuzz_target;
use harpocrates_registry::HarpocratesRegistry;
use soroban_sdk::{Env, Bytes};

fuzz_target!(|data: &[u8]| {
    // Need at least 8 bytes: 4 for schema_id, 4 for proof_len, rest for public inputs.
    if data.len() < 8 {
        return;
    }
    let schema_id = u32::from_be_bytes([data[0], data[1], data[2], data[3]]);
    let proof_len = u32::from_be_bytes([data[4], data[5], data[6], data[7]]);
    let public_bytes = &data[8..];
    // Create a default Env for host‑less invocation.
    let env = Env::default();
    let public_inputs = Bytes::from_slice(&env, public_bytes);
    // Invoke the on‑chain entry point. We only care that it does not panic.
    let _ = HarpocratesRegistry::classify_public_inputs(env, schema_id, public_inputs, proof_len);
});
