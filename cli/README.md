# Headless verification CLI

From `cli/`, run `npm ci && npm run build`. The executable is `node dist/cli.js`.
It accepts the frontend's v2 proof manifest (and legacy v1), checks the
selected network and registry contract, looks up the manifest transaction and
video hash on Stellar RPC, and emits a machine-readable receipt with `--output
json`. It never needs a wallet or signing key; a funded public source address
is needed for read-only Soroban simulation.

```sh
node dist/cli.js verify --manifest proof.json \
  --contract-id C... --network 'Test DF Network ; September 2015' \
  --source-address G... --output json
```

To verify a signed verification receipt offline without hitting the RPC:

```sh
node dist/cli.js verify-receipt --receipt receipt.json --keys trusted_keys.json
```

To export C2PA authenticity assertions from a proof manifest (with an optional
verification receipt) for signing by your own C2PA tooling and key material:

```sh
node dist/cli.js c2pa --manifest proof.json [--receipt receipt.json] --output export.json
```

The export is an **unsigned** C2PA JSON manifest definition carrying standard
`c2pa.actions.v2` and `c2pa.hash.data` assertions plus namespaced
`hrpocrates.registry.v1` (canonical manifest fields bound by
`manifestHash`), `hrpocrates.verification.v1` (the receipt outcome verbatim,
only when `--receipt` is supplied, never a fabricated `valid`), and
`hrpocrates.export.v1` (`unsigned: true`). It contains only public manifest
and registry fields; it never carries media bytes, witness values, secrets,
proof bytes, or signing keys, and the exporter never signs. Out-of-band you
sign the result with your own C2PA signer. Missing `--manifest` exits 2;
malformed, unsupported, or unreadable input exits 8. The export is
deterministic, so the same manifest and receipt always produce the same bytes
(reproducible in CI via `devx/validate_c2pa_fixture.py`).

For reproducible, network-free manifest and status fixtures, run from `cli/`:

```sh
npm test -- --run test/manifest.test.ts test/normalize.test.ts
```

An offline verification exits 6 with `pending`: it checks syntax and
deployment binding but **cannot** establish on-chain validity. A successful
online check exits 0; expired 1, revoked 2, missing 3, network mismatch 4,
contract mismatch 5, pending 6, failed transaction 7, and malformed input or
dependency failure 8. Do not treat a nonzero exit or an offline receipt as
verified evidence. `--tx-hash`, when supplied, must match the manifest.

Harpocrates CLI environment variables:

- `HARPOCRATES_RPC_URL` -- default for `--rpc-url` in `verify` and `manifest`.
- `HARPOCRATES_CONTRACT_ID` -- default for `--contract-id` in `verify` and `manifest`.
- `HARPOCRATES_SOURCE_ADDRESS` -- default for `--source-address` in `verify`.

Explicit flags always take precedence over environment values. Contract-id
validation still applies to environment values.

The CLI accepts at most 1 MiB of manifest/metadata JSON. It rejects unknown
manifest fields and unsupported versions, and writes fixed, privacy-safe
error messages rather than raw RPC or file errors. Do not pass private
witnesses, seeds, credentials, media, or secrets in a manifest. The receipt
contains only public manifest and registry fields, but hashes and addresses
can still be sensitive in context; restrict receipt access accordingly.

Manifest v2 adds `verifierScope` and `epoch`, matching the frontend. V1 input
remains readable, without silently upgrading its version. Existing v1 receipt
shape and exit-code mapping remain unchanged. For rollback, deploy the prior
CLI build; no chain, metadata, or registry migration is required. The trust
boundary is the selected Stellar RPC and local clock (used to detect elapsed
record expiry); use a trusted RPC and synchronized host clock. The CLI does
not verify Noir proof bytes or replace the browser verifier.
