# Headless verification CLI

From `cli/`, run `npm ci && npm run build`. The executable is `node dist/cli.js`.
It accepts the frontend's v2 proof manifest (and legacy v1), checks the
selected network and registry contract, looks up the manifest transaction and
video hash on Stellar RPC, and emits a machine-readable receipt with `--output
json`. It never needs a wallet or signing key; a funded public source address
is needed for read-only Soroban simulation.

```sh
node dist/cli.js --version
# or: node dist/cli.js version
```

```sh
node dist/cli.js verify --manifest proof.json \
  --contract-id C... --network 'Test SDF Network ; September 2015' \
  --source-address G... --output json
```

RPC lookups are bounded by a request timeout (default 15000 ms). Override it
with `--timeout <ms>`, which must be a positive integer:

```sh
node dist/cli.js verify --manifest proof.json \
  --contract-id C... --network 'Test DF Network ; September 2015' \
  --source-address G... --timeout 5000 --output json
```

To check the on-chain lifecycle status of a proof directly by its 32-byte proof ID:

```sh
node dist/cli.js status --proof-id <64-hex> \
  --contract-id C... --network 'Test SDF Network ; September 2015' \
  --rpc-url https://soroban-testnet.stellar.org --output json
```

`status` simulates `get_proof_status(proof_id)` against the registry and maps the result to a stable status string (`registered`, `revoked`, `expired`, or `unknown`) and exit code (`0` for `registered`, `1` for `expired`, `2` for `revoked`, `3` for `unknown`). Malformed or missing `--proof-id` values exit `2` immediately without making an RPC call.

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
`hirpocrates.registry.v1` (canonical manifest fields bound by
`manifestHash`), `hirpocrates.verification.v1` (the receipt outcome verbatim,
only when `--receipt` is supplied, never a fabricated `valid`), and
`hirpocrates.export.v1` (`unsigned: true`). It contains only public manifest
and registry fields; it never carries media bytes, witness values, secrets,
proof bytes, or signing keys, and the exporter never signs. Out-of-band you
sign the result with your own C2PA signer. Missing `--manifest` exits 2;
malformed, unsupported, or unreadable input exits 8. The export is
deterministic, so the same manifest and receipt always produce the same bytes
(reproducible in CI via `devx/validate_c2pa_fixture.py`).

For reproducible, network-free manifest and status fixtures, run from `cli/`:

```sh
npm test -- --run test/manifest.test.ts test/normalize.test.ts test/status.test.ts
```

### Exit codes

Script authors and CI integrations can rely on the following exit codes to determine the outcome of a command.

| Code | Meaning | Emitted by |
| :--- | :--- | :--- |
| `0` | `valid` / `registered` / success | `verify`, `status`, `verify-receipt`, `verify-lineage` |
| `1` | `expired` | `verify`, `status`, `verify-lineage` |
| `2` | `revoked` / usage error (missing required flag) | `verify`, `status`, `verify-lineage`, `manifest`, `hash`, `c2pa` |
| `3` | `not_found` / `missing` / `unknown` | `verify`, `status`, `verify-lineage` |
| `4` | `network_mismatch` | `verify` |
| `5` | `contract_mismatch` | `verify` |
| `6` | `pending` (offline verification) | `verify` |
| `7` | `failed` transaction | `verify` |
| `8` | `error` (malformed input, dependency failure, invalid receipt, etc.) | `verify`, `status`, `verify-receipt`, `manifest`, `hash`, `c2pa`, `verify-lineage` |

An offline verification exits `6` with `pending`: it checks syntax and deployment binding but **cannot** establish on-chain validity. Do not treat a nonzero exit or an offline receipt as verified evidence. `--tx-hash`, when supplied, must match the manifest. An RPC request timeout (`--timeout`) is a dependency failure and thus also exits `8`.

Harpocrates CLI environment variables:

- `HARPOCRATES_RPC_URL` -- default for `--rpc-url` in `verify`, `status`, and `manifest`.
- `HARPOCRATES_CONTRACT_ID` -- default for `--contract-id` in `verify`, `status`, and `manifest`.
- `HARPOCRATES_SOURCE_ADDRESS` -- default for `--source-address` in `verify` and `status`.

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
record expiry); use a trusted RPC and synchronized host clock. The CLI
does not verify Noir proof bytes or replace the browser verifier.