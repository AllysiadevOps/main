# ZK Proof Generation and Verification Benchmarks

Harpocrates needs reproducible performance and memory baselines for proof
generation and verification across browser, native, CI, and Soroban-adjacent
targets. Without them, a silent latency or memory regression can turn a
privacy-preserving path into an availability failure — or push operators to
log sensitive material while debugging.

This document covers the harness, threat assumptions, signals, configuration,
rollout/rollback, and limitations.

## Components

| Path | Role |
| --- | --- |
| `zk/bench/bench.lock.json` | Iterations, timeouts, size ceilings, concurrency, privacy policy |
| `zk/bench/zk_bench.py` | Schema, stats, privacy checks, runners, compare/trend CLI |
| `zk/bench/test_zk_bench.py` | Unit tests (no nargo/bb required) |
| `zk/bench/run.sh` | Hermetic environment wrapper |
| `zk/bench/browser_runner.mjs` | Node/bb.js prove+verify timings (browser-equivalent) |
| `zk/bench/results/` | Local reports (gitignored; never commit proof material) |
| `zk/bench/baselines.lock.json` | Published proof benchmark thresholds (absent ⇒ compare is inert) |
| `zk/bench/gates.lock.json` | Committed circuit ACIR opcode and backend gate counts |
| `zk/bench/gates.py` | Circuit gate and opcode regression check tool (`check`, `--update`) |
| `zk/bench/test_gates.py` | Unit tests for gate check comparison and parser logic |
| `.github/workflows/zk-ci.yml` | Runs `pytest zk/bench` alongside artifact tooling |

## Targets

| Target | What is measured |
| --- | --- |
| `native` | Host CLI path (`nargo`/`bb` when present; synthetic fallback only when `--synthetic`) |
| `browser` | Node + `@aztec/bb.js` UltraHonk prove/verify (same stack as the Evidence Studio worker and its non-worker fallback) |
| `ci` | CI-tagged run; synthetic driver allowed so PR checks stay hermetic without the proving toolchain |
| `soroban_adjacent` | Host CPU/memory budget envelope for `register_anonymous_verified` / public-input classify (see `test_budget.rs`) |

Cold samples approximate a fresh process/worker. Warm samples discard
`warm_discard` iterations, then record `warm_samples`. Percentiles are computed
only over successful measured samples.

### Browser runner modes

`browser_runner.mjs --mode worker|main` (default `worker`) selects which prover
runtime the run stands in for:

- `worker` — the Web Worker proving path.
- `main` — the non-worker fallback, which is exercised under the same explicit
  limits the frontend enforces at runtime (256-byte secret cap, single
  concurrent proof, per-sample timeout). The report records `mode` and
  `runtime.threading.max_concurrency`, and `test_zk_bench.py` asserts the lock
  keeps the browser target's concurrency/timeout compatible with the frontend
  fallback bounds.

Both modes run the identical Node/bb.js prover; the flag exists so regressions
in the fallback limits or a drift between paths are measured and reported, not
silently assumed identical.

## Threat assumptions

The harness defends against:

- **Unbounded work.** Sample counts, proof/public-input/witness byte ceilings,
  concurrency, per-sample timeouts, and a wall-clock cap are enforced by
  `bench.lock.json`. The Evidence Studio proof worker imports the same witness,
  proof, and public-input ceilings, while browser ACIR byte ceilings come from
  `zk/browser.artifacts.manifest.json`. Oversized or capacity-exceeding work
  fails with a typed reject code — never hangs.
- **Partial promotion.** A report is written only when `outcome=ok`. Timeouts,
  cancellations, rejections, and fatals abort without leaving a trusted report.
- **Evidence leakage.** Reports and stderr signals carry timings, percentiles,
  byte counts, digests/metadata, and machine codes. They never carry witness
  bytes, proof hex, public-input hex, credential/nullifier secrets, or
  signatures. This is pinned by `test_zk_bench.py` privacy cases.
- **Hostile duplicate load.** Concurrent bench slots above
  `min(limits.max_concurrency, target.max_concurrency)` are rejected with
  `capacity`.

It does **not** replace production admission control or on-chain verification.
It also does not claim cross-host wall-clock equality; reports include runtime
metadata so operators can compare like with like.

## Report schema

```text
format: "harpocrates.zk-bench"
version: 1
target: native | browser | ci | soroban_adjacent
fixture_id: silent_witness.synthetic.v1
toolchain: { nargo, bb, proving_scheme, oracle_hash }
runtime: { os, arch, cpu_count, python_version, ci, hostname_hash, ... }
phases[]:
  phase: prove | verify
  cold / warm: { samples_ms, percentiles?, states }
  percentiles?: { p50, p95, p99, min, max, mean, count }
  sizes: { proof_bytes, public_input_bytes, witness_bytes?, acir_bytes?, vk_bytes? }
  memory: { peak_rss_bytes? }
outcome: ok | timeout | cancelled | rejected | fatal
```

Fixture material is synthetic only. Real user evidence is out of scope.

## Local verification

```bash
# Tooling only — no proving toolchain required.
python -m pytest zk/bench -q
zk/bench/run.sh run --target ci --synthetic
zk/bench/run.sh metadata

# Optional: real browser-equivalent path after compiling circuits and
# installing frontend dependencies.
cd frontend && npm ci
# build ACIR via zk/noir scripts, then:
node zk/bench/browser_runner.mjs --cold 1 --warm 2
# exercise the non-worker fallback path under its explicit limits:
node zk/bench/browser_runner.mjs --mode main --cold 1 --warm 1
```

## Configuration

| Knob | Where | Purpose |
| --- | --- | --- |
| per-target sample counts / timeouts | `zk/bench/bench.lock.json` | Bound work |
| size ceilings | `limits.*` | Reject oversized proof/PI/witness/report |
| proof-worker memory | `limits.max_witness_bytes` + browser manifest raw bytes | Bound browser ACIR, witness, proof, and public-input memory before expensive worker/prover boundaries |
| privacy forbidden keys | `privacy.*` | Fail closed if a report grows a sensitive field |
| baselines path | `thresholds.baselines_path` | Published regression gate (`baselines.lock.json`) |

Hermetic env vars mirror the reproducible-build pipeline: `SOURCE_DATE_EPOCH=0`,
`TZ=UTC`, `LC_ALL=C`, `PYTHONHASHSEED=0`.

## Signals

Single-line JSON on **stderr**:

| Event | Meaning |
| --- | --- |
| `bench.start` / `bench.done` | Run boundaries |
| `bench.sample` | One sample terminal state (+ elapsed_ms when ok) |
| `bench.fallback` | Synthetic driver used (missing toolchain/artifacts) |
| `bench.report_written` | Successful promotion of an ok report |
| `bench.aborted` | Non-ok outcome; no report written |
| `bench.compare_inert` / `bench.compare_ok` / `bench.regression` | Threshold gate |
| `bench.cancelled` / `bench.fatal` | Terminal failure |

## Exit codes

| Code | Meaning |
| --- | --- |
| `0` | Ok (or compare inert) |
| `1` | Threshold regression |
| `2` | Usage error |
| `3` | Fatal / timeout / cancel / reject |

## Deployment impact and rollout

1. Harness + unit tests + docs are landed; CI runs unit tests and a synthetic
   prove/verify gate against committed thresholds.
2. `zk/bench/baselines.lock.json` publishes percentile, size, and RSS caps for
   `ci`, `native`, `browser`, and `soroban_adjacent`.
3. CI enforces the `ci` target: `run --target ci --synthetic` then `compare`.
4. Operators collecting native/browser reports on pinned hardware should run
   `zk/bench/run.sh compare --report …` before promoting a release candidate.

Compare is **enforcing** while `baselines.lock.json` is present. Deleting that
file returns compare to the inert (exit 0) path — same rollback pattern as the
artifact manifest drift check.

## Rollback

- **Disable threshold enforcement:** delete `zk/bench/baselines.lock.json`.
- **Discard local reports:** delete `zk/bench/results/`.
- **Revert the harness:** revert the `zk/bench/**` and docs commit; no contract,
  codec, or proof-format migration is involved.

No undocumented repair step is required.

## Troubleshooting

**`nargo/bb not available and synthetic disabled`** — install the pinned
toolchain from `zk/toolchain.lock.json`, or pass `--synthetic` for a CI-style
timing envelope.

**`missing_artifacts` from `browser_runner.mjs`** — compile circuits first
(`zk/noir/scripts/build-silent-witness.sh` or the reproducible build).

**Compare reports regression** — expected when a report exceeds `baselines.lock.json`; delete that file only to disable enforcement.

## Limitations

- Synthetic CI timings are deterministic envelopes for harness correctness, not
  substitutes for calibrated UltraHonk wall-clock on real hardware.
- Soroban-adjacent figures track host budget envelopes from `test_budget.rs`;
  they are not wall-clock UltraHonk verification inside the VM.
- Cross-architecture percentile equality is not guaranteed; use `runtime`
  metadata when comparing reports.
- Proof hex and witnesses are intentionally never stored in reports; artifact
  digests belong to the reproducible-build manifest, not this harness.
