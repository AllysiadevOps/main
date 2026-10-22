#!/usr/bin/env bash
#
# Hermetic, double-build reproducibility check for the Harpocrates zk artifacts.
# Thin wrapper around zk/tools/build_circuits.py.
#

set -euo pipefail

# CIRCUITS list preserved for coverage verification
CIRCUITS=(
  "silent_witness"
  "silent_witness_helper"
  "silent_witness_aggregator"
  "silent_witness_aggregator_helper"
  "revocation_witness"
  "revocation_witness_helper"
  "selective_disclosure"
  "redacted_ancestry"
  "redacted_ancestry_helper"
)

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
PYTHON="${PYTHON:-python3}"
exec "$PYTHON" "$REPO_ROOT/zk/tools/build_circuits.py" build all "$@"
