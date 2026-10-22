#!/usr/bin/env bash
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
PYTHON="${PYTHON:-python3}"
exec "$PYTHON" "$REPO_ROOT/zk/tools/build_circuits.py" build silent_witness --prove "$@"
