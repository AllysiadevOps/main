# Coverage thresholds by workspace

Each workspace publishes its minimum test coverage as a small, declarative
JSON file under `devx/coverage/thresholds/<workspace>.json`, instead of
burying the number inside a workspace's own test config. That keeps the bar
visible in one place and lets one script enforce it across languages.

## File format

```json
{
  "workspace": "backend",
  "report_format": "coverage_py",
  "thresholds": { "line_rate": 70, "branch_rate": 55 }
}
```

- `report_format` is `coverage_py` (Python `coverage json` output, as
  produced by pytest-cov), `istanbul_summary` (vitest/istanbul
  `coverage-summary.json`, produced by vitest's `--coverage` with the
  `json-summary` reporter), or `llvm_cov_json` (`cargo llvm-cov --json`
  output).
- `thresholds` maps a metric name to a minimum percentage (0-100).

## Checking a report locally

```bash
# backend (from repo root, after `coverage json` has written backend/coverage.json)
python3 devx/coverage/check_coverage.py --workspace backend --report backend/coverage.json

# frontend / cli (after `vitest run --coverage` with the json-summary reporter)
python3 devx/coverage/check_coverage.py --workspace frontend --report frontend/coverage/coverage-summary.json

# contracts (after `cargo llvm-cov --json --output-path coverage.json` in contracts/)
python3 devx/coverage/check_coverage.py --workspace contracts --report contracts/coverage.json

# validate that every thresholds file itself is well-formed, without a report
python3 devx/coverage/check_coverage.py --lint-thresholds
```

The checker fails closed: a missing report file, invalid JSON, a report
missing the metrics a workspace requires, or a malformed thresholds file are
all treated as failures, not passes. Run the tests with:

```bash
python3 -m pytest devx/coverage/test_check_coverage.py -v
```

## Raising the bar

The starting numbers in `thresholds/*.json` are conservative floors, not
targets. Raise a workspace's threshold in its JSON file as coverage improves;
lowering one should be a deliberate, reviewed change.
