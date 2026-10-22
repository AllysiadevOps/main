# Historical Archive: Security Remediation & Policy

> **Historical Archive**: This document is an unmaintained historical working note preserved for reference. For current maintained security policies and vulnerability reporting procedures, refer to [SECURITY.md](../../SECURITY.md).

---

# Security Remediation & Policy

This repository utilizes automated secret scanning (TruffleHog) and dependency auditing (`npm audit`, `pip-audit`, `cargo-audit`) on all pull requests.

## Severity Policy
The CI pipeline is configured to fail the build if it detects:
- **Secrets:** Any verified, active cryptographic secret, API key, or credential.
- **Dependencies:** Any known vulnerability with a severity of **HIGH** or **CRITICAL**. (Low and moderate vulnerabilities will log warnings but will not block merges).

## Remediation & False Positives

### 1. Committed Secrets
If the TruffleHog step fails because you accidentally committed a secret:
- **Do not simply delete the secret in a new commit.** The secret will remain in git history.
- **Remediation:** You must immediately revoke the compromised credential in the issuing provider's dashboard.
- **False Positives:** If TruffleHog flags a safe, dummy testing string, you can safely ignore it by prepending `// trufflehog:ignore` or `# trufflehog:ignore` on the line above the flag.

### 2. Dependency Vulnerabilities
If an audit step fails due to a high/critical CVE:
- **Node (Frontend):** Run `npm audit fix` locally in the `/frontend` directory and commit the updated `package-lock.json`.
- **Python (Backend):** Update the vulnerable package version in `/backend/requirements.txt`.
- **Rust (Contracts):** Run `cargo update -p <crate_name>` to pull in the patched version.
- **False Positives / Unpatched CVEs:** If a patch is unavailable or the vulnerability does not affect our execution path, we will document an exception in the PR and use specific tool configurations (e.g., `audit.toml` for Rust) to bypass the block locally.
