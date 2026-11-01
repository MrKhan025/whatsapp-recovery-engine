## Summary of Changes

- Describe the feature, bug fix, or forensic enhancement introduced in this PR.

## Verification & Security Checklist

- [ ] Source scanning remains strictly read-only (`mode=ro&immutable=1` and `PRAGMA query_only = ON`).
- [ ] No telemetry, external network calls, or unauthorized encryption/permission bypasses were introduced.
- [ ] All automated tests pass (`python -m pytest -q`).
- [ ] Bandit security linter passes with zero issues (`bandit -q -ll -r wtk`).
