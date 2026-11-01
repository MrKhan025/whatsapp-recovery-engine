# Contributing to WhatsApp Recovery Engine

Thank you for your interest in contributing to **WhatsApp Recovery Engine (v1.0)**!

## Core Ethical & Technical Principles

All contributions must strictly adhere to our security and forensic integrity boundaries:

1. **100% Local & Offline Processing:** Never introduce telemetry, external analytics, or automatic cloud uploads.
2. **Read-Only Source Operations:** Never modify scanned directories or source SQLite databases (`mode=ro&immutable=1` and `PRAGMA query_only = ON` must always be enforced).
3. **Authorized Operations Only:** Never add features designed to brute-force keys, bypass Android sandboxing/Scoped Storage, root devices, or bypass OTPs/account authentication.
4. **Honest Recovery Semantics:** Never claim guaranteed recovery percentages or claim that permanently overwritten data can be reconstructed without an accessible backup or snapshot.

## Development Setup

```bash
git clone https://github.com/MrKhan025/whatsapp-recovery-engine.git
cd whatsapp-recovery-engine
python3 -m venv .venv
source .venv/bin/activate
pip install --upgrade pip setuptools wheel
pip install -r requirements-dev.txt
```

## Pre-Commit Quality Checklist

Before opening a Pull Request, ensure all checks pass locally:

```bash
# 1. Initialize synthetic zero-PII test data
python -m wtk init-sample

# 2. Run the automated pytest suite
python -m pytest -v

# 3. Run Bandit security static analysis
bandit -q -ll -r wtk

# 4. Run dependency vulnerability audit
pip-audit -r requirements.txt
```
