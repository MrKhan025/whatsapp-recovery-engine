# Contributing to WhatsApp Recovery Engine v2.0

Thank you for contributing to **WhatsApp Recovery Engine v2.0**.

## 1. Development Workflow

1. Fork and clone the repository:
   ```bash
   git clone https://github.com/MrKhan025/whatsapp-recovery-engine.git
   cd whatsapp-recovery-engine
   git checkout feature/v2-advanced-recovery
   ```
2. Set up a virtual environment and install dependencies:
   ```bash
   python3 -m venv .venv
   source .venv/bin/activate
   pip install -r requirements.txt -r requirements-dev.txt
   ```
3. Run the automated test suite and static security analyzers:
   ```bash
   PYTHONPATH=. python3 -m pytest -v
   bandit -q -ll -r wtk
   ruff check wtk/ main.py
   ```

## 2. Architectural & Forensic Rules

- **Never mutate source files:** All SQLite databases and backup folders must be opened strictly read-only (`mode=ro&immutable=1` + `PRAGMA query_only=ON`).
- **Dual Hashing:** All new export or evidence functions must calculate both `SHA-256` and `SHA-512`.
- **Format-Specific Crypt Validation:** Never assume `.crypt12`, `.crypt14`, and `.crypt15` share identical headers, offsets, or key derivation.
- **No Sensitive Data Logging:** Use `AuditLogger` from `wtk/security.py` so cryptographic keys, tokens, and message bodies are redacted automatically.
