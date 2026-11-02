# Pull Request: Upgrade to WhatsApp Recovery Engine v2.0 (`feature/v2-advanced-recovery`)

## Summary of Changes

This pull request upgrades **WhatsApp Recovery Engine** from `v1.0.0` (`main`) to **`v2.0.0` — Professional Digital Forensics & Backup Recovery Platform** on branch `feature/v2-advanced-recovery` while preserving all existing v1.0 functionality and backward compatibility.

### 1. Major New Modules & Upgrades
- **Advanced Recovery Engine (`wtk/engine.py`, `wtk/verification.py`):**
  - Multi-backup snapshot diffing, SQLite database message comparison, missing/newly discovered/duplicate message detection, message timeline reconstruction, conversation gap analysis, recovery session management, pre-export dry-run preview (`preview_recovery_operation`), and dual-hash (`SHA-256` + `SHA-512`) post-copy verification.
- **Advanced Media Recovery (`wtk/media_engine.py`, `wtk/chat_analyzer.py`):**
  - Full 8-category media discovery, orphaned media detection, media-to-message SQLite relational matching (`link_chat_media`), EXIF/timestamp metadata extraction, magic-byte signature validation, corruption inspection, duplicate media clustering, and thumbnail generation (Pillow + pure-Python SVG fallback).
- **Backup Intelligence (`wtk/decryptor.py`, `wtk/backup_analyzer.py`):**
  - Distinct, format-specific header validators and decryption handlers for `.crypt12` (fixed 67-byte header), `.crypt14` (protobuf header), and `.crypt15` (protobuf E2EE header + `HKDF-SHA256` key derivation), plus round-trip synthetic test fixtures (`create_synthetic_crypt_fixture`).
- **Advanced Chat Analyzer (`wtk/chat_analyzer.py`):**
  - SQLite read-only browser (`mode=ro&immutable=1`), WAL (`-wal`) header and frame inspection, keyword/sender/date search, `.vcf`/`.csv`/`.json` contact matching, group conversation analytics, and **JSON, CSV, HTML, and PDF chat exports** preserving message IDs and original UTC timestamps.
- **Advanced Android & ADB Module (`wtk/adb.py`):**
  - USB ADB & Wireless ADB (`adb pair` / `adb connect`) diagnostics, Android version/SDK inspection, `df -h` storage availability parsing, `com.whatsapp` and `com.whatsapp.w4b` folder discovery, and post-pull transfer verification.
- **AI-Assisted Forensic Analysis (`wtk/forensic_ai.py`):**
  - Optional, 100% local offline heuristic engine summarizing conversations, identifying missing date ranges, explaining backup differences and corruption indicators, and explicitly separating `verified_findings` from `inferred_observations`.
- **Professional Evidence Management (`wtk/evidence.py`, `wtk/reports.py`):**
  - Unique Evidence IDs (`EVID-...`), `SHA-256` and `SHA-512` checksums, chain-of-custody ledger, export history, signed (`cryptographically_signed_hmac_sha256`) vs checksum-verified (`checksum_verified_only`) evidence manifests, PDF forensic certificates, and downloadable Evidence ZIP bundles.
- **12-Section Web Dashboard (`web/index.html`, `web/style.css`, `web/app.js`):**
  - Upgraded UI to 12 dedicated forensic workspaces with interactive SVG charts, Dark/Light themes, keyboard shortcuts, and English/Hindi/Urdu i18n.
- **Enterprise Security (`wtk/security.py`):**
  - Local session authentication with TTL expiration, CSRF token issuance/validation, `EncryptedTempStore` with `atexit` zero-wipe cleanup, secret-redacting `AuditLogger`, and dependency vulnerability scanner.

### 2. Verification & QA Checklist
- [x] Unit & integration tests covering all 14 required forensic and security domains (`tests/test_scanner.py`, `tests/test_engine.py`, `tests/test_api.py`).
- [x] Static security audit (`bandit`) and linting (`ruff`) configured in `pyproject.toml` and `.github/workflows/ci.yml`.
- [x] Verified read-only SQLite access (`mode=ro&immutable=1` + `PRAGMA query_only=ON`) and source file preservation.
