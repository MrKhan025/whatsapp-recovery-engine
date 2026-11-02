# Changelog

All notable changes to **WhatsApp Recovery Engine** are documented in this file.

## [2.0.0] — 2025-02-26 (Branch: `feature/v2-advanced-recovery`)

### Added
- **Advanced Recovery Engine (`wtk/engine.py`, `wtk/verification.py`):**
  - Multi-backup comparison, SQLite database message diffing, duplicate message detection, message timeline reconstruction, conversation gap analysis, recovery session management, pre-export dry-run preview (`preview_recovery_operation`), and dual-hash (`SHA-256` + `SHA-512`) post-copy verification.
- **Advanced Media Recovery (`wtk/media_engine.py`, `wtk/chat_analyzer.py`):**
  - Full 8-category media classification, orphaned media detection, SQLite media-to-message relationship linking (`link_chat_media`), EXIF/timestamp metadata extraction, magic-byte file signature validation, corruption inspection, duplicate media clustering, and thumbnail generation (Pillow + pure-Python SVG fallback).
- **Backup Intelligence (`wtk/decryptor.py`, `wtk/backup_analyzer.py`):**
  - Format-specific `.crypt12` (fixed 67-byte header), `.crypt14` (protobuf header), and `.crypt15` (E2EE protobuf header + `HKDF-SHA256` key derivation) structural validators, user-authorized key parsers (64-char hex, 32-byte raw, 158-byte Android keyfile), and round-trip synthetic test fixtures for all three formats.
- **Advanced Chat Analyzer (`wtk/chat_analyzer.py`):**
  - Read-only SQLite browser (`mode=ro&immutable=1`), WAL (`-wal`) header and frame estimator, sender/date/keyword filtering, `.vcf`/`.csv`/`.json` contact matching, group conversation analytics, and chat record export to **JSON, CSV, HTML, and PDF** preserving message IDs and original UTC timestamps.
- **Advanced Android & ADB Module (`wtk/adb.py`):**
  - USB ADB & Android 11+ Wireless ADB (`adb pair` / `adb connect`) diagnostics, Android version/API detection, `df -h` storage availability parsing, WhatsApp (`com.whatsapp`) and WhatsApp Business (`com.whatsapp.w4b`) directory discovery, and post-pull `SHA-256`/`SHA-512` transfer verification.
- **AI-Assisted Forensic Analysis (`wtk/forensic_ai.py`):**
  - Local, offline-by-default heuristic analysis engine providing conversation summaries, missing date range explanations, backup difference narratives, suspicious file inconsistency flags, and structured findings explicitly separated into `verified_findings` and `inferred_observations`.
- **Professional Evidence Management (`wtk/evidence.py`, `wtk/reports.py`):**
  - Unique Evidence IDs (`EVID-...`), `SHA-256` + `SHA-512` checksums, append-only chain-of-custody records, signed vs checksum-verified evidence manifests (`cryptographically_signed_hmac_sha256` vs `checksum_verified_only`), PDF forensic certificates, and downloadable Evidence ZIP bundles.
- **12-Section Web Dashboard (`web/index.html`, `web/style.css`, `web/app.js`):**
  - Upgraded UI to 12 dedicated forensic workspaces with interactive SVG timeline charts, Dark/Light themes, keyboard shortcuts, and English/Hindi/Urdu localization.
- **Enterprise Security (`wtk/security.py`):**
  - Local session authentication with TTL expiration, CSRF token issuance/validation, `EncryptedTempStore` with `atexit` zero-wipe cleanup, secret-redacting `AuditLogger`, and dependency vulnerability scanner.

## [1.0.0] — 2025-02-20 (Branch: `main`)
- Initial release of WhatsApp Recovery Engine with read-only workspace scanning, `.crypt*` header detection, 8-category media discovery, SHA-256 export verification, readiness estimator, and 8-tab responsive web dashboard.
