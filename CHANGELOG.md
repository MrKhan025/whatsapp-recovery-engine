# Changelog

All notable changes to `whatsapp-recovery-engine` are documented in this file.

## [1.0.0] - 2026-11-01 (Advanced Edition Release)

### Added
- **Advanced Chat Recovery Assistant (`wtk/chat_analyzer.py`)**:
  - Read-only SQLite inspection (`mode=ro&immutable=1`, `PRAGMA query_only=ON`, `PRAGMA integrity_check`).
  - Automatic detection of modern (`message`/`chat`/`jid`) and legacy (`messages`/`chat_list`) WhatsApp schemas and `wa_contacts`.
  - Support for parsing and searching user-provided TXT, JSON, and HTML WhatsApp chat exports.
  - Record-level SQLite database snapshot comparison (`compare_chat_databases`) identifying missing (historical), modified, and newly discovered messages.
- **Advanced Media Recovery Engine (`wtk/media_engine.py`)**:
  - 8-category media classification: Photos, Videos, Voice Notes, Audio Files, Documents, Stickers, GIFs, and Thumbnails.
  - Magic-byte header integrity validation to flag 0-byte or corrupt media headers.
  - Filtering by category, byte size, modification timestamp, corruption status, and SHA-256 duplicates.
- **Smart Backup Analyzer (`wtk/backup_analyzer.py`)**:
  - Metadata inspection for encrypted `.crypt12`, `.crypt14`, and `.crypt15` backups without unauthorized decryption.
  - Detection of empty or suspiciously small backup files and generation of structured Backup Health Reports.
  - Multi-snapshot comparison (`compare_multiple_snapshots`) across two or more backup snapshots.
- **Recovery Success Estimator (`wtk/estimator.py`)**:
  - Qualitative readiness assessment (`Low` / `Medium` / `High`) backed by concrete evidence, missing requirements, and recommended next steps.
- **Advanced 8-Tab Responsive Dashboard (`web/`)**:
  - Overview, Chat Analyzer, Backup Analyzer, Media Recovery, Duplicate Finder, Recovery Verification, Recovery Reports, and Settings views.
  - Dark/Light theme switcher and English, Hindi, and Urdu (RTL) internationalization.
- **Forensic Reporting & Verification (`wtk/verification.py`, `wtk/reports.py`)**:
  - Pre-copy and post-copy SHA-256 verification and printable PDF/JSON Recovery Verification Certificates.
  - Generation of 7 report formats: PDF, JSON, CSV File Inventory, Backup Comparison, Media Recovery, Database Health, and Verification Certificate.
- **Self-Healing Synthetic Sample Data (`wtk/sample_bootstrap.py` & `sample-data/`)**:
  - Zero-PII `snapshot_v1` and `snapshot_v2` datasets with SQLite DBs, `.crypt14` headers, TXT/JSON/HTML exports, and 8 media categories, automatically initialized if missing.
