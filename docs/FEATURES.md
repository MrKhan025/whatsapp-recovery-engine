# WhatsApp Recovery Engine v2.0 — Feature & Architecture Specification

## 1. 12-Section Forensic Dashboard Architecture

1. **Overview (`tab-overview`):** Readiness badge (`Low` / `Medium` / `High`), executive KPI cards, AI-Assisted Forensic Intelligence panel (`verified_findings` vs `inferred_observations`), and interactive SVG category distribution.
2. **Recovery Workspace (`tab-workspace`):** Active session tracker, workspace metadata, and multi-backup snapshot comparison (`compare_workspaces`).
3. **Chat Analyzer (`tab-chats`):** SQLite browser (`msgstore.db` + WAL/SHM inspection), keyword/sender/date search, `.vcf`/`.csv`/`.json` contact resolver, group conversation summary, and **JSON / CSV / HTML / PDF** chat exporter preserving message IDs and original UTC timestamps.
4. **Backup Intelligence (`tab-backups`):** Format-specific `.crypt12`, `.crypt14`, and `.crypt15` structural validation, anomaly flagging, user-authorized key decryption, and synthetic round-trip test fixtures.
5. **Media Recovery (`tab-media`):** All 8 media categories (**Photos, Videos, Voice Notes, Audio, Documents, Stickers, GIFs, Thumbnails**), orphaned media detection, SQLite media-to-message linking, EXIF/timestamp metadata extraction, magic-byte validation, and thumbnail previews.
6. **Timeline Explorer (`tab-timeline`):** Interactive SVG daily message histogram, conversation gap detector, and duplicate message cluster inspector.
7. **ADB Device Manager (`tab-adb`):** USB ADB & Android 11+ Wireless ADB (`adb pair` / `adb connect`) diagnostics, `df -h` storage availability, and `com.whatsapp` / `com.whatsapp.w4b` folder discovery.
8. **Evidence Manager (`tab-evidence`):** Unique Evidence IDs (`EVID-...`), dual `SHA-256` + `SHA-512` hashes, append-only chain-of-custody ledger, signed (`HMAC-SHA256`) vs checksum-verified manifests, and Evidence ZIP bundle generator.
9. **Integrity Verification (`tab-verify`):** Pre-export dry-run preview (`preview_recovery_operation`) and post-copy dual-hash (`SHA-256` + `SHA-512`) verification preserving original source files.
10. **Forensic Reports (`tab-reports`):** One-click generation of PDF, JSON, CSV, HTML, Backup Health, Media Recovery, Database Health, and Verification Certificate PDF reports.
11. **Security Center (`tab-security`):** Active security posture, local session & CSRF token status, dependency vulnerability audit, and secret-redacted operational audit log.
12. **Settings (`tab-settings`):** Theme toggle (Dark / Light), language selector (`English`, `हिन्दी`, `اردو`), keyboard shortcuts, and sample workspace reset instructions.
