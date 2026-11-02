# REST API Reference — WhatsApp Recovery Engine v2.0

Base URL (default loopback): `http://127.0.0.1:8000`

---

## 1. Health, Session & Security Endpoints

| Method | Endpoint | Description |
| :--- | :--- | :--- |
| `GET` | `/api/health` | Returns service health, version (`2.0.0`), and default sample snapshot paths. |
| `POST` | `/api/session` | Issues a local session token (`session_token`) and CSRF token (`csrf_token`). |
| `GET` | `/api/security/audit` | Returns security posture, dependency vulnerability scan, audit log entries, and CRYPT12/14/15 specs. |
| `GET` | `/api/i18n/{lang}` | Returns UI localization strings (`en`, `hi`, `ur`). |

## 2. Recovery Workspace & Scan Endpoints

| Method | Endpoint | Description |
| :--- | :--- | :--- |
| `POST` | `/api/scan` | Scans a local directory read-only (`path`, optional `contacts_file`, `session_id`) and returns full chat, media, backup, readiness, and AI forensic intelligence. |
| `GET` | `/api/history` | Lists in-memory scan history and recovery sessions (`sessions`). |
| `POST` | `/api/compare` | Compares two backup snapshots (`source_a`, `source_b`) across files, SQLite messages, and AI difference explanations. |

## 3. Advanced Chat Analyzer & Export Endpoints

| Method | Endpoint | Description |
| :--- | :--- | :--- |
| `POST` | `/api/chats/export` | Filters messages by keyword, sender, and date range (`date_from`, `date_to`) and exports to `json`, `csv`, `html`, or `pdf` with dual `SHA-256`/`SHA-512` hashes. |

## 4. Backup Intelligence & User-Key Decryption Endpoints

| Method | Endpoint | Description |
| :--- | :--- | :--- |
| `POST` | `/api/decrypt` | Validates `.crypt12`/`.crypt14`/`.crypt15` headers and decrypts using user-authorized `key_hex` or `key_file`. |
| `POST` | `/api/decrypt/test-fixture` | Generates and verifies a synthetic `.crypt12`, `.crypt14`, or `.crypt15` fixture (`encryption_version`). |

## 5. Media Preview & Thumbnail Endpoints

| Method | Endpoint | Description |
| :--- | :--- | :--- |
| `GET` | `/api/media/preview` | Streams an authorized media file (`base_dir`, `relative_path`) for inline preview. |
| `GET` | `/api/media/thumbnail` | Generates or returns a base64 thumbnail (`data_uri`) for any media artifact. |

## 6. Recovery Preview, Verification & Evidence Management Endpoints

| Method | Endpoint | Description |
| :--- | :--- | :--- |
| `POST` | `/api/verify-preview` | Dry-run preview of a recovery export operation showing file readiness, collisions, and byte totals. |
| `POST` | `/api/verify-export` | Copies artifacts to a destination folder and verifies pre/post `SHA-256` and `SHA-512` digests with optional `signing_key_hex`. |
| `GET` | `/api/evidence` | Lists registered evidence items, chain-of-custody ledger, and export history. |
| `POST` | `/api/evidence/register` | Registers a file into the Evidence Manager with unique `EVID-...` ID and dual `SHA-256`/`SHA-512` hashes. |
| `POST` | `/api/evidence/verify/{evidence_id}` | Re-verifies an evidence item's live `SHA-256` and `SHA-512` checksums against its acquisition record and appends a custody entry. |
| `POST` | `/api/evidence/manifest` | Generates a signed (`HMAC-SHA256`) or checksum-verified evidence manifest. |
| `POST` | `/api/evidence/bundle` | Generates a complete forensic Evidence ZIP Bundle (`evidence_manifest.json`, `forensic_analysis.json`, `chain_of_custody.json`, `export_history.json`, and PDF certificate). |

## 7. Forensic Reports & ADB Diagnostics Endpoints

| Method | Endpoint | Description |
| :--- | :--- | :--- |
| `POST` | `/api/reports` | Generates all 8 forensic report formats (`pdf`, `json`, `csv`, `html`, `backup_health_json`, `media_recovery_json`, `database_health_json`, `verification_certificate_pdf`). |
| `GET` | `/api/adb` | Runs USB & Wireless ADB diagnostics, Android version/storage inspection, and WhatsApp (`com.whatsapp` & `com.whatsapp.w4b`) directory discovery. |
