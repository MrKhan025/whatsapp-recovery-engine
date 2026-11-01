# WhatsApp Recovery Engine – Advanced Edition (v3.0)

**Repository:** `whatsapp-recovery-engine`

A professional, offline-first WhatsApp backup analysis, chat export inspection, media discovery, cryptographic SHA-256 verification, and forensic reporting platform supporting **Android, Windows, Linux, Termux, and ADB-connected Android devices**.

> **Ethical & Forensic Disclaimer:** This is not an official WhatsApp product. It operates strictly in **read-only mode** on user-owned, accessible files. It never bypasses WhatsApp encryption, never decrypts `.crypt*` backups without a legitimate user-owned key/restore flow, never bypasses OTPs/passwords/device locks or Android scoped-storage restrictions, and never claims guaranteed recovery of permanently deleted data.

## Core Capabilities (v3.0 Advanced Edition)

### 1. Advanced Chat Recovery Assistant (`wtk/chat_analyzer.py`)
- Detects accessible WhatsApp SQLite databases (`msgstore.db`, `wa.db`, `chatsettings.db`, `.sqlite`).
- Identifies SQLite database formats and WhatsApp schema generations (`whatsapp_msgstore_modern`, `whatsapp_msgstore_legacy`, `whatsapp_wa_contacts`).
- Runs strictly read-only integrity checks (`PRAGMA integrity_check` with `mode=ro&immutable=1` and `PRAGMA query_only=ON`).
- Extracts database tables, column schemas, timestamps, and accessible message records.
- Parses user-provided **TXT, JSON, and HTML** WhatsApp chat exports with keyword and sender search.
- Compares two accessible SQLite database snapshots to identify **missing (historical), changed, and newly discovered** message records.

### 2. Advanced Media Recovery Engine (`wtk/media_engine.py`)
- Organizes accessible media into **8 categories**: Photos, Videos, Voice Notes, Audio Files, Documents, Stickers, GIFs, and Thumbnails.
- Performs magic-byte header validation to flag empty or corrupt media files where technically possible.
- Supports filtering by category, file size, modification date, filename query, corruption status, and duplicate status.
- Provides local-only inline browser previews for images, videos, and voice notes/audio files.

### 3. Smart Backup Analyzer (`wtk/backup_analyzer.py`)
- Discovers `.crypt12`, `.crypt14`, `.crypt15`, and SQLite backups without decrypting encrypted archives.
- Extracts file sizes, modification timestamps, embedded filename dates, and SHA-256 digests.
- Flags empty (`0 B`) or suspiciously small backup files and generates a structured **Backup Health Report**.
- Compares **two or more** backup snapshots chronologically to identify added, removed, changed, and unchanged files.

### 4. Recovery Success Estimator (`wtk/estimator.py`)
- Evaluates accessible database availability, SQLite integrity, intact media counts, backup file health, corruption indicators, duplicate redundancy, and snapshot differences.
- Outputs qualitative readiness (**Low / Medium / High**), supporting evidence, missing requirements, and recommended next steps — never presenting misleading "guaranteed recovery percentages".

### 5. Modern Responsive Dashboard (`web/`)
- 8 dedicated workspaces: **Overview, Chat Analyzer, Backup Analyzer, Media Recovery, Duplicate Finder, Recovery Verification, Recovery Reports, and Settings**.
- Mobile-friendly responsive layout with **Dark and Light themes**.
- Multi-language interface supporting **English, Hindi (हिन्दी), and Urdu (اردو with automatic RTL layout)**.

### 6. Recovery Verification & Forensic Reporting (`wtk/verification.py`, `wtk/reports.py`)
- Copies selected files to a separate destination outside the scanned source, computes **pre-copy and post-copy SHA-256 checksums**, prevents accidental overwriting, and issues a **Recovery Verification Certificate**.
- Generates **7 forensic report formats**: PDF Report, JSON Scan Report, CSV File Inventory, Backup Comparison Report, Media Recovery Report, Database Health Report, and Recovery Verification Certificate (PDF & JSON).

## Installation & Quick Start

### Linux / macOS / Windows
```bash
python3 -m venv .venv
# Linux / macOS:
source .venv/bin/activate
# Windows PowerShell:
# .venv\Scripts\Activate.ps1

pip install -r requirements.txt
python3 -m wtk serve --host 127.0.0.1 --port 8000
```
Open `http://127.0.0.1:8000` in your browser.

### Exact Termux (Android) Installation & Startup Commands
Run the following commands inside Termux on Android:
```bash
pkg update -y && pkg upgrade -y
pkg install -y python git libjpeg-turbo freetype
termux-setup-storage
git clone https://github.com/MrKhan025/whatsapp-recovery-engine.git
cd whatsapp-recovery-engine
pip install -r requirements-termux.txt
python -m wtk serve --host 127.0.0.1 --port 8000
```
Then open `http://127.0.0.1:8000` in your Android browser. Typical accessible shared-storage paths:
- Android 11+: `/storage/emulated/0/Android/media/com.whatsapp/WhatsApp` (or `~/storage/shared/Android/media/com.whatsapp/WhatsApp`)
- Android 10 & earlier: `/storage/emulated/0/WhatsApp`

## Command-Line Interface (CLI)
```bash
# Scan an accessible folder and generate PDF, JSON, CSV, Media, and DB Health reports
python3 -m wtk scan --source ./sample-data/snapshot_v2 --output ./reports

# Compare two saved scan snapshots
python3 -m wtk compare ./reports/scan-old.json ./reports/scan-new.json

# Inspect an unencrypted SQLite database in read-only mode
python3 -m wtk inspect-db ./sample-data/snapshot_v2/Databases/msgstore.db

# Compare two accessible SQLite chat database snapshots at the record level
python3 -m wtk compare-db ./sample-data/snapshot_v1/Databases/msgstore.db ./sample-data/snapshot_v2/Databases/msgstore.db

# Parse a TXT, JSON, or HTML chat export
python3 -m wtk parse-export ./sample-data/snapshot_v2/Exports/chat_export.json

# Check ADB connection status and Android storage guidance
python3 -m wtk adb-check

# Run local security and dependency posture audit
python3 -m wtk security-audit
```

## Running Automated Tests
```bash
pip install -r requirements-dev.txt
pytest -q
```

## Docker Deployment
```bash
docker compose up --build
```
Binds strictly to `127.0.0.1:8000` as a non-root container user with read-only root filesystem.
