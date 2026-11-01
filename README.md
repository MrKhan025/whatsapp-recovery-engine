<div align="center">

# 🛡️ WhatsApp Recovery Engine — v1.0 (Advanced Edition)

**A Professional, Offline-First WhatsApp Backup Analysis, Chat Export Inspection, Media Discovery, Cryptographic SHA-256 Verification & Forensic Reporting Platform**

[![Version](https://img.shields.io/badge/version-1.0.0-0d9f76?style=for-the-badge)](https://github.com/MrKhan025/whatsapp-recovery-engine)
[![Python](https://img.shields.io/badge/Python-3.10%2B-3776AB?style=for-the-badge&logo=python&logoColor=white)](https://www.python.org/)
[![FastAPI](https://img.shields.io/badge/FastAPI-009688?style=for-the-badge&logo=fastapi&logoColor=white)](https://fastapi.tiangolo.com/)
[![SQLite](https://img.shields.io/badge/SQLite-Read--Only-003B57?style=for-the-badge&logo=sqlite&logoColor=white)](https://www.sqlite.org/)
[![Platform](https://img.shields.io/badge/Platform-Android%20%7C%20Termux%20%7C%20Linux%20%7C%20Windows-25D366?style=for-the-badge)](https://github.com/MrKhan025/whatsapp-recovery-engine)
[![Security](https://img.shields.io/badge/Privacy-100%25%20Offline%20%26%20Local-success?style=for-the-badge)](./SECURITY.md)

</div>

> **Forensic & Ethical Notice:** This project is an independent, read-only diagnostic and recovery-assistance platform for inspecting **files you own or are explicitly authorized to analyze**. It **never** bypasses WhatsApp encryption, **never** decrypts `.crypt12/.crypt14/.crypt15` files without a user-owned key/official restore flow, **never** bypasses OTPs, device locks, or Android Scoped Storage restrictions, and **never** claims guaranteed recovery of permanently deleted data.

## ✨ Key Highlights at a Glance

| Module | Core Capabilities | Forensic Safety & Verification |
| :--- | :--- | :--- |
| **1. Advanced Chat Recovery Assistant** (`wtk/chat_analyzer.py`) | Detects `msgstore.db` & `wa.db`; identifies modern (`message`/`chat`/`jid`) & legacy schemas; parses **TXT, JSON & HTML** chat exports; compares two SQLite snapshots to locate missing (historical), modified, and new messages. | Opens databases strictly with `mode=ro&immutable=1` and `PRAGMA query_only = ON`; runs `PRAGMA integrity_check`. |
| **2. Advanced Media Recovery Engine** (`wtk/media_engine.py`) | Organizes accessible media into **8 categories**: Photos, Videos, Voice Notes, Audio, Documents, Stickers, GIFs & Thumbnails; inline browser preview for images, videos & voice notes. | Validates magic-byte headers (`JPEG`, `PNG`, `GIF`, `WEBP`, `PDF`, `OggS`, `MP4`, `WAV`, `ZIP`) to flag corrupt or `0 B` files. |
| **3. Smart Backup Analyzer** (`wtk/backup_analyzer.py`) | Discovers `.crypt12`, `.crypt14`, `.crypt15` & SQLite backups without decryption; extracts embedded filename dates, sizes & timestamps; compares **2 or more** snapshots chronologically. | Flags empty (`0 B`) or suspiciously small backups and produces a comprehensive **Backup Health Report**. |
| **4. Recovery Success Estimator** (`wtk/estimator.py`) | Evaluates accessible DBs, SQLite integrity, intact media, backup health, corruption indicators, duplicate redundancy & snapshot diffs. | Reports qualitative readiness (**Low / Medium / High**) with evidence, missing requirements & next steps (no fake `%` claims). |
| **5. Cryptographic Verification Engine** (`wtk/verification.py`) | Exports selected files to a separate destination outside the source directory and generates a signed **Recovery Verification Certificate**. | Computes **pre-copy and post-copy SHA-256 checksums**, prevents accidental overwrites, and blocks symlinks/traversal. |
| **6. Multi-Format Forensic Reporting** (`wtk/reports.py`) | Generates **7 downloadable report formats**: PDF Report, JSON Scan Report, CSV Inventory, Backup Comparison, Media Recovery, DB Health & Verification Certificate. | Every report includes UTC timestamps, file counts, SHA-256 digests, anomaly warnings, and explicit technical limitations. |
| **7. Responsive 8-Tab Web Dashboard** (`web/`) | **Overview, Chat Analyzer, Backup Analyzer, Media Recovery, Duplicate Finder, Recovery Verification, Recovery Reports & Settings**. | Built-in **Dark & Light Themes** plus **English, Hindi (हिन्दी) & Urdu (اردو RTL)** multi-language support. |

## 🏗️ System Architecture

```text
whatsapp-recovery-engine/
├── wtk/                        # Core Python Package (v1.0.0)
│   ├── __init__.py             # Version & package metadata
│   ├── __main__.py             # `python -m wtk` entry point
│   ├── api.py                  # FastAPI REST backend & static dashboard mount
│   ├── cli.py                  # Command-Line Interface (scan, compare, inspect-db, serve, etc.)
│   ├── scanner.py              # Read-only directory tree scanner & inventory orchestrator
│   ├── chat_analyzer.py        # SQLite inspector, TXT/JSON/HTML parser, search & DB diff engine
│   ├── media_engine.py         # 8-category media classifier, magic-byte corruption & SHA-256 deduplicator
│   ├── backup_analyzer.py      # .crypt12/.crypt14/.crypt15 metadata analyzer & Backup Health Report
│   ├── estimator.py            # Qualitative Recovery Readiness Estimator (Low / Medium / High)
│   ├── verification.py         # Pre/post-copy SHA-256 verified export & Certificate generator
│   ├── reports.py              # 7-format PDF, JSON & CSV forensic report generator
│   ├── adb.py                  # Authorized read-only ADB diagnostics & Android/Termux guidance
│   ├── security.py             # Path traversal guard, symlink chain validator & dependency auditor
│   ├── i18n.py                 # English, Hindi & Urdu (RTL) translations
│   └── sample_bootstrap.py     # Self-healing zero-PII synthetic sample dataset generator
├── web/                        # Responsive Single-Page Forensic Dashboard
│   ├── index.html              # 8-tab responsive UI with Dark/Light mode
│   ├── style.css               # Modern adaptive styling & RTL support
│   └── app.js                  # Interactive API client, filters, media player & report downloads
├── sample-data/                # Zero-PII Synthetic Test Snapshots (auto-initialized if missing)
│   ├── snapshot_v1/            # Earlier backup snapshot (SQLite msgstore.db, .crypt14, media)
│   └── snapshot_v2/            # Newer backup snapshot (8 media categories, exports, DB changes)
├── tests/                      # Automated Pytest Suite (18 comprehensive unit & integration tests)
│   ├── test_scanner.py         # Backup discovery, SQLite integrity, 8 categories, symlinks & traversal
│   ├── test_engine.py          # Snapshot comparison, multi-snapshot diff & verified export
│   └── test_api.py             # FastAPI endpoints, chat exports & 7 forensic report formats
├── docs/                       # Additional Guides
│   ├── RECOVERY-GUIDE.md       # Step-by-step user recovery workflow
│   └── local-security.md       # Operational security checklist
├── .github/workflows/ci.yml    # GitHub Actions CI (Pytest + Bandit Security Linter + pip-audit)
├── Dockerfile                  # Non-root hardened container image
├── docker-compose.yml          # Loopback-bound (127.0.0.1:8000) read-only Compose service
├── pyproject.toml              # Package build configuration & pytest settings
├── requirements.txt            # Production dependencies
├── requirements-dev.txt        # Testing & security audit dependencies
├── requirements-termux.txt     # Termux-compatible dependencies
├── CHANGELOG.md                # Release history (v1.0.0)
├── SECURITY.md                 # Security & privacy guarantees
└── LICENSE                     # MIT License
```

## 🚀 Step-by-Step Execution Guide

### Option 1: Run on Windows, Linux, or macOS (Step-by-Step)

#### Step 1: Clone or Extract the Repository
```bash
git clone https://github.com/MrKhan025/whatsapp-recovery-engine.git
cd whatsapp-recovery-engine
```
*(If you downloaded the ZIP archive instead of using `git`, extract `whatsapp-recovery-engine.zip` and open a terminal inside the extracted folder.)*

#### Step 2: Create a Virtual Environment & Install Dependencies
* **On Linux / macOS:**
  ```bash
  python3 -m venv .venv
  source .venv/bin/activate
  pip install --upgrade pip
  pip install -r requirements.txt
  ```
* **On Windows (PowerShell):**
  ```powershell
  python -m venv .venv
  .venv\Scripts\Activate.ps1
  pip install --upgrade pip
  pip install -r requirements.txt
  ```

#### Step 3: Initialize Synthetic Sample Data (Optional — Auto-Runs on Startup)
Even if `sample-data/` was not uploaded to GitHub, the engine automatically generates the synthetic `snapshot_v1` and `snapshot_v2` test folders on startup. You can also initialize them manually at any time:
```bash
python -m wtk init-sample
```

#### Step 4: Start the Web Dashboard
```bash
python -m wtk serve --host 127.0.0.1 --port 8000
```
Open **`http://127.0.0.1:8000`** in your browser:
1. Click **"Load Sample Snapshot (v2)"** (or enter your own accessible WhatsApp folder path) and click **"Scan Folder"**.
2. Explore the **Overview** tab to view the **Recovery Readiness Assessment (Low / Medium / High)**, supporting evidence, and category counts.
3. Open **Chat Analyzer** to inspect `msgstore.db` schemas, search messages across SQLite and TXT/JSON/HTML exports, or compare `snapshot_v1/Databases/msgstore.db` against `snapshot_v2/Databases/msgstore.db`.
4. Open **Backup Analyzer** to inspect `.crypt14` metadata, detect 0-byte/suspicious backups, and compare two saved scan snapshots.
5. Open **Media Recovery** to filter by any of the 8 categories, preview photos/videos/voice notes inline, and select files for export.
6. Open **Recovery Verification** to copy selected files to a separate folder with pre-copy and post-copy SHA-256 verification and download your **Verification Certificate**.
7. Open **Recovery Reports** to download any of the **7 forensic reports** (PDF, JSON, CSV Inventory, Comparison, Media, DB Health, and Certificate).

### Option 2: Run on Android via Termux (Exact Commands)

1. Install **Termux** on your Android device and run these exact commands:
   ```bash
   pkg update -y && pkg upgrade -y
   pkg install -y python git libjpeg-turbo freetype
   termux-setup-storage
   ```
   *(Tap **"Allow"** when Android prompts for storage permission.)*

2. Clone the repository and install dependencies:
   ```bash
   git clone https://github.com/MrKhan025/whatsapp-recovery-engine.git
   cd whatsapp-recovery-engine
   pip install -r requirements-termux.txt
   ```

3. Start the local dashboard:
   ```bash
   python -m wtk serve --host 127.0.0.1 --port 8000
   ```

4. Open **`http://127.0.0.1:8000`** in Chrome/Firefox on your Android phone and scan your accessible WhatsApp shared folder:
   * **Android 11+ Path:** `/storage/emulated/0/Android/media/com.whatsapp/WhatsApp` (or `/data/data/com.termux/files/home/storage/shared/Android/media/com.whatsapp/WhatsApp`)
   * **Android 10 & Earlier Path:** `/storage/emulated/0/WhatsApp`

### Option 3: Command-Line Interface (CLI) Reference

Every dashboard capability is also available directly via the `wtk` CLI:

```bash
# 1. Initialize synthetic sample datasets (snapshot_v1 and snapshot_v2)
python -m wtk init-sample

# 2. Scan an accessible folder and generate all forensic reports (PDF, JSON, CSV, Media, DB Health)
python -m wtk scan --source ./sample-data/snapshot_v2 --output ./reports

# 3. Scan the earlier snapshot and compare two saved scan snapshots
python -m wtk scan --source ./sample-data/snapshot_v1 --output ./reports
python -m wtk compare ./reports/scan-*.json

# 4. Inspect an accessible SQLite chat database in read-only mode
python -m wtk inspect-db ./sample-data/snapshot_v2/Databases/msgstore.db

# 5. Compare two accessible SQLite chat databases at the message record level
python -m wtk compare-db ./sample-data/snapshot_v1/Databases/msgstore.db ./sample-data/snapshot_v2/Databases/msgstore.db

# 6. Parse a user-provided TXT, JSON, or HTML chat export
python -m wtk parse-export ./sample-data/snapshot_v2/Exports/chat_export.json

# 7. Copy & verify files with pre-copy and post-copy SHA-256 checksums
python -m wtk verify-export --source ./sample-data/snapshot_v2 --destination ./verified-output ./sample-data/snapshot_v2/Media/WhatsApp\ Images/IMG-20261001-WA0001.jpg

# 8. Check ADB device status and Android storage guidance
python -m wtk adb-check

# 9. Run local security & dependency posture audit
python -m wtk security-audit
```

### Option 4: Run with Docker

```bash
docker compose up --build
```
The service binds exclusively to `http://127.0.0.1:8000` on the host machine and runs as an unprivileged user (`uid 10001`) with a read-only container root filesystem.

## 🧪 Running Automated Tests & Security Checks

To run the full test suite and security linters locally (matching the GitHub Actions CI pipeline):

```bash
pip install -r requirements-dev.txt
pip install -e .
python -m pytest -q
bandit -q -r wtk
pip-audit
```

## 🔒 Security, Privacy & Honest Limitations

* **100% Local & Offline:** No telemetry, analytics, or cloud uploads.
* **Read-Only Source Protection:** Source directories are never modified; SQLite databases are opened with `mode=ro&immutable=1` and `PRAGMA query_only = ON`.
* **Path Traversal & Symlink Defense:** Rejects `..` traversal tokens, null bytes, and symbolic links during scanning, previewing, and exporting.
* **No Encryption or Permission Bypass:** Encrypted `.crypt*` backups are inventoried by metadata and SHA-256 only; restoring encrypted backups requires the official WhatsApp restore flow or a legitimate user-owned key.
* **Honest Recovery Semantics:** Deleted messages or media that do not exist in any accessible database, chat export, or earlier snapshot cannot be reconstructed from nothing.
