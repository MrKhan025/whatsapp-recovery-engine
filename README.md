<div align="center">

# WhatsApp Recovery Engine — v2.0

### Professional Digital Forensics, Backup Intelligence, Media Recovery & Evidence Verification Platform

[![Version](https://img.shields.io/badge/version-2.0.0-10b981?style=for-the-badge)](CHANGELOG.md)
[![Python](https://img.shields.io/badge/python-3.10%2B-3b82f6?style=for-the-badge&logo=python&logoColor=white)](pyproject.toml)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.110%2B-059669?style=for-the-badge&logo=fastapi&logoColor=white)](https://fastapi.tiangolo.com/)
[![Security](https://img.shields.io/badge/Offline--First-Read--Only%20Forensics-f59e0b?style=for-the-badge)](SECURITY.md)
[![License: MIT](https://img.shields.io/badge/License-MIT-6366f1?style=for-the-badge)](LICENSE)

**Supported Platforms:** Windows 10/11 • Linux • macOS • Android Termux • USB & Wireless ADB Devices • Docker

</div>

![Dashboard Preview](docs/screenshots/dashboard-preview.svg)

---

## Overview

**WhatsApp Recovery Engine v2.0** is an offline-first digital forensics, backup intelligence, media recovery, and cryptographic verification platform designed for examining user-authorized WhatsApp (`com.whatsapp`) and WhatsApp Business (`com.whatsapp.w4b`) backups and exports.

Every analysis operation strictly enforces **read-only source inspection** (`mode=ro&immutable=1` and `PRAGMA query_only=ON`), **dual cryptographic hashing (`SHA-256` + `SHA-512`)**, and **chain-of-custody evidence tracking** without modifying original backup files or transmitting data to external cloud servers.

---

## Core v2.0 Capabilities

| Subsystem | Key Capabilities |
| :--- | :--- |
| **1. Advanced Recovery Engine** | Multi-backup snapshot diffing, SQLite DB comparison, missing/newly discovered/duplicate message detection, timeline reconstruction, conversation gap analysis, recovery session management, operation preview (`dry-run`), and dual-hash post-copy verification. |
| **2. Advanced Media Recovery** | Categorizes all 8 WhatsApp media types (**Photos, Videos, Voice Notes, Audio, Documents, Stickers, GIFs, Thumbnails**), detects **orphaned media**, maps media attachments to SQLite message rows, extracts EXIF/timestamp metadata, validates magic-byte signatures, generates thumbnails, and safely exports verified copies. |
| **3. Backup Intelligence** | Format-specific `.crypt12`, `.crypt14`, and `.crypt15` header inspection & validation (distinct header layouts, IV offsets, and `HKDF-SHA256` key derivation for CRYPT15), anomaly detection, multi-backup comparison, backup history tracking, and user-authorized key decryption with synthetic test fixtures. |
| **4. Advanced Chat Analyzer** | Interactive SQLite browser, WAL/SHM/Journal frame inspection, message/sender/date search, `.vcf`/`.csv`/`.json` contact matching, group conversation analytics, `.txt`/`.json`/`.html` export parsing, and **JSON, CSV, HTML, and PDF chat exports** preserving message IDs and original UTC timestamps. |
| **5. Advanced Android & ADB Module** | USB ADB & Android 11+ Wireless ADB (`adb pair` / `adb connect`) diagnostics, Android version/API/SDK detection, `df -h` storage availability, WhatsApp & WhatsApp Business folder discovery, authorized backup acquisition verification, and Termux native execution. |
| **6. AI-Assisted Forensic Analysis** | Optional, **100% local offline heuristic engine** that summarizes conversations, identifies missing date ranges, explains backup differences and corruption indicators, and explicitly separates **Verified Findings** from **Inferred Observations**. |
| **7. Professional Evidence Management** | Unique Evidence IDs (`EVID-...`), `SHA-256` + `SHA-512` dual hashes, append-only chain-of-custody ledger, export history, **Signed Evidence Manifests** (explicitly distinguishing `cryptographically_signed_hmac_sha256` vs `checksum_verified_only`), PDF forensic certificates, and **Evidence ZIP Bundles**. |
| **8. 12-Section Web Dashboard** | Responsive Dark/Light UI featuring **Overview, Recovery Workspace, Chat Analyzer, Backup Intelligence, Media Recovery, Timeline Explorer, ADB Device Manager, Evidence Manager, Integrity Verification, Forensic Reports, Security Center, and Settings** with English, Hindi (`हिन्दी`), and Urdu (`اردو` RTL) support. |

---

## Quick Start (Step-by-Step Execution Guide)

### 1. Windows 10 / 11
```powershell
git clone https://github.com/MrKhan025/whatsapp-recovery-engine.git
cd whatsapp-recovery-engine
git checkout feature/v2-advanced-recovery

python -m venv .venv
.venv\Scripts\activate
pip install -r requirements.txt

# Launch the v2.0 Dashboard (automatically creates sample_data/snapshot_v1 & snapshot_v2)
python main.py serve --host 127.0.0.1 --port 8000
```
Open **`http://127.0.0.1:8000`** in your browser, or double-click **`start.bat`**.

### 2. Linux & macOS
```bash
git clone https://github.com/MrKhan025/whatsapp-recovery-engine.git
cd whatsapp-recovery-engine
git checkout feature/v2-advanced-recovery

python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt

python3 main.py serve --host 127.0.0.1 --port 8000
```

### 3. Android (Termux — No Root Required)
> **Important Termux Rule:** Never run `pip install --upgrade pip` in Termux (it breaks Termux's system wrapper), and always use `requirements-termux.txt` so `pydantic-core` installs prebuilt Android wheels instead of compiling Rust from source.

```bash
pkg update -y && pkg upgrade -y
pkg install -y python git android-tools tur-repo
termux-setup-storage

git clone https://github.com/MrKhan025/whatsapp-recovery-engine.git
cd whatsapp-recovery-engine
git checkout feature/v2-advanced-recovery

pip install -r requirements-termux.txt
python main.py serve --host 127.0.0.1 --port 8000
```
Or run the automated Termux installer:
```bash
bash scripts/termux-install.sh
```

---

## Command-Line Interface (`main.py` & `wtk`)

```bash
# 1. Start the 12-Section Forensic Web Dashboard
python main.py serve --host 127.0.0.1 --port 8000

# 2. Generate self-healing sample forensic workspaces (snapshot_v1 & snapshot_v2)
python main.py init-samples --target ./sample_data

# 3. Scan a WhatsApp backup directory and generate all 8 forensic reports
python main.py scan ./sample_data/snapshot_v2 --report-dir ./forensic_reports

# 4. Compare two backup snapshots (files + SQLite messages + AI difference analysis)
python main.py compare ./sample_data/snapshot_v1 ./sample_data/snapshot_v2 --output diff.json

# 5. Preview and execute a dual-hash (SHA-256 + SHA-512) verified export
python main.py verify-export ./sample_data/snapshot_v2 ./exports msgstore_sample.db --signing-key-hex 00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff

# 6. Run CRYPT12 / CRYPT14 / CRYPT15 synthetic decryption verification fixture
python main.py test-decrypt-fixture --output-dir ./crypt15_test --format crypt15

# 7. Run ADB USB & Wireless diagnostics
python main.py adb-check
```

---

## Documentation Index

- **[Installation Guide (`INSTALLATION.md`)](INSTALLATION.md)** — Windows, Linux, macOS, Termux, Docker, and USB/Wireless ADB setup.
- **[Feature Architecture (`docs/FEATURES.md`)](docs/FEATURES.md)** — Detailed breakdown of all 12 dashboard workspaces and forensic engines.
- **[REST API Reference (`docs/API.md`)](docs/API.md)** — Complete v2.0 FastAPI endpoint documentation.
- **[Troubleshooting Guide (`docs/TROUBLESHOOTING.md`)](docs/TROUBLESHOOTING.md)** — Solutions for Termux, ADB, Scoped Storage, and SQLite WAL recovery.
- **[Security & Ethics Policy (`SECURITY.md`)](SECURITY.md)** — Forensic boundaries, threat model, and cryptographic verification design.
- **[Changelog (`CHANGELOG.md`)](CHANGELOG.md)** — Release history from v1.0.0 to v2.0.0.

---

## Ethical & Legal Notice

1. **Authorization Required:** Only analyze backups, devices, and chat exports that you own or have explicit written legal authorization to inspect.
2. **Honest Forensic Boundaries:** Deleted messages can only be recovered if they remain present in an accessible SQLite database, WAL journal (`-wal`), older backup snapshot, or exported chat archive. Permanently overwritten blocks cannot be recovered.
3. **No Encryption Bypass:** Encrypted `.crypt12`, `.crypt14`, and `.crypt15` databases cannot be decrypted without the legitimate 32-byte (64-hex) user key or 158-byte Android `key` file.
