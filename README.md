<div align="center">

# WhatsApp Recovery Engine — v2.0

### Professional Digital Forensics, Backup Intelligence, Media Recovery & Evidence Verification Platform

[![Version](https://img.shields.io/badge/version-2.0.0-10b981?style=for-the-badge)](CHANGELOG.md)
[![Python](https://img.shields.io/badge/python-3.10%2B-3b82f6?style=for-the-badge&logo=python&logoColor=white)](pyproject.toml)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.110%2B-059669?style=for-the-badge&logo=fastapi&logoColor=white)](https://fastapi.tiangolo.com/)
[![Security](https://img.shields.io/badge/Offline--First-Read--Only%20Forensics-f59e0b?style=for-the-badge)](SECURITY.md)
[![License: MIT](https://img.shields.io/badge/License-MIT-6366f1?style=for-the-badge)](LICENSE)

**Supported Platforms:** Android Termux • Windows 10/11 • Linux • macOS • USB & Wireless ADB • Docker

</div>

![Dashboard Preview](docs/screenshots/dashboard-preview.svg)

---

## Table of Contents

1. [Overview & v2.0 Core Subsystems](#1-overview--v20-core-subsystems)
2. [Android (Termux) — Complete Step-by-Step Commands](#2-android-termux--complete-step-by-step-commands)
3. [Windows 10 / 11 — Complete Step-by-Step Commands](#3-windows-10--11--complete-step-by-step-commands)
4. [Linux (Ubuntu / Debian / Kali / Fedora) — Complete Step-by-Step Commands](#4-linux-ubuntu--debian--kali--fedora--complete-step-by-step-commands)
5. [macOS — Complete Step-by-Step Commands](#5-macos--complete-step-by-step-commands)
6. [USB ADB & Wireless ADB — Complete Step-by-Step Commands](#6-usb-adb--wireless-adb--complete-step-by-step-commands)
7. [Docker & Docker Compose — Step-by-Step Commands](#7-docker--docker-compose--step-by-step-commands)
8. [Complete CLI Reference (Every Single Command)](#8-complete-cli-reference-every-single-command)
9. [Complete Troubleshooting Commands (Termux, Windows, Linux, macOS, ADB, GitHub)](#9-complete-troubleshooting-commands-termux-windows-linux-macos-adb-github)
10. [Security, Privacy & Forensic Boundaries](#10-security-privacy--forensic-boundaries)

---

## 1. Overview & v2.0 Core Subsystems

**WhatsApp Recovery Engine v2.0** is an offline-first digital forensics, backup intelligence, media recovery, and cryptographic verification platform for inspecting user-authorized WhatsApp (`com.whatsapp`) and WhatsApp Business (`com.whatsapp.w4b`) backups and chat exports.

| Subsystem | Key Capabilities |
| :--- | :--- |
| **1. Advanced Recovery Engine** | Multi-backup snapshot diffing, SQLite DB comparison, missing/newly discovered/duplicate message detection, timeline reconstruction, conversation gap analysis, dry-run operation preview, and dual-hash (`SHA-256` + `SHA-512`) post-copy verification. |
| **2. Advanced Media Recovery** | Categorizes all 8 media types (**Photos, Videos, Voice Notes, Audio, Documents, Stickers, GIFs, Thumbnails**), detects **orphaned media**, links media to SQLite `message_media` rows, extracts EXIF/filename dates, validates magic-byte signatures, generates thumbnails, and safely exports verified copies. |
| **3. Backup Intelligence** | Format-specific `.crypt12` (fixed 67B header), `.crypt14` (protobuf header), and `.crypt15` (E2EE protobuf header + `HKDF-SHA256` key derivation) validation, anomaly detection, and user-authorized key decryption with synthetic test fixtures. |
| **4. Advanced Chat Analyzer** | Read-only SQLite browser (`mode=ro&immutable=1` + `PRAGMA query_only=ON`), companion `-wal` frame inspection, keyword/sender/date search, `.vcf`/`.csv`/`.json` contact matching, group analytics, and **JSON, CSV, HTML, and PDF chat exports**. |
| **5. Android & ADB Module** | USB ADB & Android 11+ Wireless ADB (`adb pair` / `adb connect`) diagnostics, storage availability checks, WhatsApp & WhatsApp Business folder discovery, and post-pull `SHA-256` transfer verification. |
| **6. AI-Assisted Forensic Analysis** | Optional **100% local offline heuristic engine** summarizing conversations, identifying missing date ranges, explaining backup diffs and corruption indicators, and separating `verified_findings` from `inferred_observations`. |
| **7. Professional Evidence Management** | Unique Evidence IDs (`EVID-...`), `SHA-256` + `SHA-512` checksums, append-only chain-of-custody records, signed (`cryptographically_signed_hmac_sha256`) vs checksum-verified (`checksum_verified_only`) manifests, PDF certificates, and Evidence ZIP bundles. |
| **8. 12-Section Web Dashboard** | Responsive Dark/Light UI featuring **Overview, Recovery Workspace, Chat Analyzer, Backup Intelligence, Media Recovery, Timeline Explorer, ADB Device Manager, Evidence Manager, Integrity Verification, Forensic Reports, Security Center, and Settings** with English, Hindi (`हिन्दी`), and Urdu (`اردو` RTL) localization. |

---

## 2. Android (Termux) — Complete Step-by-Step Commands

> **CRITICAL TERMUX RULES:**
> 1. Install Termux from **F-Droid** or **GitHub Releases** (never from the outdated Google Play Store build).
> 2. **NEVER** run `pip install --upgrade pip` in Termux (Termux forbids upgrading `pip` outside `pkg`).
> 3. **ALWAYS** use `--extra-index-url https://termux-user-repository.github.io/pypi/` so `pydantic-core` installs from prebuilt Android wheels instead of compiling Rust from source.

### Step 2.1: Update Termux & Install System Packages
```bash
pkg update -y && pkg upgrade -y
pkg install -y tur-repo
pkg install -y python git libjpeg-turbo freetype android-tools python-cryptography
```

### Step 2.2: Grant Android Shared Storage Permission
```bash
termux-setup-storage
```
*(Tap **Allow** on the Android popup so Termux can read `/sdcard` and `~/storage/shared`.)*

### Step 2.3: Clone the Repository (Fresh Install)
```bash
cd ~
git clone https://github.com/MrKhan025/whatsapp-recovery-engine.git
cd ~/whatsapp-recovery-engine
```

### Step 2.4: If You Already Cloned Earlier — Pull the Latest v2.0 Files (So `main.py` Appears)
```bash
cd ~/whatsapp-recovery-engine
git fetch --all
git reset --hard origin/main
ls -la main.py
```
*(If your v2.0 changes are on branch `feature/v2-advanced-recovery`, run `git checkout feature/v2-advanced-recovery && git pull origin feature/v2-advanced-recovery`.)*

### Step 2.5: Install Python Dependencies in Termux
```bash
cd ~/whatsapp-recovery-engine
pip install --extra-index-url https://termux-user-repository.github.io/pypi/ -r requirements-termux.txt
```

### Step 2.6: Generate Sample Forensic Data & Start the v2.0 Web Dashboard
```bash
cd ~/whatsapp-recovery-engine
python main.py init-sample
python main.py serve --host 127.0.0.1 --port 8000
```
*(Alternative module command if needed: `python -m wtk serve --host 127.0.0.1 --port 8000`)*

Now open Chrome or Firefox on your Android phone and visit:
```text
http://127.0.0.1:8000
```

### Step 2.7: One-Command Automated Termux Launcher
```bash
cd ~/whatsapp-recovery-engine
bash scripts/termux-install.sh
```

### Step 2.8: Scan Your Real Android WhatsApp or WhatsApp Business Folder in Termux
```bash
# Scan Android 11+ WhatsApp folder:
python main.py scan --source ~/storage/shared/Android/media/com.whatsapp/WhatsApp --output ./reports

# Scan Android 11+ WhatsApp Business folder:
python main.py scan --source "~/storage/shared/Android/media/com.whatsapp.w4b/WhatsApp Business" --output ./reports_w4b

# Scan Android 9 / 10 Legacy WhatsApp folder:
python main.py scan --source ~/storage/shared/WhatsApp --output ./reports_legacy
```

### Step 2.9: Run Automated Tests & Security Checks in Termux
```bash
cd ~/whatsapp-recovery-engine

# Install test & security tools in Termux using prebuilt wheels:
pip install --extra-index-url https://termux-user-repository.github.io/pypi/ pytest httpx bandit

# 1. Initialize sample snapshots
python main.py init-sample

# 2. Run all 19 unit & integration tests (via pytest or built-in unittest)
PYTHONPATH=. python -m pytest -v
PYTHONPATH=. python -m unittest discover -s tests -v

# 3. Run Bandit static security scan
bandit -q -ll -s B101,B608 -r wtk

# 4. Run built-in offline dependency & security posture audit (No Rust build required)
python main.py security-audit
```

---

## 3. Windows 10 / 11 — Complete Step-by-Step Commands

### Step 3.1: Clone the Repository & Enter the Folder (PowerShell)
```powershell
git clone https://github.com/MrKhan025/whatsapp-recovery-engine.git
cd whatsapp-recovery-engine
```

### Step 3.2: Pull Latest Updates (If Already Cloned)
```powershell
cd whatsapp-recovery-engine
git fetch --all
git pull origin main
```

### Step 3.3: Create & Activate a Python Virtual Environment

**In PowerShell:**
```powershell
python -m venv .venv
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope Process
.venv\Scripts\Activate.ps1
```

**In Command Prompt (`cmd.exe`):**
```cmd
python -m venv .venv
.venv\Scripts\activate.bat
```

### Step 3.4: Install Dependencies & Start the v2.0 Dashboard
```powershell
pip install --upgrade pip setuptools wheel
pip install -r requirements.txt
python main.py init-sample
python main.py serve --host 127.0.0.1 --port 8000
```
*(Or simply double-click **`start.bat`** in Windows File Explorer.)*

Open your browser at:
```text
http://127.0.0.1:8000
```

### Step 3.5: Run All Automated Tests & Security Audits on Windows
```powershell
pip install -r requirements-dev.txt
python main.py init-sample
$env:PYTHONPATH="."
python -m pytest -v
python -m unittest discover -s tests -v
bandit -q -ll -s B101,B608 -r wtk
ruff check wtk/ main.py
pip-audit -r requirements.txt
python main.py security-audit
```

---

## 4. Linux (Ubuntu / Debian / Kali / Fedora) — Complete Step-by-Step Commands

### Step 4.1: Install Python, Virtualenv, Git & ADB

**Ubuntu / Debian / Kali / Linux Mint:**
```bash
sudo apt-get update
sudo apt-get install -y python3 python3-venv python3-pip git android-tools-adb
```

**Fedora / RHEL:**
```bash
sudo dnf install -y python3 python3-pip git android-tools
```

**Arch Linux / Manjaro:**
```bash
sudo pacman -S --noconfirm python python-pip git android-tools
```

### Step 4.2: Clone the Repository & Create Virtual Environment
```bash
git clone https://github.com/MrKhan025/whatsapp-recovery-engine.git
cd whatsapp-recovery-engine

python3 -m venv .venv
source .venv/bin/activate
pip install --upgrade pip setuptools wheel
pip install -r requirements.txt
```

### Step 4.3: Initialize Sample Data & Launch the Dashboard
```bash
python3 main.py init-sample
python3 main.py serve --host 127.0.0.1 --port 8000
```
Open **`http://127.0.0.1:8000`** in your browser.

### Step 4.4: Run All Automated Tests & Security Audits on Linux
```bash
source .venv/bin/activate
pip install -r requirements-dev.txt
python3 main.py init-sample
PYTHONPATH=. pytest -v
PYTHONPATH=. python3 -m unittest discover -s tests -v
bandit -q -ll -s B101,B608 -r wtk
ruff check wtk/ main.py
pip-audit -r requirements.txt
python3 main.py security-audit
```

---

## 5. macOS — Complete Step-by-Step Commands

### Step 5.1: Install Python 3.10+, Git & ADB via Homebrew
```bash
brew update
brew install python@3.11 git android-platform-tools
```

### Step 5.2: Clone the Repository & Set Up Virtual Environment
```bash
git clone https://github.com/MrKhan025/whatsapp-recovery-engine.git
cd whatsapp-recovery-engine

python3 -m venv .venv
source .venv/bin/activate
pip install --upgrade pip setuptools wheel
pip install -r requirements.txt
```

### Step 5.3: Initialize Sample Data & Start the Dashboard
```bash
python3 main.py init-sample
python3 main.py serve --host 127.0.0.1 --port 8000
```
Open **`http://127.0.0.1:8000`** in Safari or Chrome.

### Step 5.4: Run All Automated Tests & Security Audits on macOS
```bash
source .venv/bin/activate
pip install -r requirements-dev.txt
python3 main.py init-sample
PYTHONPATH=. pytest -v
PYTHONPATH=. python3 -m unittest discover -s tests -v
bandit -q -ll -s B101,B608 -r wtk
ruff check wtk/ main.py
pip-audit -r requirements.txt
python3 main.py security-audit
```

---

## 6. USB ADB & Wireless ADB — Complete Step-by-Step Commands

### 6.1: Connect via USB ADB (Windows / Linux / macOS)
1. On your Android phone, open **Settings → About Phone** and tap **Build Number** 7 times.
2. Open **Settings → System → Developer Options** and enable **USB Debugging**.
3. Connect your phone via USB cable and run:
```bash
adb start-server
adb devices -l
```
4. Tap **Allow USB debugging** on your phone screen so the status changes from `unauthorized` to `device`.
5. Run the built-in ADB diagnostic check:
```bash
python main.py adb-check
```

### 6.2: Connect via Wireless ADB (Android 11+ — On PC or Directly Inside Termux)
1. Open **Settings → Developer Options → Wireless debugging** and toggle it **ON**.
2. Tap **Pair device with pairing code** to display the **IP address**, **Pairing Port**, and **6-digit Wi-Fi pairing code**.
   *(Tip for Termux on the same phone: place Settings and Termux in **Split-Screen mode** so the pairing dialog stays open.)*
3. Run the pairing and connection commands:
```bash
# Pair using the Pairing Port and 6-digit code shown in the popup:
adb pair <PHONE_IP>:<PAIRING_PORT> <6_DIGIT_PAIRING_CODE>

# Connect using the main Connect Port shown on the Wireless Debugging screen:
adb connect <PHONE_IP>:<CONNECT_PORT>

# Verify connection:
adb devices -l
python main.py adb-check
```

### 6.3: Pull Authorized WhatsApp Backups via ADB & Scan Them
```bash
# Create an isolated local folder for the pulled backup
mkdir -p ./phone_whatsapp_backup

# Pull WhatsApp Databases & Media (Android 11+)
adb pull "/sdcard/Android/media/com.whatsapp/WhatsApp/Databases" ./phone_whatsapp_backup/Databases
adb pull "/sdcard/Android/media/com.whatsapp/WhatsApp/Media" ./phone_whatsapp_backup/Media

# Pull WhatsApp Business Databases & Media (Android 11+ if applicable)
adb pull "/sdcard/Android/media/com.whatsapp.w4b/WhatsApp Business/Databases" ./phone_whatsapp_backup/Business_Databases

# Scan the pulled backup and generate all 8 forensic reports
python main.py scan --source ./phone_whatsapp_backup --output ./phone_reports
```

---

## 7. Docker & Docker Compose — Step-by-Step Commands

```bash
# Build and start using Docker Compose
docker compose up --build -d

# View container logs
docker compose logs -f

# Stop container
docker compose down

# Or build and run directly with Docker CLI
docker build -t whatsapp-recovery-engine:2.0 .
docker run --rm -p 127.0.0.1:8000:8000 whatsapp-recovery-engine:2.0
```
Open **`http://127.0.0.1:8000`**.

---

## 8. Complete CLI Reference (Every Single Command)

You can invoke every command with either `python main.py <command>` or `python -m wtk <command>`:

```bash
# 1. Show CLI help and all available subcommands
python main.py --help

# 2. Generate synthetic zero-PII sample workspaces (snapshot_v1 & snapshot_v2)
python main.py init-sample
python main.py init-samples --target ./sample-data

# 3. Start the 12-Section Forensic Web Dashboard on localhost:8000
python main.py serve --host 127.0.0.1 --port 8000

# 4. Scan a backup directory read-only and generate all 8 forensic reports
python main.py scan --source ./sample-data/snapshot_v2 --output ./reports

# 5. Compare two saved scan snapshot JSON files
python main.py compare ./reports/scan-old.json ./reports/scan-new.json

# 6. Inspect an accessible SQLite chat database (read-only + WAL inspection)
python main.py inspect-db ./sample-data/snapshot_v2/Databases/msgstore.db

# 7. Compare two SQLite chat databases to find missing, changed, and new messages
python main.py compare-db ./sample-data/snapshot_v1/Databases/msgstore.db ./sample-data/snapshot_v2/Databases/msgstore.db

# 8. Parse a WhatsApp chat export (.txt, .json, or .html)
python main.py parse-export "./sample-data/snapshot_v2/Exports/WhatsApp Chat with Operations Team.txt"
python main.py parse-export ./sample-data/snapshot_v2/Exports/chat_export.json
python main.py parse-export ./sample-data/snapshot_v2/Exports/chat_export.html

# 9. Preview a recovery export (dry-run without copying files)
python main.py verify-export --source ./sample-data/snapshot_v2 --destination ./verified_out --preview ./sample-data/snapshot_v2/Media/WhatsApp\ Images/IMG-20261001-WA0001.jpg

# 10. Execute a safe recovery export with dual SHA-256 and SHA-512 verification
python main.py verify-export --source ./sample-data/snapshot_v2 --destination ./verified_out ./sample-data/snapshot_v2/Media/WhatsApp\ Images/IMG-20261001-WA0001.jpg

# 11. Check connected USB/Wireless ADB devices and Android storage guidance
python main.py adb-check

# 12. Run local security posture and dependency audit
python main.py security-audit
```

---

## 9. Complete Troubleshooting Commands (Termux, Windows, Linux, macOS, ADB, GitHub)

### 9.1: Termux — `can't open file '.../main.py': [Errno 2] No such file or directory`
- **Cause:** Your `~/whatsapp-recovery-engine` directory in Termux is an older clone created before `main.py` was added, or you are outside the repository folder.
- **Fix Commands:**
```bash
cd ~/whatsapp-recovery-engine
git fetch --all
git reset --hard origin/main
ls -la main.py
python main.py serve --host 127.0.0.1 --port 8000
```
*(Or re-clone fresh from scratch:)*
```bash
cd ~
rm -rf ~/whatsapp-recovery-engine
git clone https://github.com/MrKhan025/whatsapp-recovery-engine.git
cd ~/whatsapp-recovery-engine
bash scripts/termux-install.sh
```

### 9.2: Termux — `ERROR: Installing pip is forbidden, this will break the python-pip package`
- **Cause:** Running `pip install --upgrade pip` is forbidden on Termux.
- **Fix Commands (if `pip` is broken or missing in Termux):**
```bash
pkg update -y
pkg reinstall -y python python-pip
pip --version
```

### 9.3: Termux — `Checking for Rust toolchain... error: metadata-generation-failed -> pydantic-core`
- **Cause:** Running `pip install -r requirements.txt` or `pip-audit -r requirements.txt` without Termux's prebuilt wheel index triggers a source build of `pydantic-core`.
- **Fix Commands:**
```bash
# Enable Termux User Repository and install prebuilt Android packages:
pkg install -y tur-repo python-cryptography
pip install --extra-index-url https://termux-user-repository.github.io/pypi/ -r requirements-termux.txt

# Run the built-in security audit (never spawns a temporary Rust build):
python main.py security-audit

# Or if running pip-audit in Termux, run it WITHOUT '-r requirements.txt' so it audits installed packages:
pip-audit
```

### 9.4: Termux — Permission Denied When Scanning `/sdcard` or `~/storage/shared`
- **Fix Commands:**
```bash
termux-setup-storage
ls -la ~/storage/shared/Android/media/com.whatsapp/WhatsApp
```

### 9.5: Windows PowerShell — `Activate.ps1 cannot be loaded because running scripts is disabled`
- **Fix Command:**
```powershell
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope Process
.venv\Scripts\Activate.ps1
```

### 9.6: Port `8000` Already in Use (`[Errno 98] Address already in use`)
- **Fix Commands:**
```bash
# Run on port 8080 instead:
python main.py serve --host 127.0.0.1 --port 8080

# Or find and stop the existing process on port 8000 (Linux / macOS / Termux):
pkill -f "uvicorn" || pkill -f "main.py"
```
**On Windows PowerShell:**
```powershell
netstat -ano | findstr :8000
taskkill /PID <PID_NUMBER> /F
```

### 9.7: ADB — Device Shows `unauthorized` or `no devices/emulators found`
- **Fix Commands:**
```bash
adb kill-server
adb start-server
adb devices -l
```
Then unlock your phone screen, unplug and reconnect the USB cable, and tap **Allow USB debugging**.

### 9.8: GitHub Web Upload — `That path contains a malformed path component`
- **Cause:** Trying to create or upload a `.git/` folder (such as `.git/COMMIT_EDITMSG`) in the GitHub web editor.
- **Fix:** Never upload the `.git` folder via the GitHub website — GitHub manages `.git` automatically. Only upload project folders (`wtk/`, `web/`, `tests/`, `docs/`, `scripts/`, `.github/workflows/ci.yml`, and root files).

---

## 10. Security, Privacy & Forensic Boundaries

1. **100% Local & Offline-First:** Binds to `127.0.0.1` by default with zero telemetry and zero automatic cloud uploads.
2. **Read-Only Source Guarantee:** Opens SQLite databases using `file:<path>?mode=ro&immutable=1` and `PRAGMA query_only = ON;` so original evidence is never modified.
3. **Dual Hash Verification:** Every exported artifact and evidence record is verified with both `SHA-256` and `SHA-512`.
4. **Honest Forensic Boundaries:** Deleted messages can only be recovered if they remain in an accessible SQLite database, `-wal` journal, older backup snapshot, or chat export. Encrypted `.crypt12`, `.crypt14`, and `.crypt15` files are never brute-forced and require a legitimate user-authorized key.
