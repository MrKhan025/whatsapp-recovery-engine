<div align="center">

# 🛡️ WhatsApp Recovery Engine — v1.0 (Advanced Edition)

**A Professional, Offline-First WhatsApp Backup Analysis, Chat Export Inspection, Media Discovery, Cryptographic SHA-256 Verification & Forensic Reporting Platform**

[![Version](https://img.shields.io/badge/version-1.0.0-0d9f76?style=for-the-badge)](https://github.com/MrKhan025/whatsapp-recovery-engine)
[![Python](https://img.shields.io/badge/Python-3.10%2B-3776AB?style=for-the-badge&logo=python&logoColor=white)](https://www.python.org/)
[![FastAPI](https://img.shields.io/badge/FastAPI-009688?style=for-the-badge&logo=fastapi&logoColor=white)](https://fastapi.tiangolo.com/)
[![SQLite](https://img.shields.io/badge/SQLite-Read--Only%20%2B%20WAL-003B57?style=for-the-badge&logo=sqlite&logoColor=white)](https://www.sqlite.org/)
[![Platform](https://img.shields.io/badge/Platform-Android%20%7C%20Termux%20%7C%20Linux%20%7C%20Windows-25D366?style=for-the-badge)](https://github.com/MrKhan025/whatsapp-recovery-engine)
[![Security](https://img.shields.io/badge/Privacy-100%25%20Offline%20%26%20Local-success?style=for-the-badge)](./SECURITY.md)

<br>

![WhatsApp Recovery Engine v1.0 Dashboard Preview](./docs/screenshots/dashboard-preview.svg)

</div>

> **Forensic & Ethical Notice:** This project is an independent, read-only diagnostic and recovery-assistance platform for inspecting **files you own or are explicitly authorized to analyze**. It **never** bypasses WhatsApp encryption, **never** decrypts `.crypt12/.crypt14/.crypt15` files without a user-owned key/official restore flow, **never** bypasses OTPs, device locks, or Android Scoped Storage restrictions, and **never** claims guaranteed recovery of permanently deleted data.

## ✨ Key Capabilities & Features (v1.0)

| Module | Core Capabilities | Forensic Safety & Verification |
| :--- | :--- | :--- |
| **1. Advanced Chat Recovery Assistant** (`wtk/chat_analyzer.py`) | Detects `msgstore.db` & `wa.db`; inspects companion **SQLite Write-Ahead Log (`-wal`)** uncheckpointed frames; cross-references `message_media` attachments against disk (`link_chat_media`); parses **TXT, JSON & HTML** chat exports; compares two SQLite snapshots to locate missing (historical), modified, and new messages. | Opens databases strictly with `mode=ro&immutable=1` and `PRAGMA query_only = ON`; runs `PRAGMA integrity_check`. |
| **2. Advanced Media Recovery Engine** (`wtk/media_engine.py`) | Organizes accessible media into **8 categories**: Photos, Videos, Voice Notes, Audio, Documents, Stickers, GIFs & Thumbnails; **reconstructs original dates from EXIF `DateTimeOriginal` headers and WhatsApp filenames (`IMG-YYYYMMDD-WAxxxx`)** to detect OS timestamp drift; inline browser preview for images, videos & voice notes. | Validates magic-byte headers (`JPEG`, `PNG`, `GIF`, `WEBP`, `PDF`, `OggS`, `MP4`, `WAV`, `ZIP`) to flag corrupt or `0 B` files. |
| **3. Smart Backup Analyzer & User-Key Decryptor** (`wtk/backup_analyzer.py`, `wtk/decryptor.py`) | Discovers `.crypt12`, `.crypt14`, `.crypt15` & SQLite backups; inspects header structure; supports **strictly local AES-256-GCM + `zlib` decryption when the user supplies their own 32-byte hex key or 158-byte `key` file**; compares **2 or more** snapshots chronologically. | Never brute-forces or guesses keys; flags empty (`0 B`) or suspiciously small backups and produces a comprehensive **Backup Health Report**. |
| **4. Recovery Success Estimator** (`wtk/estimator.py`) | Evaluates accessible DBs, SQLite integrity, intact media, backup health, corruption indicators, duplicate redundancy & snapshot diffs. | Reports qualitative readiness (**Low / Medium / High**) with evidence, missing requirements & next steps (no fake `%` claims). |
| **5. Cryptographic Verification Engine** (`wtk/verification.py`) | Exports selected files to a separate destination outside the source directory and generates a signed **Recovery Verification Certificate**. | Computes **pre-copy and post-copy SHA-256 checksums**, prevents accidental overwrites, and blocks symlinks/traversal. |
| **6. Multi-Format Forensic Reporting & Bundle** (`wtk/reports.py`) | Generates **8 downloadable outputs**: PDF Report, JSON Scan Report, CSV Inventory, Backup Comparison, Media Recovery, DB Health, Verification Certificate & **One-Click Forensic Evidence Bundle (`.zip` with `SHA256SUMS.txt`)**. | Every report includes UTC timestamps, file counts, SHA-256 digests, anomaly warnings, and explicit technical limitations. |
| **7. Responsive 8-Tab Web Dashboard** (`web/`) | **Overview, Chat Analyzer, Backup Analyzer, Media Recovery, Duplicate Finder, Recovery Verification, Recovery Reports & Settings**. | Built-in **Dark & Light Themes** plus **English, Hindi (हिन्दी) & Urdu (اردو RTL)** multi-language support. |

## 🚀 Step-by-Step Guide to Execute This Repository

Choose your platform below (**Android Termux**, **Windows**, **Linux / macOS**, or **Docker**) and follow the numbered steps in order.

### Platform 1: Execute on Android via Termux (Step-by-Step)

> **Important Note for Termux Users:** Never run `pip install --upgrade pip` on Termux (Termux forbids upgrading `pip` via `pip` and will show an error). Always use `--extra-index-url https://termux-user-repository.github.io/pypi/` so `pydantic-core` installs from prebuilt Android binary wheels in 1 second without needing Rust or `maturin`.

#### Step 1: Install Required System Packages in Termux
Open Termux and run:
```bash
pkg update -y && pkg upgrade -y
pkg install -y python git libjpeg-turbo freetype
```

#### Step 2: Grant Android Shared Storage Permission
Run the command below and tap **"Allow"** on the Android popup so Termux can read your shared storage folders:
```bash
termux-setup-storage
```

#### Step 3: Clone the Repository & Enter the Folder
```bash
cd ~
rm -rf whatsapp-recovery-engine
git clone https://github.com/MrKhan025/whatsapp-recovery-engine.git
cd whatsapp-recovery-engine
```

#### Step 4: Install Python Dependencies (Using Prebuilt Termux Wheels)
```bash
pip install --extra-index-url https://termux-user-repository.github.io/pypi/ -r requirements-termux.txt
pip install uvicorn
```
*(Or simply run our one-line setup script: `bash scripts/termux-install.sh`)*

#### Step 5: Start the Web Dashboard Server
You can start the server using **any** of these three commands:
```bash
python main.py
# OR:
python -m wtk serve --host 127.0.0.1 --port 8000
```

#### Step 6: Open the Dashboard in Your Android Browser
1. Leave Termux running in the background.
2. Open **Chrome** or **Firefox** on your phone and go to:
   ```text
   http://127.0.0.1:8000
   ```
3. To test immediately with sample data, tap **"Load Sample Snapshot (v2)"** and tap **"Scan Folder"**.
4. To scan your real WhatsApp folder on your phone, paste one of these paths into the scan box and tap **"Scan Folder"**:
   * **Android 11, 12, 13, 14, 15+ Path:**
     ```text
     /storage/emulated/0/Android/media/com.whatsapp/WhatsApp
     ```
   * **Termux Shared Storage Alias Path:**
     ```text
     /data/data/com.termux/files/home/storage/shared/Android/media/com.whatsapp/WhatsApp
     ```
   * **Android 10 & Earlier Path:**
     ```text
     /storage/emulated/0/WhatsApp
     ```

### Platform 2: Execute on Windows 10 / 11 (Step-by-Step)

#### Method A: One-Click Windows Launcher (`start.bat`)
1. Download and install [Python 3.10+](https://www.python.org/downloads/windows/) (check **"Add python.exe to PATH"** during installation).
2. Clone or extract `whatsapp-recovery-engine` to a folder on your PC.
3. Double-click **`start.bat`** inside the folder. It will automatically create `.venv`, install all requirements, and start the dashboard at `http://127.0.0.1:8000`.

#### Method B: Manual PowerShell Step-by-Step
Open **PowerShell** and run:
```powershell
# Step 1: Clone the repository and enter the directory
git clone https://github.com/MrKhan025/whatsapp-recovery-engine.git
cd whatsapp-recovery-engine

# Step 2: Create and activate a virtual environment
python -m venv .venv
.venv\Scripts\Activate.ps1

# Step 3: Install dependencies
pip install --upgrade pip
pip install -r requirements.txt

# Step 4: Initialize sample datasets and start the server
python main.py init-sample
python main.py
```
Open **`http://127.0.0.1:8000`** in Microsoft Edge, Chrome, or Firefox.

### Platform 3: Execute on Linux & macOS (Step-by-Step)

```bash
# Step 1: Clone the repository
git clone https://github.com/MrKhan025/whatsapp-recovery-engine.git
cd whatsapp-recovery-engine

# Step 2: Create and activate a virtual environment
python3 -m venv .venv
source .venv/bin/activate

# Step 3: Install dependencies
pip install --upgrade pip
pip install -r requirements.txt

# Step 4: Initialize sample datasets and start the server
python3 main.py init-sample
python3 main.py
```
Open **`http://127.0.0.1:8000`** in your browser.

### Platform 4: Execute with Docker (Step-by-Step)

```bash
git clone https://github.com/MrKhan025/whatsapp-recovery-engine.git
cd whatsapp-recovery-engine
docker compose up --build
```
Open **`http://127.0.0.1:8000`**. The container runs as a non-root user (`uid 10001`) with a read-only root filesystem and binds strictly to loopback (`127.0.0.1`).

## 📱 Step-by-Step Guide to Connect with ADB (USB & Wireless)

WhatsApp Recovery Engine includes read-only ADB connection diagnostics (`wtk/adb.py`) to detect authorized Android devices, inspect device properties (`manufacturer`, `model`, `android_version`, `sdk_int`), and help you inspect authorized shared WhatsApp folders.

### Scenario A: Connect an Android Phone to a PC (Windows / Linux / macOS) via USB Cable

#### Step 1: Enable Developer Options & USB Debugging on Your Android Phone
1. Open your phone's **Settings** → **About Phone** (or **About Device**).
2. Locate **Build Number** (on Xiaomi/MIUI, tap **OS Version**; on Oppo/Realme, tap **Version** → **Build Number**) and tap it **7 times** rapidly until you see *"You are now a developer!"*.
3. Go back to **Settings** → **System** (or **Additional Settings**) → **Developer Options**.
4. Toggle **Developer Options** ON, scroll down, and enable **USB Debugging**.

#### Step 2: Install ADB (`android-platform-tools`) on Your Computer
* **Windows (via Winget in PowerShell):**
  ```powershell
  winget install Google.PlatformTools
  ```
* **Ubuntu / Debian / Kali Linux:**
  ```bash
  sudo apt update && sudo apt install -y adb
  ```
* **macOS (via Homebrew):**
  ```bash
  brew install android-platform-tools
  ```

#### Step 3: Connect via USB & Authorize Your Computer
1. Connect your Android phone to your computer using a **data-capable USB cable** (set USB mode on the phone notification to **File Transfer / MTP**).
2. Run this command in your computer terminal:
   ```bash
   adb devices -l
   ```
3. Look at your phone screen: a popup titled **"Allow USB debugging?"** will appear.
4. Check **"Always allow from this computer"** and tap **"Allow"**.
5. Run `adb devices -l` again and confirm the status changed from `unauthorized` to **`device`**:
   ```text
   List of devices attached
   R58M42XXXXX    device product:dm3q model:SM_S918B device:dm3q transport_id:1
   ```

#### Step 4: Verify ADB Connection in WhatsApp Recovery Engine
Run the CLI diagnostic check or check the **Settings** tab in the dashboard:
```bash
python main.py adb-check
```
You will see your connected device's serial, authorization state (`"authorized": true`), manufacturer, model, and Android version.

#### Step 5: Copy Your Authorized Shared WhatsApp Folder to Your PC for Inspection (Optional)
If you want to analyze your phone's accessible WhatsApp shared folder on your PC:
```bash
mkdir -p ./my-phone-whatsapp
# For Android 11+:
adb pull /sdcard/Android/media/com.whatsapp/WhatsApp ./my-phone-whatsapp
# For Android 10 and earlier:
# adb pull /sdcard/WhatsApp ./my-phone-whatsapp
```
Then scan `./my-phone-whatsapp/WhatsApp` in the dashboard at `http://127.0.0.1:8000` or via CLI:
```bash
python main.py scan --source ./my-phone-whatsapp/WhatsApp --output ./reports
```

### Scenario B: Connect ADB Wirelessly Inside Termux on the Same Phone (Android 11+ — No PC Required!)

If you are running Termux directly on an Android 11+ phone and want ADB connected locally without a computer:

#### Step 1: Install `android-tools` in Termux
```bash
pkg install -y android-tools
```

#### Step 2: Open Developer Options in Split-Screen Mode
1. Connect your phone to a Wi-Fi network (or enable Wi-Fi).
2. Go to **Settings** → **Developer Options** → enable **Wireless Debugging** and tap the text **Wireless Debugging** to open its submenu.
3. Put **Settings** and **Termux** in **Split-Screen view** (important: if Settings closes in the background, Android resets the pairing code!).

#### Step 3: Pair & Connect ADB in Termux
1. In the Wireless Debugging screen, tap **"Pair device with pairing code"**. Note the **IP address & Port** (e.g., `192.168.1.5:39451`) and the **6-digit Wi-Fi pairing code**.
2. In the Termux half of the screen, run:
   ```bash
   adb pair 127.0.0.1:<PAIRING_PORT>
   ```
   *(Replace `<PAIRING_PORT>` with the 5-digit port shown in the popup, then type the 6-digit code and press Enter.)*
3. Next, look at the main **Wireless Debugging** screen under **"IP address & Port"** (note: this port is different from the pairing port!) and run:
   ```bash
   adb connect 127.0.0.1:<CONNECT_PORT>
   ```
4. Verify your device is connected and authorized:
   ```bash
   adb devices -l
   python main.py adb-check
   ```

### Scenario C: ADB Troubleshooting Quick Reference

| ADB State / Symptom | Cause | Solution |
| :--- | :--- | :--- |
| **`unauthorized`** | You haven't tapped **"Allow"** on the phone's USB debugging popup yet. | Unlock your phone screen, run `adb kill-server && adb devices`, and tap **"Allow"** on the prompt. |
| **`offline`** | ADB daemon connection timed out or wireless port changed. | Unplug/replug the USB cable (or run `adb reconnect`), or re-run `adb connect 127.0.0.1:<PORT>`. |
| **Empty list under `List of devices attached`** | Charge-only USB cable or USB mode set to Charging Only. | Switch to a data-transfer USB cable and set the Android USB notification to **File Transfer (MTP)**. |
| **`ADB not installed or not on PATH`** | `adb` binary is not installed. | In Termux, run `pkg install -y android-tools`. On Ubuntu/Debian, run `sudo apt install -y adb`. |

## 🖥️ Step-by-Step Walkthrough of the 8 Dashboard Tabs (`http://127.0.0.1:8000`)

Once the server is running and you open `http://127.0.0.1:8000`:

1. **Overview Tab:** Enter your folder path (or click **"Load Sample Snapshot (v2)"**) and click **"Scan Folder"**. View total scanned files, media counts across all 8 categories, the **Recovery Readiness Assessment (Low / Medium / High)**, supporting forensic evidence, missing requirements, and scan history.
2. **Chat Analyzer Tab:** View accessible SQLite databases (`msgstore.db`, `wa.db`), check `PRAGMA integrity_check` status and companion `-wal` uncheckpointed frame counts, search messages by keyword or sender across SQLite and **TXT/JSON/HTML** exports, and compare two SQLite databases (`snapshot_v1/Databases/msgstore.db` vs `snapshot_v2/Databases/msgstore.db`) to find missing historical messages.
3. **Backup Analyzer Tab:** Inspect `.crypt12`, `.crypt14`, and `.crypt15` backups by size, timestamp, embedded date, and SHA-256 without modifying them, spot `0 B` or suspicious backups, and compare two or more saved scan snapshots.
4. **Media Recovery Tab:** Filter discovered media by category (**Photos, Videos, Voice Notes, Audio, Documents, Stickers, GIFs, Thumbnails**), byte size, filename, or corruption status. Click **"Preview"** to view images, play videos, or listen to voice notes inline.
5. **Duplicate Finder Tab:** Inspect cryptographic SHA-256 duplicate groups and see exact reclaimable storage in bytes.
6. **Recovery Verification Tab:** Select media files in the Media Recovery tab, enter a safe destination path outside the scanned source (e.g., `/tmp/verified-export`), and click **"Export Selected & Verify SHA-256"** to verify pre-copy and post-copy hashes and issue a **Verification Certificate**.
7. **Recovery Reports Tab:** Download any of the **8 forensic outputs** with one click:
   * Comprehensive Forensic PDF Report (`recovery-report.pdf`)
   * Full JSON Scan Inventory (`recovery-scan.json`)
   * CSV File Inventory (`file-inventory.csv`)
   * Backup Comparison Report (`backup-comparison-report.json`)
   * Media Recovery Report (`media-recovery-report.json`)
   * Database Health Report (`database-health-report.json`)
   * Recovery Verification Certificate (`verification-certificate.pdf` & `.json`)
   * **Complete Forensic Evidence Bundle (`forensic-evidence-bundle.zip` with `SHA256SUMS.txt`)**
8. **Settings Tab:** Toggle **Dark / Light Theme**, switch interface language between **English, Hindi (हिन्दी), and Urdu (اردو RTL)**, refresh **ADB Diagnostics**, and view the live **Security & Privacy Audit**.

## ⌨️ Complete CLI Command Reference

You can run every tool directly from the terminal using either `python main.py <command>` or `python -m wtk <command>`:

```bash
# Start the local web dashboard at http://127.0.0.1:8000 (default when no command is given)
python main.py
python main.py serve --host 127.0.0.1 --port 8000

# Initialize synthetic zero-PII sample datasets (snapshot_v1 and snapshot_v2)
python main.py init-sample

# Scan a directory in read-only mode and generate all reports + Forensic Bundle (.zip)
python main.py scan --source ./sample-data/snapshot_v2 --output ./reports

# Compare two saved scan snapshot JSON files
python main.py compare ./reports/scan-old.json ./reports/scan-new.json

# Inspect an accessible SQLite chat database and companion -wal file in read-only mode
python main.py inspect-db ./sample-data/snapshot_v2/Databases/msgstore.db

# Compare two accessible SQLite chat databases at the message record level
python main.py compare-db ./sample-data/snapshot_v1/Databases/msgstore.db ./sample-data/snapshot_v2/Databases/msgstore.db

# Parse a user-provided TXT, JSON, or HTML WhatsApp chat export
python main.py parse-export ./sample-data/snapshot_v2/Exports/chat_export.json

# Copy and verify files with pre-copy and post-copy SHA-256 checksums
python main.py verify-export --source ./sample-data/snapshot_v2 --destination ./verified-out ./sample-data/snapshot_v2/Media/WhatsApp\ Images/IMG-20261001-WA0001.jpg

# Check ADB device connection status and Android storage guidance
python main.py adb-check

# Run local security and dependency posture audit
python main.py security-audit
```

## 🧪 Automated Testing & Security Verification

```bash
pip install -r requirements-dev.txt
python main.py init-sample
python -m pytest -v
bandit -q -ll -r wtk
pip-audit -r requirements.txt
```
