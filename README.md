# WhatsApp Recovery Engine

**Suggested GitHub repository name:** `whatsapp-recovery-engine`

A privacy-first, offline toolkit for inspecting user-owned WhatsApp backups and accessible media. Version 2.0 adds backup snapshot comparison, safe media previews, verified media export, and an upgraded dashboard.

> This is not an official WhatsApp product. It does not bypass WhatsApp encryption, Android sandboxing, account authentication, Google Drive access controls, or device permissions. It cannot guarantee recovery of deleted messages. It only works with files you own or are authorized to inspect.

## v2.0 features

- **Backup comparison:** save scan snapshots and compare two inventories to identify added, removed, changed, and unchanged files.
- **Media preview:** view accessible image thumbnails and play supported browser media through a local-only preview endpoint.
- **Verified export:** copy selected accessible media into a separate destination, then verify source and destination SHA-256 hashes.
- **Advanced dashboard:** scan folders, view metrics, search inventory, compare snapshots, preview media, and verify exports.
- **Offline-first:** no cloud upload, telemetry, WhatsApp login, OTP handling, or remote account access.
- **Android / Termux:** scan accessible shared-storage folders.
- **ADB diagnostics:** checks authorized device connection status only.
- **PDF and JSON reports**, SQLite integrity checks, duplicate detection, Docker, tests, and GitHub Actions.
- English, Hindi, and Urdu interface labels.

## Requirements

- Python 3.10+
- Optional: Android Platform Tools (`adb`) for device connection diagnostics
- Optional: Docker for container deployment

## Install

```bash
python -m venv .venv
# Linux/macOS
source .venv/bin/activate
# Windows PowerShell: .venv\Scripts\Activate.ps1
pip install -r requirements.txt
```

## Start the dashboard

```bash
python -m wtk serve
```

Open `http://127.0.0.1:8000`.

Keep the service on localhost. Do not expose it to the public internet.

## Termux (Android)

```bash
pkg update && pkg upgrade
pkg install python git
termux-setup-storage
git clone https://github.com/YOUR-USERNAME/whatsapp-recovery-engine.git
cd whatsapp-recovery-engine
pip install -r requirements-termux.txt
python -m wtk serve
```

In the Android browser, open `http://127.0.0.1:8000`. Example accessible folder (paths vary):

```text
/data/data/com.termux/files/home/storage/shared/Android/media/com.whatsapp/WhatsApp
```

Android may restrict access to app-private data. Grant storage access only when needed.

## CLI

```bash
# Scan an accessible directory and save JSON/PDF report plus a snapshot
python -m wtk scan --source ./sample-data --output ./reports

# Compare two saved scan JSON files
python -m wtk compare ./reports/scan-*.json ./reports/another-scan.json

# Verify SQLite integrity (only unencrypted SQLite files)
python -m wtk inspect-db ./path/to/file.db

# Check ADB connection state; does not pull files
python -m wtk adb-check
```

## v2 recovery workflow

1. Scan an accessible WhatsApp media/backup folder.
2. Save the resulting scan snapshot.
3. Run another scan later and compare snapshots to identify changes.
4. Preview accessible image/audio/video files from the dashboard.
5. Select files and export them to a separate destination.
6. Review the SHA-256 verification result and keep the report.

**Removed from a later scan does not mean recoverable.** It only means a file was not present in that later inventory. It may have been moved, renamed, become inaccessible, or deleted.

## Docker

```bash
docker compose up --build
```

Open `http://127.0.0.1:8000`. Docker publishes only to host loopback and runs as a non-root user. For host files, mount only the specific directory you intend to inspect. ADB is best run on the host.

## Security model

- Scanning and preview are read-only.
- Export copies files; it never overwrites an existing destination file.
- Export verification compares SHA-256 hashes after copying.
- File preview is restricted to files in the latest scan and to supported media MIME types.
- Symlinks are skipped during scanning and export.
- No WhatsApp credentials, OTPs, tokens, or cloud account credentials are requested.
- Reports may contain private filenames and local paths; protect them.

## Tests

```bash
pip install -r requirements-dev.txt
pytest -q
```

## Limitations

- WhatsApp `.crypt*` backups are inventoried, not decrypted.
- SQLite checks apply only to ordinary unencrypted SQLite databases.
- Preview is for media that is already accessible as a file.
- Export verifies copied bytes; it does not restore a file into WhatsApp.
- Deleted chats/media may be permanently unrecoverable if no valid copy or backup exists.
