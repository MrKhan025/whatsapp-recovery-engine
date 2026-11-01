"""Smart Backup Analyzer (`wtk/backup_analyzer.py`).

Capabilities:
- Discover accessible WhatsApp backup files (`.crypt12`, `.crypt14`, `.crypt15`, `.db`, `msgstore*`, `wa.db*`)
- Identify encrypted `.crypt*` backups without decrypting them
- Detect backup file sizes, timestamps, embedded filename dates, and SHA-256 hashes
- Detect suspiciously small or empty backup files
- Compare two or more backup snapshots chronologically
- Inspect accessible SQLite databases
- Generate a comprehensive Backup Health Report
"""

from __future__ import annotations

import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .chat_analyzer import inspect_chat_database, is_sqlite_file

CRYPT_PATTERN = re.compile(r"\.crypt(?P<ver>\d{1,2})$", re.IGNORECASE)
DATE_IN_NAME_PATTERN = re.compile(r"(?P<date>20\d{2}-\d{2}-\d{2})")

# Minimum reasonable byte threshold for a non-empty encrypted WhatsApp backup header + payload
MIN_HEALTHY_CRYPT_BYTES = 256
MIN_HEALTHY_SQLITE_BYTES = 1024


def inspect_backup_file(path: Path | str, sha256_digest: str | None = None) -> dict[str, Any]:
    """Analyze a single backup or database candidate without decrypting `.crypt*` files."""
    p = Path(path)
    stat = p.stat()
    size = stat.st_size
    mtime = int(stat.st_mtime)
    name_lower = p.name.lower()

    crypt_match = CRYPT_PATTERN.search(name_lower)
    date_match = DATE_IN_NAME_PATTERN.search(p.name)
    backup_date_hint = date_match.group("date") if date_match else None

    is_encrypted = bool(crypt_match or ".crypt" in name_lower)
    crypt_version = f"crypt{crypt_match.group('ver')}" if crypt_match else (
        "crypt_unknown" if ".crypt" in name_lower else None
    )

    suspicious = False
    warnings: list[str] = []
    status = "healthy"

    if size == 0:
        suspicious = True
        status = "empty"
        warnings.append("Backup file is empty (0 bytes).")
    elif is_encrypted and size < MIN_HEALTHY_CRYPT_BYTES:
        suspicious = True
        status = "suspiciously_small"
        warnings.append(
            f"Encrypted backup ({size} bytes) is smaller than minimum expected header/payload size ({MIN_HEALTHY_CRYPT_BYTES} bytes)."
        )

    sqlite_info: dict[str, Any] | None = None
    if not is_encrypted and (p.suffix.lower() in (".db", ".sqlite", ".sqlite3") or is_sqlite_file(p)):
        sqlite_info = inspect_chat_database(p, sample_limit=25)
        if not sqlite_info.get("ok"):
            suspicious = True
            status = "corrupt_or_unreadable"
            warnings.append(f"SQLite integrity check failed: {sqlite_info.get('integrity')}")
        elif size < MIN_HEALTHY_SQLITE_BYTES:
            suspicious = True
            status = "suspiciously_small"
            warnings.append(f"SQLite database is unusually small ({size} bytes).")

    return {
        "name": p.name,
        "path": str(p),
        "size": size,
        "modified": mtime,
        "modified_iso": datetime.fromtimestamp(mtime, tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC"),
        "backup_date_in_filename": backup_date_hint,
        "sha256": sha256_digest or (sqlite_info.get("sha256") if sqlite_info else ""),
        "encrypted": is_encrypted,
        "encryption_format": crypt_version,
        "decryption_attempted": False,
        "is_sqlite": bool(sqlite_info and sqlite_info.get("is_sqlite")),
        "sqlite": sqlite_info,
        "suspicious": suspicious,
        "status": status,
        "warnings": warnings,
    }


def generate_backup_health_report(entries: list[dict[str, Any]], source_root: str = "") -> dict[str, Any]:
    """Generate a structured Backup Health Report from scanned inventory entries."""
    backup_entries = [
        e for e in entries
        if e.get("kind") == "backup_candidate" or e.get("sqlite") is not None
    ]

    encrypted_backups = [e for e in backup_entries if e.get("encrypted")]
    sqlite_backups = [e for e in backup_entries if e.get("sqlite") and e["sqlite"].get("supported")]
    healthy_sqlite = [e for e in sqlite_backups if e["sqlite"].get("ok")]
    corrupt_sqlite = [e for e in sqlite_backups if not e["sqlite"].get("ok")]
    suspicious_files = [e for e in backup_entries if e.get("suspicious") or e.get("size", 0) == 0]

    warnings: list[str] = []
    if not backup_entries:
        health_status = "No Backups Found"
        warnings.append("No WhatsApp database or .crypt* backup files were found in the scanned directory.")
    elif corrupt_sqlite or (suspicious_files and len(suspicious_files) == len(backup_entries)):
        health_status = "Critical"
    elif suspicious_files:
        health_status = "Warning"
    else:
        health_status = "Healthy"

    for item in suspicious_files:
        for w in item.get("warnings", []):
            warnings.append(f"{item['name']}: {w}")
        if not item.get("warnings") and item.get("size", 0) == 0:
            warnings.append(f"{item['name']}: Empty backup file (0 bytes).")

    for item in corrupt_sqlite:
        warnings.append(f"{item['name']}: SQLite integrity check returned '{item['sqlite'].get('integrity')}'.")

    timestamps = [int(e.get("modified", 0)) for e in backup_entries if e.get("modified")]
    newest_ts = max(timestamps) if timestamps else None
    oldest_ts = min(timestamps) if timestamps else None

    return {
        "source": source_root,
        "generated_at": datetime.now(tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC"),
        "health_status": health_status,
        "total_backup_files": len(backup_entries),
        "encrypted_crypt_count": len(encrypted_backups),
        "accessible_sqlite_count": len(sqlite_backups),
        "healthy_sqlite_count": len(healthy_sqlite),
        "corrupt_sqlite_count": len(corrupt_sqlite),
        "suspicious_or_empty_count": len(suspicious_files),
        "oldest_backup_timestamp": (
            datetime.fromtimestamp(oldest_ts, tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
            if oldest_ts else None
        ),
        "newest_backup_timestamp": (
            datetime.fromtimestamp(newest_ts, tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
            if newest_ts else None
        ),
        "backups": backup_entries,
        "warnings": warnings,
        "limitations": [
            "Encrypted WhatsApp backups (.crypt12/.crypt14/.crypt15) are cataloged by metadata and SHA-256 only; they are never decrypted.",
            "Restoring encrypted .crypt* backups requires the official WhatsApp app with the registered phone number or the user's own legitimate 64-byte key.",
            "SQLite integrity checks verify structural page/B-tree consistency but cannot recover purged pages unless an older snapshot exists.",
        ],
    }
