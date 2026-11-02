"""Filesystem Scanner (`wtk/scanner.py`).

Scans user-authorized directories in strictly read-only mode, classifies media across
8 categories, reconstructs EXIF/filename timestamps, detects orphaned media, inspects
SQLite databases (plus companion `-wal` files) and encrypted CRYPT12/14/15 backups,
links chat media records, detects duplicates and corrupt headers, parses chat exports,
and runs AI-assisted local forensic analysis.
"""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .backup_analyzer import generate_backup_health_report, inspect_backup_file
from .chat_analyzer import inspect_chat_database, link_chat_media, parse_chat_export
from .estimator import estimate_recovery_readiness
from .forensic_ai import generate_forensic_findings
from .media_engine import (
    MEDIA_CATEGORIES,
    MEDIA_EXTENSIONS,
    MEDIA_MIME,
    analyze_duplicates,
    classify_media_file,
    detect_orphaned_media,
    extract_media_timestamp_metadata,
    inspect_media_integrity,
)
from .security import dual_checksum_file, has_symlink_in_chain, is_within, sha256_file

BACKUP_HINTS = ("msgstore", "crypt", "backup", "wa.db", "chatsettings", "axolotl", "stickers.db")
CHAT_EXPORT_HINTS = ("whatsapp chat", "chat_export", "chat-export", "_chat", "messages.json", "chat.html", "chat.txt")


def inspect_sqlite(path: Path | str) -> dict[str, Any]:
    """Inspect a SQLite file in read-only mode (backward-compatible entry point)."""
    p = Path(path)
    if not p.exists() or not p.is_file() or p.is_symlink():
        return {
            "supported": False,
            "integrity": "unsupported_or_encrypted",
            "detail": "File does not exist or is a symlink",
            "ok": False,
        }
    info = inspect_chat_database(p, sample_limit=50)
    return {
        "supported": info["supported"],
        "integrity": info["integrity"],
        "ok": info["ok"],
        "format_type": info.get("format_type", "unknown"),
        "wal_diagnostics": info.get("wal_diagnostics", {}),
        "tables": info.get("tables", []),
        "schemas": info.get("schemas", {}),
        "total_records": info.get("total_records", 0),
        "message_count": info.get("message_count", 0),
        "chat_count": info.get("chat_count", 0),
        "earliest_timestamp": info.get("earliest_timestamp"),
        "latest_timestamp": info.get("latest_timestamp"),
        "sample_messages": info.get("sample_messages", []),
        "duplicate_messages": info.get("duplicate_messages", {}),
        "timeline_analysis": info.get("timeline_analysis", {}),
        "group_analysis": info.get("group_analysis", {}),
        "detail": info.get("detail", ""),
    }


def _is_chat_export_file(path: Path) -> bool:
    """Detect whether a .txt, .json, or .html file is a WhatsApp chat export."""
    suffix = path.suffix.lower()
    name_lower = path.name.lower()
    if suffix not in (".txt", ".json", ".html", ".htm"):
        return False
    if any(hint in name_lower for hint in CHAT_EXPORT_HINTS):
        return True
    try:
        if path.stat().st_size > 5 * 1024 * 1024 or path.stat().st_size == 0:
            return False
        head = path.read_text(encoding="utf-8", errors="replace")[:1024]
        if suffix == ".txt" and (" - " in head or (head.startswith("[") and "]" in head)):
            return True
        if suffix == ".json" and ('"messages"' in head or ('"sender"' in head and '"text"' in head)):
            return True
        if suffix in (".html", ".htm") and ("chat" in head.lower() or "message" in head.lower()):
            return True
    except OSError:
        return False
    return False


def scan_tree(source: str | Path, max_files: int = 20000, enable_ai: bool = True) -> dict[str, Any]:
    """Perform a read-only forensic inventory of a directory tree."""
    if source is None or not str(source).strip():
        raise ValueError("Source must be an existing directory")
    raw_str = str(source).strip()
    if "\x00" in raw_str or ".." in Path(raw_str).parts:
        raise ValueError("Invalid or traversal path is not allowed")

    raw_source = Path(raw_str).expanduser()
    if raw_source.is_symlink() or has_symlink_in_chain(raw_source):
        raise ValueError("Symbolic link directories cannot be scanned")

    root = raw_source.resolve()
    if not root.exists() or not root.is_dir():
        raise ValueError("Source must be an existing directory")

    entries: list[dict[str, Any]] = []
    errors: list[str] = []
    hashes: dict[str, list[str]] = {}
    category_counts: dict[str, int] = {cat: 0 for cat in MEDIA_CATEGORIES}
    chat_databases: list[dict[str, Any]] = []
    chat_exports: list[dict[str, Any]] = []

    visited = 0
    for item in sorted(root.rglob("*")):
        if visited >= max_files:
            errors.append(f"File limit reached ({max_files})")
            break
        try:
            if item.is_symlink() or has_symlink_in_chain(item, stop_at=root):
                continue
            if not item.is_file() or not is_within(item, root):
                continue

            stat = item.stat()
            visited += 1
            suffix = item.suffix.lower()
            name_lower = item.name.lower()
            if stat.st_size > 0:
                checksums = dual_checksum_file(item)
                file_hash = checksums["sha256"]
                file_sha512 = checksums["sha512"]
            else:
                file_hash = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
                file_sha512 = (
                    "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce"
                    "47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e"
                )

            is_backup_name = (
                any(h in name_lower for h in BACKUP_HINTS)
                or suffix in (".db", ".sqlite", ".sqlite3", ".crypt12", ".crypt14", ".crypt15")
            )
            is_export = _is_chat_export_file(item)

            if is_backup_name:
                kind = "backup_candidate"
            elif is_export:
                kind = "chat_export"
            elif suffix in MEDIA_EXTENSIONS:
                kind = "media"
            else:
                kind = "other"

            record: dict[str, Any] = {
                "name": item.name,
                "path": str(item),
                "relative_path": str(item.relative_to(root)),
                "size": stat.st_size,
                "modified": int(stat.st_mtime),
                "modified_iso": datetime.fromtimestamp(int(stat.st_mtime), tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC"),
                "kind": kind,
                "sha256": file_hash,
                "sha512": file_sha512,
                "mime": MEDIA_MIME.get(suffix),
            }

            if kind == "media":
                cat = classify_media_file(item, size=stat.st_size)
                integrity = inspect_media_integrity(item)
                ts_meta = extract_media_timestamp_metadata(item, stat_mtime=int(stat.st_mtime))
                record["category"] = cat
                record["corrupt"] = integrity["corrupt"]
                record["header_valid"] = integrity["header_valid"]
                record["signature"] = integrity["signature"]
                record["corruption_reason"] = integrity["reason"]
                record["timestamp_meta"] = ts_meta
                category_counts[cat] = category_counts.get(cat, 0) + 1
                hashes.setdefault(file_hash, []).append(str(item))

            elif kind == "backup_candidate":
                b_info = inspect_backup_file(item, sha256_digest=file_hash)
                record["encrypted"] = b_info["encrypted"]
                record["encryption_format"] = b_info["encryption_format"]
                record["format_specification"] = b_info["format_specification"]
                record["suspicious"] = b_info["suspicious"]
                record["status"] = b_info["status"]
                record["warnings"] = b_info["warnings"]
                record["backup_date_in_filename"] = b_info["backup_date_in_filename"]
                if suffix in (".db", ".sqlite", ".sqlite3") or b_info.get("is_sqlite"):
                    sqlite_res = inspect_sqlite(item)
                    record["sqlite"] = sqlite_res
                    if sqlite_res.get("supported"):
                        chat_databases.append({
                            "name": item.name,
                            "path": str(item),
                            "size": stat.st_size,
                            "sha256": file_hash,
                            "sha512": file_sha512,
                            **sqlite_res,
                        })

            elif kind == "chat_export":
                try:
                    parsed_exp = parse_chat_export(item, max_messages=200)
                    record["chat_export"] = {
                        "format": parsed_exp["format"],
                        "message_count": parsed_exp["message_count"],
                        "participants": parsed_exp["participants"],
                        "earliest_timestamp": parsed_exp["earliest_timestamp"],
                        "latest_timestamp": parsed_exp["latest_timestamp"],
                    }
                    chat_exports.append(parsed_exp)
                except ValueError as exc:
                    errors.append(f"{item.name}: {exc}")

            if suffix in (".db", ".sqlite", ".sqlite3") and "sqlite" not in record:
                record["sqlite"] = inspect_sqlite(item)

            entries.append(record)
        except (OSError, PermissionError) as exc:
            errors.append(f"{item}: {str(exc)[:120]}")

    # Cross-reference SQLite message_media against scanned media entries & flag orphaned media
    linked_disk_paths: set[str] = set()
    for db in chat_databases:
        ml = link_chat_media(db["path"], entries)
        db["media_links"] = ml
        for l_item in ml.get("linked", []):
            if l_item.get("disk_path"):
                linked_disk_paths.add(str(l_item["disk_path"]))

    for e in entries:
        if e["kind"] == "media":
            e["orphaned"] = bool(chat_databases and e["path"] not in linked_disk_paths)

    media_entries = [e for e in entries if e["kind"] == "media"]
    orphaned_summary = detect_orphaned_media(entries, linked_disk_paths) if chat_databases else {
        "total_media": len(media_entries),
        "linked_count": 0,
        "orphaned_count": 0,
        "orphaned_files": [],
    }
    duplicate_analysis = analyze_duplicates(media_entries)
    backup_health = generate_backup_health_report(entries, source_root=str(root))

    report: dict[str, Any] = {
        "version": 2,
        "timestamp": datetime.now(tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC"),
        "source": str(root),
        "files_scanned": visited,
        "media_count": len(media_entries),
        "corrupt_media_count": sum(1 for e in media_entries if e.get("corrupt")),
        "orphaned_media_count": orphaned_summary["orphaned_count"],
        "timestamp_drift_count": sum(
            1 for e in media_entries if e.get("timestamp_meta", {}).get("timestamp_drift_detected")
        ),
        "category_counts": category_counts,
        "backup_candidates": sum(1 for x in entries if x["kind"] == "backup_candidate"),
        "chat_export_count": len(chat_exports),
        "duplicates": [paths for paths in hashes.values() if len(paths) > 1],
        "duplicate_analysis": duplicate_analysis,
        "orphaned_media_analysis": orphaned_summary,
        "backup_health": backup_health,
        "chat_databases": chat_databases,
        "chat_exports": chat_exports,
        "errors": errors[:100],
        "entries": entries,
    }
    report["recovery_estimate"] = estimate_recovery_readiness(report)
    report["forensic_ai"] = generate_forensic_findings(report, enabled=enable_ai)
    return report


__all__ = ["scan_tree", "inspect_sqlite", "sha256_file", "is_within", "MEDIA_MIME", "MEDIA_EXTENSIONS"]
