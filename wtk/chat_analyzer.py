"""Advanced Chat Analyzer & Timeline Reconstruction Engine (`wtk/chat_analyzer.py`).

Implements:
- Read-only SQLite database browser (`PRAGMA integrity_check`, `PRAGMA query_only=ON`, `-wal` frame inspection)
- Message search, sender search, and date-range search (`date_from`, `date_to`)
- Duplicate message detection (`detect_duplicate_messages`)
- Message timeline reconstruction & conversation gap analysis (`analyze_conversation_gaps`)
- Contact matching using user-provided VCF, CSV, or JSON contact files (`match_contacts`)
- Group conversation analysis (`analyze_group_conversations`)
- Chat export parser (TXT, JSON, HTML)
- Backup-to-backup SQLite message comparison (`compare_chat_databases`)
- Media attachment mapping (`link_chat_media`)
- Multi-format chat record export (JSON, CSV, HTML, PDF) preserving message IDs and original timestamps
"""

from __future__ import annotations

import csv
import hashlib
import html
import json
import re
import sqlite3
import struct
from datetime import datetime, timezone
from html.parser import HTMLParser
from pathlib import Path
from typing import Any

from reportlab.lib.pagesizes import A4
from reportlab.pdfgen import canvas

from .security import (
    MAX_SAFE_PARSE_BYTES,
    open_sqlite_readonly,
    sanitize_search_query,
    sha256_file,
    validate_safe_path,
)

SQLITE_MAGIC = b"SQLite format 3\x00"
WAL_MAGIC_VALUES = (0x377F0682, 0x377F0683)
WAL_HEADER_SIZE = 32
WAL_FRAME_HEADER_SIZE = 24
_SAFE_IDENT_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")

_TXT_PATTERNS = [
    re.compile(
        r"^(?P<date>\d{1,4}[/\-\.]\d{1,2}[/\-\.]\d{1,4}),?\s+"
        r"(?P<time>\d{1,2}:\d{2}(?::\d{2})?(?:\s*[APap][Mm])?)\s*-\s*"
        r"(?:(?P<sender>[^:]{1,80}):\s*)?(?P<text>.*)$"
    ),
    re.compile(
        r"^\[(?P<date>\d{1,4}[/\-\.]\d{1,2}[/\-\.]\d{1,4}),?\s+"
        r"(?P<time>\d{1,2}:\d{2}(?::\d{2})?(?:\s*[APap][Mm])?)\]\s*"
        r"(?:(?P<sender>[^:]{1,80}):\s*)?(?P<text>.*)$"
    ),
]


def _quote_ident(name: str) -> str:
    """Validate and double-quote a SQLite table or column identifier from sqlite_master."""
    if not _SAFE_IDENT_RE.match(name):
        raise ValueError(f"Unsafe SQLite identifier rejected: {name}")
    return f'"{name}"'


def is_sqlite_file(path: Path | str) -> bool:
    """Return True if the file starts with the standard 16-byte SQLite3 header."""
    try:
        p = Path(path)
        if not p.is_file() or p.is_symlink() or p.stat().st_size < 100:
            return False
        with p.open("rb") as f:
            header = f.read(16)
        return header == SQLITE_MAGIC
    except OSError:
        return False


def inspect_sqlite_wal(db_path: Path | str) -> dict[str, Any]:
    """Inspect companion `-wal` (Write-Ahead Log) and `-journal` files alongside a SQLite database in read-only mode."""
    p = Path(db_path)
    wal_path = p.with_name(p.name + "-wal")
    journal_path = p.with_name(p.name + "-journal")

    result: dict[str, Any] = {
        "wal_present": False,
        "journal_present": False,
        "wal_size": 0,
        "wal_valid_header": False,
        "uncheckpointed_frames": 0,
        "page_size": 0,
        "checkpoint_seq": 0,
    }

    if journal_path.exists() and journal_path.is_file() and not journal_path.is_symlink():
        result["journal_present"] = True
        result["journal_size"] = journal_path.stat().st_size

    if wal_path.exists() and wal_path.is_file() and not wal_path.is_symlink():
        wal_size = wal_path.stat().st_size
        result["wal_present"] = True
        result["wal_size"] = wal_size
        if wal_size >= WAL_HEADER_SIZE:
            try:
                with wal_path.open("rb") as f:
                    hdr = f.read(WAL_HEADER_SIZE)
                magic, fmt_ver, page_sz, chk_seq = struct.unpack(">IIII", hdr[:16])
                if magic in WAL_MAGIC_VALUES and page_sz >= 512:
                    result["wal_valid_header"] = True
                    result["format_version"] = fmt_ver
                    result["page_size"] = page_sz
                    result["checkpoint_seq"] = chk_seq
                    frame_bytes = page_sz + WAL_FRAME_HEADER_SIZE
                    result["uncheckpointed_frames"] = max(0, (wal_size - WAL_HEADER_SIZE) // frame_bytes)
            except OSError:
                result["wal_valid_header"] = False

    return result


def _to_epoch_seconds(val: Any) -> float | None:
    """Convert raw epoch ms/s or ISO string into epoch seconds when possible."""
    if val is None or val == "":
        return None
    if isinstance(val, (int, float)):
        num = float(val)
        if num <= 0:
            return None
        return num / 1000.0 if num > 1e11 else num
    if isinstance(val, str):
        s = val.strip()
        if s.isdigit():
            return _to_epoch_seconds(int(s))
        for fmt in ("%Y-%m-%d %H:%M:%S UTC", "%Y-%m-%d %H:%M:%S", "%Y-%m-%d %H:%M", "%d/%m/%Y %H:%M", "%d/%m/%Y, %H:%M"):
            try:
                dt = datetime.strptime(s, fmt).replace(tzinfo=timezone.utc)
                return dt.timestamp()
            except ValueError:
                continue
    return None


def _normalize_timestamp(val: Any) -> str | None:
    """Convert epoch milliseconds, epoch seconds, or ISO strings into ISO-8601 UTC."""
    sec = _to_epoch_seconds(val)
    if sec is not None:
        try:
            return datetime.fromtimestamp(sec, tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
        except (OSError, OverflowError, ValueError):
            return str(val)
    if val is None or val == "":
        return None
    return str(val).strip()


def detect_duplicate_messages(messages: list[dict[str, Any]]) -> dict[str, Any]:
    """Identify duplicate message records sharing identical sender, timestamp, and body text."""
    seen: dict[str, list[dict[str, Any]]] = {}
    for msg in messages:
        sig = hashlib.sha256(
            f"{msg.get('sender','')}|{msg.get('timestamp','')}|{msg.get('text','')}".encode("utf-8", errors="replace")
        ).hexdigest()
        seen.setdefault(sig, []).append(msg)

    dup_groups = [
        {"content_sha256": sig, "count": len(items), "messages": items}
        for sig, items in seen.items()
        if len(items) > 1
    ]
    return {
        "duplicate_group_count": len(dup_groups),
        "duplicate_message_count": sum(len(g["messages"]) - 1 for g in dup_groups),
        "groups": dup_groups,
    }


def analyze_conversation_gaps(
    messages: list[dict[str, Any]],
    gap_threshold_seconds: float = 3600.0,
) -> dict[str, Any]:
    """Reconstruct chronological message timeline and detect conversation gaps exceeding `gap_threshold_seconds`."""
    timed: list[tuple[float, dict[str, Any]]] = []
    daily_buckets: dict[str, int] = {}

    for msg in messages:
        sec = _to_epoch_seconds(msg.get("raw_timestamp") or msg.get("timestamp"))
        if sec is not None:
            timed.append((sec, msg))
            day_str = datetime.fromtimestamp(sec, tz=timezone.utc).strftime("%Y-%m-%d")
            daily_buckets[day_str] = daily_buckets.get(day_str, 0) + 1

    timed.sort(key=lambda pair: pair[0])
    gaps: list[dict[str, Any]] = []

    for idx in range(len(timed) - 1):
        t1, m1 = timed[idx]
        t2, m2 = timed[idx + 1]
        delta = t2 - t1
        if delta >= gap_threshold_seconds:
            gaps.append({
                "from_message_id": m1.get("id"),
                "to_message_id": m2.get("id"),
                "gap_start": datetime.fromtimestamp(t1, tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC"),
                "gap_end": datetime.fromtimestamp(t2, tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC"),
                "duration_seconds": int(delta),
                "duration_hours": round(delta / 3600.0, 2),
            })

    return {
        "total_timed_messages": len(timed),
        "earliest_timestamp": (
            datetime.fromtimestamp(timed[0][0], tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
            if timed else None
        ),
        "latest_timestamp": (
            datetime.fromtimestamp(timed[-1][0], tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
            if timed else None
        ),
        "gap_threshold_seconds": gap_threshold_seconds,
        "gap_count": len(gaps),
        "gaps": gaps,
        "daily_activity": [{"date": k, "count": v} for k, v in sorted(daily_buckets.items())],
        "timeline": [m for _, m in timed[:500]],
    }


def analyze_group_conversations(messages: list[dict[str, Any]], chats_table: list[dict[str, Any]] | None = None) -> dict[str, Any]:
    """Analyze participant distribution, message volume per sender, and group metadata."""
    by_sender: dict[str, int] = {}
    for m in messages:
        sender = str(m.get("sender") or "unknown")
        by_sender[sender] = by_sender.get(sender, 0) + 1

    participants = [
        {"sender": k, "message_count": v}
        for k, v in sorted(by_sender.items(), key=lambda x: x[1], reverse=True)
    ]
    return {
        "participant_count": len(participants),
        "total_messages": len(messages),
        "is_group_conversation": len(participants) > 2 or bool(chats_table),
        "groups_metadata": chats_table or [],
        "participants": participants,
    }


def parse_contacts_file(contact_path: Path | str) -> dict[str, str]:
    """Parse a user-provided `.vcf` (vCard), `.csv`, or `.json` contacts file into a JID/phone -> name map."""
    p = validate_safe_path(
        contact_path,
        must_exist=True,
        allow_symlinks=False,
        reject_traversal_tokens=False,
        max_file_size=MAX_SAFE_PARSE_BYTES,
    )
    suffix = p.suffix.lower()
    raw = p.read_text(encoding="utf-8", errors="replace")
    mapping: dict[str, str] = {}

    def _norm_key(k: str) -> str:
        digits = re.sub(r"[^\dA-Za-z@._-]", "", k.strip())
        return digits

    if suffix == ".vcf":
        current_fn = ""
        current_tels: list[str] = []
        for line in raw.splitlines():
            s = line.strip()
            if s.upper().startswith("BEGIN:VCARD"):
                current_fn = ""
                current_tels = []
            elif s.upper().startswith("FN:"):
                current_fn = s.split(":", 1)[1].strip()
            elif s.upper().startswith("TEL"):
                if ":" in s:
                    current_tels.append(s.split(":", 1)[1].strip())
            elif s.upper().startswith("END:VCARD") and current_fn:
                for tel in current_tels:
                    clean_digits = re.sub(r"\D", "", tel)
                    if clean_digits:
                        mapping[clean_digits] = current_fn
                        mapping[f"{clean_digits}@s.whatsapp.net"] = current_fn
                    mapping[_norm_key(tel)] = current_fn

    elif suffix == ".json":
        data = json.loads(raw)
        items = data if isinstance(data, list) else data.get("contacts", [])
        if isinstance(items, list):
            for item in items:
                if isinstance(item, dict):
                    name = str(item.get("name") or item.get("display_name") or "").strip()
                    jid_or_phone = str(item.get("jid") or item.get("phone") or item.get("id") or "").strip()
                    if name and jid_or_phone:
                        mapping[jid_or_phone] = name
                        digits = re.sub(r"\D", "", jid_or_phone)
                        if digits:
                            mapping[digits] = name
                            mapping[f"{digits}@s.whatsapp.net"] = name

    elif suffix == ".csv":
        reader = csv.DictReader(raw.splitlines())
        for row in reader:
            name = (row.get("name") or row.get("Name") or row.get("display_name") or "").strip()
            phone = (row.get("phone") or row.get("Phone") or row.get("jid") or "").strip()
            if name and phone:
                mapping[phone] = name
                digits = re.sub(r"\D", "", phone)
                if digits:
                    mapping[digits] = name
                    mapping[f"{digits}@s.whatsapp.net"] = name

    return mapping


def match_contacts(messages: list[dict[str, Any]], contact_map: dict[str, str]) -> list[dict[str, Any]]:
    """Enrich message records with resolved contact display names where matched."""
    enriched: list[dict[str, Any]] = []
    for m in messages:
        sender = str(m.get("sender") or "")
        digits = re.sub(r"\D", "", sender)
        resolved = contact_map.get(sender) or (contact_map.get(digits) if digits else None)
        enriched.append({
            **m,
            "contact_name": resolved or sender,
            "contact_matched": resolved is not None,
        })
    return enriched


def link_chat_media(
    db_path: Path | str,
    scanned_entries: list[dict[str, Any]],
) -> dict[str, Any]:
    """Cross-reference rows in the SQLite `message_media` table against scanned files on disk.

    Also identifies orphaned media files (media files on disk not referenced by any database row).
    """
    file_path = validate_safe_path(db_path, must_exist=True, allow_symlinks=False, reject_traversal_tokens=False)
    media_entries = [e for e in scanned_entries if e.get("kind") == "media"]
    if not is_sqlite_file(file_path):
        return {
            "supported": False,
            "linked_count": 0,
            "missing_count": 0,
            "orphaned_media_count": len(media_entries),
            "linked": [],
            "missing": [],
            "orphaned_media": [e.get("path") for e in media_entries],
        }

    by_name: dict[str, dict[str, Any]] = {}
    by_sha: dict[str, dict[str, Any]] = {}
    for entry in media_entries:
        by_name[entry.get("name", "")] = entry
        if entry.get("sha256"):
            by_sha[entry["sha256"]] = entry

    linked: list[dict[str, Any]] = []
    missing: list[dict[str, Any]] = []
    matched_disk_paths: set[str] = set()

    try:
        conn = open_sqlite_readonly(file_path)
        try:
            tables = {
                str(r["name"]).lower(): str(r["name"])
                for r in conn.execute(
                    "SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%';"
                ).fetchall()
            }
            if "message_media" not in tables:
                return {
                    "supported": True,
                    "has_media_table": False,
                    "linked_count": 0,
                    "missing_count": 0,
                    "orphaned_media_count": len(media_entries),
                    "linked": [],
                    "missing": [],
                    "orphaned_media": [e.get("path") for e in media_entries],
                }

            tname = _quote_ident(tables["message_media"])
            cols = {
                str(c["name"]).lower(): str(c["name"])
                for c in conn.execute(f"PRAGMA table_info({tname});").fetchall()  # nosec
                if _SAFE_IDENT_RE.match(str(c["name"]))
            }
            path_col = cols.get("file_path") or cols.get("media_name") or cols.get("file_name")
            sha_col = cols.get("file_hash") or cols.get("sha256")
            size_col = cols.get("file_size") or cols.get("media_size")
            msg_col = cols.get("message_row_id") or cols.get("_id")

            if path_col or sha_col:
                sel_parts = [
                    f"{_quote_ident(msg_col)} AS msg_id" if msg_col else "rowid AS msg_id",
                    f"{_quote_ident(path_col)} AS fpath" if path_col else "'' AS fpath",
                    f"{_quote_ident(sha_col)} AS fhash" if sha_col else "'' AS fhash",
                    f"{_quote_ident(size_col)} AS fsize" if size_col else "0 AS fsize",
                ]
                sel_joined = ", ".join(sel_parts)
                q = f"SELECT {sel_joined} FROM {tname} LIMIT 500;"  # nosec
                for row in conn.execute(q).fetchall():
                    raw_fp = str(row["fpath"] or "")
                    fname = Path(raw_fp).name if raw_fp else ""
                    fhash = str(row["fhash"] or "")
                    matched_entry = by_sha.get(fhash) or by_name.get(fname)
                    rec = {
                        "message_id": str(row["msg_id"]),
                        "referenced_path": raw_fp,
                        "referenced_name": fname,
                        "referenced_size": int(row["fsize"] or 0),
                    }
                    if matched_entry:
                        matched_disk_paths.add(str(matched_entry["path"]))
                        linked.append({
                            **rec,
                            "disk_path": matched_entry["path"],
                            "disk_sha256": matched_entry.get("sha256", ""),
                        })
                    else:
                        missing.append(rec)
        finally:
            conn.close()
    except (sqlite3.DatabaseError, OSError, ValueError):
        return {
            "supported": False,
            "linked_count": 0,
            "missing_count": 0,
            "orphaned_media_count": len(media_entries),
            "linked": [],
            "missing": [],
            "orphaned_media": [e.get("path") for e in media_entries],
        }

    orphaned = [e.get("path") for e in media_entries if e.get("path") not in matched_disk_paths]
    return {
        "supported": True,
        "has_media_table": True,
        "linked_count": len(linked),
        "missing_count": len(missing),
        "orphaned_media_count": len(orphaned),
        "linked": linked,
        "missing": missing,
        "orphaned_media": orphaned,
    }


def inspect_chat_database(path: Path | str, sample_limit: int = 100) -> dict[str, Any]:
    """Perform a comprehensive, read-only forensic inspection of a SQLite database."""
    file_path = validate_safe_path(path, must_exist=True, allow_symlinks=False, reject_traversal_tokens=False)
    stat = file_path.stat()
    wal_info = inspect_sqlite_wal(file_path)
    base_info: dict[str, Any] = {
        "name": file_path.name,
        "path": str(file_path),
        "size": stat.st_size,
        "modified": int(stat.st_mtime),
        "sha256": sha256_file(file_path) if stat.st_size > 0 else "",
        "is_sqlite": is_sqlite_file(file_path),
        "wal_diagnostics": wal_info,
        "supported": False,
        "ok": False,
        "integrity": "unsupported_or_encrypted",
        "format_type": "unknown",
        "tables": [],
        "schemas": {},
        "total_records": 0,
        "message_count": 0,
        "chat_count": 0,
        "contact_count": 0,
        "earliest_timestamp": None,
        "latest_timestamp": None,
        "sample_messages": [],
        "duplicate_messages": {"duplicate_group_count": 0, "duplicate_message_count": 0, "groups": []},
        "timeline_analysis": {},
        "group_analysis": {},
        "disclaimer": (
            "Read-only inspection of accessible database records only. "
            "Deleted messages cannot be recovered unless present in an accessible table or snapshot."
        ),
    }

    if stat.st_size == 0:
        base_info["integrity"] = "empty_file"
        base_info["detail"] = "File is 0 bytes"
        return base_info

    if not base_info["is_sqlite"]:
        suffix_lower = file_path.suffix.lower()
        if "crypt" in suffix_lower or "crypt" in file_path.name.lower():
            base_info["format_type"] = f"encrypted_whatsapp_backup ({suffix_lower.lstrip('.')})"
            base_info["integrity"] = "encrypted_not_sqlite"
            base_info["detail"] = "Encrypted WhatsApp .crypt* backup; decryption is not performed automatically."
        else:
            base_info["detail"] = "File does not have a valid SQLite3 header."
        return base_info

    try:
        conn = open_sqlite_readonly(file_path)
        try:
            integrity_row = conn.execute("PRAGMA integrity_check;").fetchone()
            integrity_str = str(integrity_row[0]) if integrity_row else "unknown"
            page_count_row = conn.execute("PRAGMA page_count;").fetchone()
            page_size_row = conn.execute("PRAGMA page_size;").fetchone()
            freelist_row = conn.execute("PRAGMA freelist_count;").fetchone()
            user_ver_row = conn.execute("PRAGMA user_version;").fetchone()

            base_info["supported"] = True
            base_info["integrity"] = integrity_str
            base_info["ok"] = integrity_str.lower() == "ok"
            base_info["sqlite_metadata"] = {
                "page_count": int(page_count_row[0]) if page_count_row else 0,
                "page_size": int(page_size_row[0]) if page_size_row else 0,
                "freelist_count": int(freelist_row[0]) if freelist_row else 0,
                "user_version": int(user_ver_row[0]) if user_ver_row else 0,
            }

            table_rows = conn.execute(
                "SELECT name, sql FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%' ORDER BY name;"
            ).fetchall()

            table_names: list[str] = []
            schemas: dict[str, Any] = {}
            total_records = 0

            for trow in table_rows:
                tname = str(trow["name"])
                if not _SAFE_IDENT_RE.match(tname):
                    continue
                tsql = str(trow["sql"] or "")
                table_names.append(tname)
                quoted_tname = _quote_ident(tname)
                try:
                    count_sql = f"SELECT COUNT(*) FROM {quoted_tname};"  # nosec
                    cnt_row = conn.execute(count_sql).fetchone()
                    row_count = int(cnt_row[0]) if cnt_row else 0
                except sqlite3.DatabaseError:
                    row_count = 0
                total_records += row_count

                cols_info: list[dict[str, Any]] = []
                try:
                    pragma_sql = f"PRAGMA table_info({quoted_tname});"  # nosec
                    for col in conn.execute(pragma_sql).fetchall():
                        cols_info.append({
                            "name": str(col["name"]),
                            "type": str(col["type"] or "ANY"),
                            "notnull": bool(col["notnull"]),
                            "pk": bool(col["pk"]),
                        })
                except sqlite3.DatabaseError:
                    cols_info = []

                schemas[tname] = {
                    "row_count": row_count,
                    "columns": cols_info,
                    "sql": tsql,
                }

            base_info["tables"] = table_names
            base_info["schemas"] = schemas
            base_info["total_records"] = total_records

            table_set = {t.lower() for t in table_names}
            if "message" in table_set and ("chat" in table_set or "jid" in table_set):
                base_info["format_type"] = "whatsapp_msgstore_modern"
            elif "messages" in table_set:
                base_info["format_type"] = "whatsapp_msgstore_legacy"
            elif "wa_contacts" in table_set:
                base_info["format_type"] = "whatsapp_wa_contacts"
            else:
                base_info["format_type"] = "generic_sqlite"

            messages_extracted, min_ts, max_ts, msg_count = _extract_messages_from_conn(
                conn, table_names, schemas, limit=sample_limit
            )
            base_info["sample_messages"] = messages_extracted
            base_info["message_count"] = msg_count
            base_info["earliest_timestamp"] = min_ts
            base_info["latest_timestamp"] = max_ts
            base_info["duplicate_messages"] = detect_duplicate_messages(messages_extracted)
            base_info["timeline_analysis"] = analyze_conversation_gaps(messages_extracted)
            base_info["group_analysis"] = analyze_group_conversations(messages_extracted)

            if "chat" in schemas:
                base_info["chat_count"] = schemas["chat"]["row_count"]
            elif "chat_list" in schemas:
                base_info["chat_count"] = schemas["chat_list"]["row_count"]

            if "wa_contacts" in schemas:
                base_info["contact_count"] = schemas["wa_contacts"]["row_count"]

        finally:
            conn.close()
    except (sqlite3.DatabaseError, OSError, ValueError) as exc:
        base_info["supported"] = False
        base_info["ok"] = False
        base_info["integrity"] = "corrupt_or_unreadable"
        base_info["detail"] = str(exc)[:200]

    return base_info


def _extract_messages_from_conn(
    conn: sqlite3.Connection,
    table_names: list[str],
    schemas: dict[str, Any],
    limit: int = 100,
) -> tuple[list[dict[str, Any]], str | None, str | None, int]:
    """Read accessible message records from known WhatsApp or generic message tables."""
    candidates = [t for t in table_names if t.lower() in ("message", "messages", "chat_messages")]
    if not candidates:
        return [], None, None, 0

    target_table = candidates[0]
    quoted_table = _quote_ident(target_table)
    col_names = {
        c["name"].lower(): c["name"]
        for c in schemas.get(target_table, {}).get("columns", [])
        if _SAFE_IDENT_RE.match(c["name"])
    }

    id_col = (
        col_names.get("_id")
        or col_names.get("id")
        or col_names.get("key_id")
        or col_names.get("message_id")
    )
    text_col = (
        col_names.get("text_data")
        or col_names.get("data")
        or col_names.get("text")
        or col_names.get("content")
        or col_names.get("body")
        or col_names.get("message")
    )
    ts_col = (
        col_names.get("timestamp")
        or col_names.get("sort_timestamp")
        or col_names.get("created_at")
        or col_names.get("date")
    )
    sender_col = (
        col_names.get("sender_jid_raw_string")
        or col_names.get("key_remote_jid")
        or col_names.get("remote_resource")
        or col_names.get("sender")
        or col_names.get("author")
        or col_names.get("chat_jid")
    )
    from_me_col = col_names.get("from_me") or col_names.get("key_from_me")

    total_count = schemas.get(target_table, {}).get("row_count", 0)
    min_ts_str: str | None = None
    max_ts_str: str | None = None

    if ts_col:
        quoted_ts = _quote_ident(ts_col)
        try:
            bounds_sql = f"SELECT MIN({quoted_ts}), MAX({quoted_ts}) FROM {quoted_table} WHERE {quoted_ts} IS NOT NULL AND {quoted_ts} != 0;"  # nosec
            bounds = conn.execute(bounds_sql).fetchone()
            if bounds:
                min_ts_str = _normalize_timestamp(bounds[0])
                max_ts_str = _normalize_timestamp(bounds[1])
        except sqlite3.DatabaseError:
            min_ts_str = None

    select_exprs = []
    select_exprs.append(f"{_quote_ident(id_col)} AS msg_id" if id_col else "rowid AS msg_id")
    select_exprs.append(f"{_quote_ident(sender_col)} AS sender" if sender_col else "'unknown' AS sender")
    select_exprs.append(f"{_quote_ident(text_col)} AS text_body" if text_col else "'' AS text_body")
    select_exprs.append(f"{_quote_ident(ts_col)} AS raw_ts" if ts_col else "NULL AS raw_ts")
    select_exprs.append(f"{_quote_ident(from_me_col)} AS from_me" if from_me_col else "0 AS from_me")

    order_clause = f"ORDER BY {_quote_ident(ts_col)} ASC" if ts_col else "ORDER BY msg_id ASC"
    cols_joined = ", ".join(select_exprs)
    query = f"SELECT {cols_joined} FROM {quoted_table} {order_clause} LIMIT ?;"  # nosec

    messages: list[dict[str, Any]] = []
    try:
        for row in conn.execute(query, (int(limit),)).fetchall():
            text_val = str(row["text_body"] if row["text_body"] is not None else "")
            sender_val = str(row["sender"] if row["sender"] is not None else "unknown")
            raw_ts = row["raw_ts"]
            norm_ts = _normalize_timestamp(raw_ts)
            msg_id = str(row["msg_id"])
            record_hash = hashlib.sha256(
                f"{msg_id}|{sender_val}|{raw_ts}|{text_val}".encode("utf-8", errors="replace")
            ).hexdigest()
            messages.append({
                "id": msg_id,
                "sender": sender_val,
                "from_me": bool(row["from_me"]),
                "text": text_val,
                "raw_timestamp": raw_ts,
                "timestamp": norm_ts or "",
                "sha256": record_hash,
            })
    except sqlite3.DatabaseError:
        messages = []

    return messages, min_ts_str, max_ts_str, total_count


class _ChatHTMLParser(HTMLParser):
    """Lightweight HTML parser for WhatsApp HTML chat exports."""

    def __init__(self) -> None:
        super().__init__()
        self.messages: list[dict[str, Any]] = []
        self._in_msg = False
        self._current_class = ""
        self._current_parts: list[str] = []
        self._sender = ""
        self._timestamp = ""

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        attr_map = {k.lower(): (v or "") for k, v in attrs}
        cls = attr_map.get("class", "").lower()
        if tag in ("div", "article", "li", "p", "tr") and any(
            token in cls for token in ("message", "msg", "chat-item", "bubble")
        ):
            self._in_msg = True
            self._sender = attr_map.get("data-sender", "")
            self._timestamp = attr_map.get("data-timestamp", "")
            self._current_parts = []
        self._current_class = cls

    def handle_data(self, data: str) -> None:
        text = data.strip()
        if not text:
            return
        if self._in_msg:
            if "sender" in self._current_class or "author" in self._current_class or "from" in self._current_class:
                if not self._sender:
                    self._sender = text
            elif "time" in self._current_class or "date" in self._current_class or "meta" in self._current_class:
                if not self._timestamp:
                    self._timestamp = text
            else:
                self._current_parts.append(text)

    def handle_endtag(self, tag: str) -> None:
        if self._in_msg and tag in ("div", "article", "li", "p", "tr") and self._current_parts:
            body = " ".join(self._current_parts).strip()
            idx = len(self.messages) + 1
            rec_hash = hashlib.sha256(
                f"{idx}|{self._sender}|{self._timestamp}|{body}".encode("utf-8", errors="replace")
            ).hexdigest()
            self.messages.append({
                "id": str(idx),
                "sender": self._sender or "Participant",
                "timestamp": self._timestamp or "",
                "text": body,
                "sha256": rec_hash,
            })
            self._in_msg = False
            self._sender = ""
            self._timestamp = ""
            self._current_parts = []


def parse_chat_export(path: Path | str, max_messages: int = 5000) -> dict[str, Any]:
    """Parse a user-provided TXT, JSON, or HTML WhatsApp chat export in read-only mode."""
    file_path = validate_safe_path(
        path,
        must_exist=True,
        allow_symlinks=False,
        reject_traversal_tokens=False,
        max_file_size=MAX_SAFE_PARSE_BYTES,
    )
    suffix = file_path.suffix.lower()
    if suffix not in (".txt", ".json", ".html", ".htm"):
        raise ValueError(f"Unsupported chat export format '{suffix}'. Supported: .txt, .json, .html")

    raw_text = file_path.read_text(encoding="utf-8", errors="replace")
    messages: list[dict[str, Any]] = []
    participants: set[str] = set()

    if suffix == ".txt":
        current_msg: dict[str, Any] | None = None
        for line in raw_text.splitlines():
            matched = None
            for pattern in _TXT_PATTERNS:
                m = pattern.match(line.strip())
                if m:
                    matched = m
                    break
            if matched:
                if current_msg is not None:
                    messages.append(current_msg)
                    if len(messages) >= max_messages:
                        break
                sender = (matched.group("sender") or "System").strip()
                ts = f"{matched.group('date')} {matched.group('time')}".strip()
                text_body = matched.group("text").strip()
                if sender != "System":
                    participants.add(sender)
                idx = len(messages) + 1
                current_msg = {
                    "id": str(idx),
                    "sender": sender,
                    "timestamp": ts,
                    "text": text_body,
                    "sha256": hashlib.sha256(
                        f"{idx}|{sender}|{ts}|{text_body}".encode("utf-8", errors="replace")
                    ).hexdigest(),
                }
            elif current_msg is not None and line.strip():
                current_msg["text"] += "\n" + line.strip()
                current_msg["sha256"] = hashlib.sha256(
                    f"{current_msg['id']}|{current_msg['sender']}|{current_msg['timestamp']}|{current_msg['text']}".encode(
                        "utf-8", errors="replace"
                    )
                ).hexdigest()
        if current_msg is not None and len(messages) < max_messages:
            messages.append(current_msg)

    elif suffix == ".json":
        try:
            payload = json.loads(raw_text)
        except json.JSONDecodeError as exc:
            raise ValueError(f"Invalid JSON chat export: {exc}") from exc

        raw_list = payload if isinstance(payload, list) else payload.get("messages", [])
        if not isinstance(raw_list, list):
            raise ValueError("JSON chat export must contain a list of messages")

        for idx, item in enumerate(raw_list[:max_messages], start=1):
            if not isinstance(item, dict):
                continue
            msg_id = str(item.get("id", idx))
            sender = str(item.get("sender") or item.get("from") or item.get("author") or "Participant")
            ts_raw = item.get("timestamp") or item.get("date") or item.get("time") or ""
            ts = _normalize_timestamp(ts_raw) or str(ts_raw)
            text_body = str(item.get("text") or item.get("message") or item.get("body") or "")
            participants.add(sender)
            messages.append({
                "id": msg_id,
                "sender": sender,
                "raw_timestamp": ts_raw,
                "timestamp": ts,
                "text": text_body,
                "sha256": hashlib.sha256(
                    f"{msg_id}|{sender}|{ts}|{text_body}".encode("utf-8", errors="replace")
                ).hexdigest(),
            })

    elif suffix in (".html", ".htm"):
        parser = _ChatHTMLParser()
        parser.feed(raw_text)
        messages = parser.messages[:max_messages]
        if not messages:
            stripped_lines = [
                html.unescape(re.sub(r"<[^>]+>", " ", block)).strip()
                for block in re.split(r"</(?:p|div|li|tr)>", raw_text, flags=re.IGNORECASE)
            ]
            for idx, line in enumerate((l for l in stripped_lines if l), start=1):
                if idx > max_messages:
                    break
                messages.append({
                    "id": str(idx),
                    "sender": "Participant",
                    "timestamp": "",
                    "text": line,
                    "sha256": hashlib.sha256(line.encode("utf-8", errors="replace")).hexdigest(),
                })
        for m in messages:
            if m.get("sender"):
                participants.add(m["sender"])

    timestamps = [m["timestamp"] for m in messages if m.get("timestamp")]
    return {
        "name": file_path.name,
        "path": str(file_path),
        "format": suffix.lstrip("."),
        "size": file_path.stat().st_size,
        "sha256": sha256_file(file_path),
        "message_count": len(messages),
        "participants": sorted(participants),
        "earliest_timestamp": timestamps[0] if timestamps else None,
        "latest_timestamp": timestamps[-1] if timestamps else None,
        "duplicate_messages": detect_duplicate_messages(messages),
        "timeline_analysis": analyze_conversation_gaps(messages),
        "group_analysis": analyze_group_conversations(messages),
        "messages": messages,
    }


def search_chat_messages(
    messages: list[dict[str, Any]],
    query: str | None = None,
    sender: str | None = None,
    date_from: str | None = None,
    date_to: str | None = None,
    limit: int = 200,
) -> dict[str, Any]:
    """Filter and search parsed chat messages by keyword, sender, and optional date range."""
    clean_q = sanitize_search_query(query).lower()
    clean_sender = sanitize_search_query(sender).lower()
    ts_from = _to_epoch_seconds(date_from) if date_from else None
    ts_to = _to_epoch_seconds(date_to) if date_to else None

    matched: list[dict[str, Any]] = []
    for msg in messages:
        msg_sender = str(msg.get("sender", "")).lower()
        msg_text = str(msg.get("text", "")).lower()
        if clean_sender and clean_sender not in msg_sender:
            continue
        if clean_q and clean_q not in msg_text and clean_q not in msg_sender:
            continue
        if ts_from is not None or ts_to is not None:
            msg_sec = _to_epoch_seconds(msg.get("raw_timestamp") or msg.get("timestamp"))
            if msg_sec is None:
                continue
            if ts_from is not None and msg_sec < ts_from:
                continue
            if ts_to is not None and msg_sec > ts_to:
                continue
        matched.append(msg)
        if len(matched) >= limit:
            break

    return {
        "query": clean_q,
        "sender_filter": clean_sender,
        "date_from": date_from,
        "date_to": date_to,
        "total_searched": len(messages),
        "match_count": len(matched),
        "results": matched,
    }


def export_chat_records(
    messages: list[dict[str, Any]],
    output_dir: Path | str,
    fmt: str = "json",
    filename_prefix: str = "chat-records-export",
) -> Path:
    """Export chat records to JSON, CSV, HTML, or PDF while preserving message IDs and original timestamps."""
    out = Path(output_dir)
    out.mkdir(parents=True, exist_ok=True)
    fmt_clean = fmt.lower().strip().lstrip(".")

    if fmt_clean == "json":
        target = out / f"{filename_prefix}.json"
        target.write_text(
            json.dumps({"count": len(messages), "messages": messages}, indent=2, ensure_ascii=False),
            encoding="utf-8",
        )
        return target

    if fmt_clean == "csv":
        target = out / f"{filename_prefix}.csv"
        with target.open("w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=["id", "timestamp", "raw_timestamp", "sender", "text", "sha256"])
            writer.writeheader()
            for m in messages:
                writer.writerow({
                    "id": m.get("id", ""),
                    "timestamp": m.get("timestamp", ""),
                    "raw_timestamp": m.get("raw_timestamp", ""),
                    "sender": m.get("sender", ""),
                    "text": m.get("text", ""),
                    "sha256": m.get("sha256", ""),
                })
        return target

    if fmt_clean == "html":
        target = out / f"{filename_prefix}.html"
        rows_html = [
            "<!doctype html><html lang='en'><head><meta charset='utf-8'><title>Chat Forensic Export</title>"
            "<style>body{font-family:system-ui;padding:24px;background:#0b1729;color:#eef5ff}"
            "table{width:100%;border-collapse:collapse}th,td{padding:8px 10px;border-bottom:1px solid #253c59;text-align:left}</style>"
            "</head><body><h1>WhatsApp Recovery Engine v2.0 — Chat Record Export</h1>"
            "<table><thead><tr><th>ID</th><th>Timestamp</th><th>Sender</th><th>Message</th><th>SHA-256</th></tr></thead><tbody>"
        ]
        for m in messages:
            rows_html.append(
                f"<tr class='message' data-sender='{html.escape(str(m.get('sender','')))}' data-timestamp='{html.escape(str(m.get('timestamp','')))}'>"
                f"<td>{html.escape(str(m.get('id','')))}</td>"
                f"<td>{html.escape(str(m.get('timestamp','')))}</td>"
                f"<td>{html.escape(str(m.get('sender','')))}</td>"
                f"<td>{html.escape(str(m.get('text','')))}</td>"
                f"<td><code>{html.escape(str(m.get('sha256',''))[:24])}...</code></td></tr>"
            )
        rows_html.append("</tbody></table></body></html>")
        target.write_text("\n".join(rows_html), encoding="utf-8")
        return target

    if fmt_clean == "pdf":
        target = out / f"{filename_prefix}.pdf"
        pdf = canvas.Canvas(str(target), pagesize=A4)
        _, height = A4
        y = height - 45
        pdf.setTitle("WhatsApp Recovery Engine v2.0 - Chat Export")
        pdf.drawString(36, y, f"WHATSAPP RECOVERY ENGINE v2.0 - CHAT FORENSIC EXPORT ({len(messages)} records)")
        y -= 20
        for m in messages[:200]:
            line = f"[{m.get('id','')}] {m.get('timestamp','')} | {m.get('sender','')}: {m.get('text','')}"
            pdf.drawString(36, y, line[:110])
            y -= 13
            if y < 50:
                pdf.showPage()
                y = height - 45
        pdf.save()
        return target

    raise ValueError(f"Unsupported chat export format: {fmt}")


def compare_chat_databases(
    old_db_path: Path | str,
    new_db_path: Path | str,
    max_records: int = 10000,
) -> dict[str, Any]:
    """Compare two accessible SQLite chat databases to identify missing, changed, and new messages."""
    old_info = inspect_chat_database(old_db_path, sample_limit=max_records)
    new_info = inspect_chat_database(new_db_path, sample_limit=max_records)

    if not old_info.get("supported") or not new_info.get("supported"):
        raise ValueError(
            "Both database snapshots must be accessible, unencrypted SQLite files for record-level comparison."
        )

    old_msgs = {m["id"]: m for m in old_info.get("sample_messages", [])}
    new_msgs = {m["id"]: m for m in new_info.get("sample_messages", [])}

    missing_in_new: list[dict[str, Any]] = []
    newly_discovered: list[dict[str, Any]] = []
    changed_records: list[dict[str, Any]] = []
    unchanged_count = 0

    all_ids = sorted(old_msgs.keys() | new_msgs.keys(), key=lambda x: (len(str(x)), str(x)))
    for mid in all_ids:
        if mid in old_msgs and mid not in new_msgs:
            missing_in_new.append(old_msgs[mid])
        elif mid not in old_msgs and mid in new_msgs:
            newly_discovered.append(new_msgs[mid])
        else:
            a, b = old_msgs[mid], new_msgs[mid]
            if a.get("text") != b.get("text") or a.get("sender") != b.get("sender") or a.get("timestamp") != b.get("timestamp"):
                changed_records.append({"id": mid, "old": a, "new": b})
            else:
                unchanged_count += 1

    return {
        "old_database": {"name": old_info["name"], "path": old_info["path"], "sha256": old_info["sha256"]},
        "new_database": {"name": new_info["name"], "path": new_info["path"], "sha256": new_info["sha256"]},
        "summary": {
            "missing_in_new": len(missing_in_new),
            "changed_records": len(changed_records),
            "newly_discovered": len(newly_discovered),
            "unchanged": unchanged_count,
        },
        "missing_in_new": missing_in_new[:500],
        "changed_records": changed_records[:500],
        "newly_discovered": newly_discovered[:500],
        "disclaimer": (
            "Comparison reflects differences between two accessible SQLite snapshots. "
            "Records listed under 'missing_in_new' are recoverable only because they exist in the older snapshot."
        ),
    }
