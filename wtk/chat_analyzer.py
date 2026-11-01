"""Advanced Chat Recovery Assistant (`wtk/chat_analyzer.py`).

Capabilities:
- Detect accessible WhatsApp SQLite chat database files (`msgstore.db`, `wa.db`, etc.)
- Identify SQLite database formats and WhatsApp schema generations (modern `message`/`chat` vs legacy `messages`/`chat_list` vs `wa_contacts`)
- Inspect database integrity using strictly read-only SQLite operations (`PRAGMA integrity_check`, `PRAGMA quick_check`, `PRAGMA query_only=ON`)
- Extract database tables, schemas, column definitions, record counts, and timestamp ranges
- Parse and preview user-provided TXT, JSON, and HTML chat exports
- Provide searchable chat export & accessible database previews
- Compare two accessible database snapshots or chat exports to identify missing (historically present), changed, and newly discovered records
- Never claims deleted messages can be recovered unless an accessible source contains them
"""

from __future__ import annotations

import hashlib
import html
import json
import re
import sqlite3
from datetime import datetime, timezone
from html.parser import HTMLParser
from pathlib import Path
from typing import Any

from .security import open_sqlite_readonly, sanitize_search_query, sha256_file, validate_safe_path

SQLITE_MAGIC = b"SQLite format 3\x00"
_SAFE_IDENT_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")

# Regex patterns for standard WhatsApp TXT chat exports across Android and iOS locales
_TXT_PATTERNS = [
    # Android format: 12/05/2025, 14:32 - Sender Name: Message text
    re.compile(
        r"^(?P<date>\d{1,4}[/\-\.]\d{1,2}[/\-\.]\d{1,4}),?\s+"
        r"(?P<time>\d{1,2}:\d{2}(?::\d{2})?(?:\s*[APap][Mm])?)\s*-\s*"
        r"(?:(?P<sender>[^:]{1,80}):\s*)?(?P<text>.*)$"
    ),
    # iOS / Bracketed format: [12/05/25, 14:32:10] Sender Name: Message text
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


def _normalize_timestamp(val: Any) -> str | None:
    """Convert epoch milliseconds, epoch seconds, or ISO strings into ISO-8601 UTC."""
    if val is None or val == "":
        return None
    if isinstance(val, (int, float)):
        num = float(val)
        if num <= 0:
            return None
        if num > 1e11:
            num = num / 1000.0
        try:
            return datetime.fromtimestamp(num, tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
        except (OSError, OverflowError, ValueError):
            return str(val)
    if isinstance(val, str):
        stripped = val.strip()
        if stripped.isdigit():
            return _normalize_timestamp(int(stripped))
        return stripped
    return str(val)


def inspect_chat_database(path: Path | str, sample_limit: int = 50) -> dict[str, Any]:
    """Perform a comprehensive, read-only forensic inspection of a SQLite database."""
    file_path = validate_safe_path(path, must_exist=True, allow_symlinks=False, reject_traversal_tokens=False)
    stat = file_path.stat()
    base_info: dict[str, Any] = {
        "name": file_path.name,
        "path": str(file_path),
        "size": stat.st_size,
        "modified": int(stat.st_mtime),
        "sha256": sha256_file(file_path) if stat.st_size > 0 else "",
        "is_sqlite": is_sqlite_file(file_path),
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
            base_info["detail"] = "Encrypted WhatsApp .crypt* backup; decryption is not performed."
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
                    cnt_row = conn.execute(f"SELECT COUNT(*) FROM {quoted_tname};").fetchone()  # nosec B608
                    row_count = int(cnt_row[0]) if cnt_row else 0
                except sqlite3.DatabaseError:
                    row_count = 0
                total_records += row_count

                cols_info = []
                try:
                    for col in conn.execute(f"PRAGMA table_info({quoted_tname});").fetchall():  # nosec B608
                        cols_info.append({
                            "name": str(col["name"]),
                            "type": str(col["type"] or "ANY"),
                            "notnull": bool(col["notnull"]),
                            "pk": bool(col["pk"]),
                        })
                except sqlite3.DatabaseError:
                    pass

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
            bounds = conn.execute(  # nosec B608
                f"SELECT MIN({quoted_ts}), MAX({quoted_ts}) FROM {quoted_table} WHERE {quoted_ts} IS NOT NULL AND {quoted_ts} != 0;"
            ).fetchone()
            if bounds:
                min_ts_str = _normalize_timestamp(bounds[0])
                max_ts_str = _normalize_timestamp(bounds[1])
        except sqlite3.DatabaseError:
            pass

    select_exprs = []
    select_exprs.append(f"{_quote_ident(id_col)} AS msg_id" if id_col else "rowid AS msg_id")
    select_exprs.append(f"{_quote_ident(sender_col)} AS sender" if sender_col else "'unknown' AS sender")
    select_exprs.append(f"{_quote_ident(text_col)} AS text_body" if text_col else "'' AS text_body")
    select_exprs.append(f"{_quote_ident(ts_col)} AS raw_ts" if ts_col else "NULL AS raw_ts")
    select_exprs.append(f"{_quote_ident(from_me_col)} AS from_me" if from_me_col else "0 AS from_me")

    order_clause = f"ORDER BY {_quote_ident(ts_col)} ASC" if ts_col else "ORDER BY msg_id ASC"
    query = f'SELECT {", ".join(select_exprs)} FROM {quoted_table} {order_clause} LIMIT ?;'  # nosec B608

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
        pass

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
    file_path = validate_safe_path(path, must_exist=True, allow_symlinks=False, reject_traversal_tokens=False)
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
        "messages": messages,
    }


def search_chat_messages(
    messages: list[dict[str, Any]],
    query: str | None = None,
    sender: str | None = None,
    limit: int = 200,
) -> dict[str, Any]:
    """Filter and search parsed chat messages by keyword and sender."""
    clean_q = sanitize_search_query(query).lower()
    clean_sender = sanitize_search_query(sender).lower()

    matched: list[dict[str, Any]] = []
    for msg in messages:
        msg_sender = str(msg.get("sender", "")).lower()
        msg_text = str(msg.get("text", "")).lower()
        if clean_sender and clean_sender not in msg_sender:
            continue
        if clean_q and clean_q not in msg_text and clean_q not in msg_sender:
            continue
        matched.append(msg)
        if len(matched) >= limit:
            break

    return {
        "query": clean_q,
        "sender_filter": clean_sender,
        "total_searched": len(messages),
        "match_count": len(matched),
        "results": matched,
    }


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
