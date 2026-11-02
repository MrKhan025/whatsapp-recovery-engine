"""Self-healing synthetic sample data bootstrapper (`wtk/sample_bootstrap.py`) for v2.0.

Ensures `sample-data/snapshot_v1` and `sample-data/snapshot_v2` are always present
with valid SQLite databases (including `message_media` table for media relationship matching),
CRYPT12, CRYPT14, and CRYPT15 backup files, TXT/JSON/HTML chat exports, VCF/JSON contacts,
and media across all 8 categories.
"""

from __future__ import annotations

import json
import shutil
import sqlite3
import tempfile
from pathlib import Path

SQLITE_HEADER = b"SQLite format 3\x00"


def _is_valid_sqlite(path: Path) -> bool:
    try:
        if not path.is_file() or path.stat().st_size < 4096:
            return False
        with path.open("rb") as f:
            return f.read(16) == SQLITE_HEADER
    except OSError:
        return False


def _build_sqlite_db(target_path: Path, statements: list[str], rows_sql: str, rows: list[tuple]) -> None:
    target_path.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory() as tmpdir:
        tmp_db = Path(tmpdir) / target_path.name
        conn = sqlite3.connect(tmp_db)
        try:
            for stmt in statements:
                conn.execute(stmt)
            if rows:
                conn.executemany(rows_sql, rows)
            conn.commit()
        finally:
            conn.close()
        shutil.copyfile(tmp_db, target_path)


def ensure_sample_data(sample_root: Path | str) -> Path:
    """Create or repair synthetic, zero-PII `snapshot_v1` and `snapshot_v2` datasets."""
    root = Path(sample_root)
    v1 = root / "snapshot_v1"
    v2 = root / "snapshot_v2"

    v1_db = v1 / "Databases" / "msgstore.db"
    v2_db = v2 / "Databases" / "msgstore.db"
    v2_wa = v2 / "Databases" / "wa.db"
    marker_html = v2 / "Exports" / "chat_export.html"
    marker_vcf = v2 / "Exports" / "contacts.vcf"
    marker_c15 = v2 / "Databases" / "msgstore-2026-10-18.1.db.crypt15"

    if (
        _is_valid_sqlite(v1_db)
        and _is_valid_sqlite(v2_db)
        and _is_valid_sqlite(v2_wa)
        and marker_html.exists()
        and marker_vcf.exists()
        and marker_c15.exists()
    ):
        return root

    msg_schema = [
        "CREATE TABLE chat (_id INTEGER PRIMARY KEY, subject TEXT, created_timestamp INTEGER);",
        "CREATE TABLE jid (_id INTEGER PRIMARY KEY, raw_string TEXT);",
        "CREATE TABLE message (_id INTEGER PRIMARY KEY, sender_jid_raw_string TEXT, text_data TEXT, timestamp INTEGER, from_me INTEGER);",
        "CREATE TABLE message_media (message_row_id INTEGER PRIMARY KEY, file_path TEXT, file_size INTEGER, sha256 TEXT);",
        "INSERT INTO chat VALUES (1, 'Project Operations Team', 1730000000000);",
        "INSERT INTO jid VALUES (1, 'participant_a@s.whatsapp.net'), (2, 'participant_b@s.whatsapp.net');",
        "INSERT INTO message_media VALUES (1, 'Media/WhatsApp Images/IMG-20261001-WA0001.jpg', 47, '');",
        "INSERT INTO message_media VALUES (4, 'Media/WhatsApp Video/VID-20261010-MISSING.mp4', 102400, '');",
    ]

    # 1. Snapshot v1 SQLite DB & Media
    _build_sqlite_db(
        v1_db,
        msg_schema,
        "INSERT INTO message VALUES (?, ?, ?, ?, ?);",
        [
            (1, "participant_a@s.whatsapp.net", "Initial backup verification test started.", 1730100000000, 0),
            (2, "participant_b@s.whatsapp.net", "Historical checklist item #42 (present only in v1 snapshot).", 1730100060000, 1),
            (3, "participant_a@s.whatsapp.net", "Status report draft version 1.", 1730100120000, 0),
            (4, "participant_b@s.whatsapp.net", "Media archive checksum verified.", 1730100180000, 1),
        ],
    )
    (v1 / "Databases" / "msgstore-2026-10-01.1.db.crypt14").write_bytes(
        b"WRE_CRYPT14_PROTO_HDR".ljust(66, b"\x02") + b"\x22" * 16 + b"\x9a" * 600
    )

    (v1 / "Media" / "WhatsApp Images").mkdir(parents=True, exist_ok=True)
    (v1 / "Media" / "WhatsApp Voice Notes").mkdir(parents=True, exist_ok=True)
    jpeg_bytes = (
        b"\xff\xd8\xff\xe0\x00\x10JFIF\x00\x01\x01\x00\x00\x01\x00\x01\x00\x00"
        b"SYNTHETIC_JPEG_PAYLOAD_01\xff\xd9"
    )
    jpeg_v1_only = (
        b"\xff\xd8\xff\xe0\x00\x10JFIF\x00\x01\x01\x00\x00\x01\x00\x01\x00\x00"
        b"HISTORICAL_IMAGE_V1_ONLY\xff\xd9"
    )
    opus_bytes = b"OggS\x00\x02\x00\x00\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00OpusHead_SYNTHETIC_VOICE_NOTE"
    (v1 / "Media" / "WhatsApp Images" / "IMG-20261001-WA0001.jpg").write_bytes(jpeg_bytes)
    (v1 / "Media" / "WhatsApp Images" / "IMG-20261001-WA0002.jpg").write_bytes(jpeg_v1_only)
    (v1 / "Media" / "WhatsApp Voice Notes" / "PTT-20261001-WA0001.opus").write_bytes(opus_bytes)

    # 2. Snapshot v2 SQLite DBs & CRYPT12 / CRYPT14 / CRYPT15 Backups
    _build_sqlite_db(
        v2_db,
        msg_schema,
        "INSERT INTO message VALUES (?, ?, ?, ?, ?);",
        [
            (1, "participant_a@s.whatsapp.net", "Initial backup verification test started.", 1730100000000, 0),
            (3, "participant_a@s.whatsapp.net", "Status report draft version 2 (edited).", 1730100120000, 0),
            (4, "participant_b@s.whatsapp.net", "Media archive checksum verified.", 1730100180000, 1),
            (5, "participant_a@s.whatsapp.net", "Added new architecture specification PDF.", 1730200000000, 0),
            (6, "participant_b@s.whatsapp.net", "All offline tests green.", 1730200060000, 1),
        ],
    )
    _build_sqlite_db(
        v2_wa,
        [
            "CREATE TABLE wa_contacts (_id INTEGER PRIMARY KEY, jid TEXT, display_name TEXT);",
            "INSERT INTO wa_contacts VALUES (1, 'participant_a@s.whatsapp.net', 'Participant Alpha');",
            "INSERT INTO wa_contacts VALUES (2, 'participant_b@s.whatsapp.net', 'Participant Beta');",
        ],
        "",
        [],
    )
    (v2 / "Databases" / "msgstore-2026-10-12.1.db.crypt12").write_bytes(
        b"WRE_CRYPT12_FIXED_HDR".ljust(51, b"\x03") + b"\x22" * 16 + b"\xa5" * 640
    )
    (v2 / "Databases" / "msgstore-2026-10-15.1.db.crypt14").write_bytes(
        b"WRE_CRYPT14_PROTO_HDR".ljust(66, b"\x02") + b"\x22" * 16 + b"\xb4" * 720
    )
    (v2 / "Databases" / "msgstore-2026-10-18.1.db.crypt15").write_bytes(
        b"WRE_CRYPT15_PROTO_HDR".ljust(59, b"\x01") + b"\x22" * 16 + b"\xc7" * 760
    )
    (v2 / "Databases" / "msgstore-empty.db.crypt14").write_bytes(b"")

    # 3. Snapshot v2 Media across all 8 categories
    for sub in (
        "WhatsApp Images",
        "WhatsApp Images/Thumbs",
        "WhatsApp Video",
        "WhatsApp Voice Notes",
        "WhatsApp Audio",
        "WhatsApp Documents",
        "WhatsApp Stickers",
        "WhatsApp Animated Gifs",
    ):
        (v2 / "Media" / sub).mkdir(parents=True, exist_ok=True)

    (v2 / "Media" / "WhatsApp Images" / "IMG-20261001-WA0001.jpg").write_bytes(jpeg_bytes)
    (v2 / "Media" / "WhatsApp Images" / "IMG-20261001-WA0001-copy.jpg").write_bytes(jpeg_bytes)
    (v2 / "Media" / "WhatsApp Images" / "IMG-20261015-CORRUPT.jpg").write_bytes(
        b"\x00\x00\x00\x00BROKEN_HEADER_BYTES_TEST_FILE"
    )
    (v2 / "Media" / "WhatsApp Video" / "VID-20261015-WA0001.mp4").write_bytes(
        b"\x00\x00\x00\x18ftypmp42\x00\x00\x00\x00mp42isomSYNTHETIC_MP4_STREAM"
    )
    (v2 / "Media" / "WhatsApp Voice Notes" / "PTT-20261001-WA0001.opus").write_bytes(opus_bytes)
    (v2 / "Media" / "WhatsApp Audio" / "AUD-20261015-WA0001.wav").write_bytes(
        b"RIFF\x24\x00\x00\x00WAVEfmt \x10\x00\x00\x00\x01\x00\x01\x00"
    )
    (v2 / "Media" / "WhatsApp Documents" / "DOC-20261015-Specification.pdf").write_bytes(
        b"%PDF-1.4\n1 0 obj\n<< /Type /Catalog >>\nendobj\n%%EOF\n"
    )
    (v2 / "Media" / "WhatsApp Stickers" / "STK-20261015-WA0001.webp").write_bytes(
        b"RIFF\x1a\x00\x00\x00WEBPVP8 " + b"\x00" * 16
    )
    (v2 / "Media" / "WhatsApp Animated Gifs" / "GIF-20261015-WA0001.gif").write_bytes(
        b"GIF89a\x01\x00\x01\x00\x80\x00\x00\xff\xff\xff\x00\x00\x00!\xf9\x04\x01\x00\x00\x00\x00,\x00\x00\x00\x00\x01\x00\x01\x00\x00\x02\x02D\x01\x00;"
    )
    (v2 / "Media" / "WhatsApp Images" / "Thumbs" / "thumb-IMG-20261001.jpg").write_bytes(jpeg_bytes)

    # 4. Chat Exports (TXT, JSON, HTML) & Contacts (VCF, JSON)
    exports_dir = v2 / "Exports"
    exports_dir.mkdir(parents=True, exist_ok=True)
    (exports_dir / "WhatsApp Chat with Operations Team.txt").write_text(
        "15/10/2026, 09:15 - Participant Alpha: Welcome to the offline backup verification test.\n"
        "15/10/2026, 09:17 - Participant Beta: All media checksums and SQLite tables are ready.\n"
        "15/10/2026, 09:20 - Participant Alpha: Great, exporting forensic report now.\n",
        encoding="utf-8",
    )
    (exports_dir / "chat_export.json").write_text(
        json.dumps(
            {
                "messages": [
                    {"id": "101", "sender": "participant_a@s.whatsapp.net", "timestamp": "2026-10-15 09:15:00 UTC", "text": "JSON export test record 1"},
                    {"id": "102", "sender": "participant_b@s.whatsapp.net", "timestamp": "2026-10-15 09:16:00 UTC", "text": "JSON export test record 2"},
                ]
            },
            indent=2,
        ),
        encoding="utf-8",
    )
    (exports_dir / "chat_export.html").write_text(
        "<!doctype html><html><body>"
        "<div class='message' data-sender='Participant Alpha' data-timestamp='2026-10-15 09:15'>HTML chat export message one.</div>"
        "<div class='message' data-sender='Participant Beta' data-timestamp='2026-10-15 09:18'>HTML chat export message two.</div>"
        "</body></html>",
        encoding="utf-8",
    )
    (exports_dir / "contacts.vcf").write_text(
        "BEGIN:VCARD\nVERSION:3.0\nFN:Participant Alpha\nTEL:participant_a@s.whatsapp.net\nEND:VCARD\n"
        "BEGIN:VCARD\nVERSION:3.0\nFN:Participant Beta\nTEL:participant_b@s.whatsapp.net\nEND:VCARD\n",
        encoding="utf-8",
    )

    (root / "README.txt").write_text(
        "Synthetic, zero-PII WhatsApp backup sample dataset (snapshot_v1 and snapshot_v2).\n"
        "Contains unencrypted SQLite msgstore.db/wa.db fixtures, CRYPT12/CRYPT14/CRYPT15 headers,\n"
        "TXT/JSON/HTML chat exports, VCF contacts, and sample media across all 8 categories.\n",
        encoding="utf-8",
    )
    return root
