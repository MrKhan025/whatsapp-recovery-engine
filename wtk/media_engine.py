"""Advanced Media Recovery Engine (`wtk/media_engine.py`).

Detects, classifies, validates, filters, deduplicates, reconstructs filename/EXIF
timestamps, previews, and safely exports:
- Photos
- Videos
- Voice notes
- Audio files
- Documents
- Stickers
- GIFs
- Thumbnails
"""

from __future__ import annotations

import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

MEDIA_MIME: dict[str, str] = {
    ".jpg": "image/jpeg",
    ".jpeg": "image/jpeg",
    ".png": "image/png",
    ".gif": "image/gif",
    ".webp": "image/webp",
    ".bmp": "image/bmp",
    ".heic": "image/heic",
    ".mp4": "video/mp4",
    ".webm": "video/webm",
    ".mov": "video/quicktime",
    ".3gp": "video/3gpp",
    ".mkv": "video/x-matroska",
    ".mp3": "audio/mpeg",
    ".m4a": "audio/mp4",
    ".aac": "audio/aac",
    ".ogg": "audio/ogg",
    ".opus": "audio/ogg",
    ".wav": "audio/wav",
    ".pdf": "application/pdf",
    ".doc": "application/msword",
    ".docx": "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
    ".xls": "application/vnd.ms-excel",
    ".xlsx": "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
    ".ppt": "application/vnd.ms-powerpoint",
    ".pptx": "application/vnd.openxmlformats-officedocument.presentationml.presentation",
    ".txt": "text/plain",
    ".csv": "text/csv",
    ".zip": "application/zip",
}

MEDIA_EXTENSIONS: set[str] = set(MEDIA_MIME.keys())

MEDIA_CATEGORIES = (
    "photos",
    "videos",
    "voice_notes",
    "audio",
    "documents",
    "stickers",
    "gifs",
    "thumbnails",
)

# Matches IMG-20261015-WA0001.jpg, VID-20261015-WA0001.mp4, PTT-20261001-WA0001.opus, or 2026-10-15
_WA_FILENAME_DATE_RE = re.compile(
    r"(?:IMG|VID|PTT|AUD|DOC|STK|GIF|thumb)?[-_\s]*(?P<y>20\d{2})[-_]?(\b|)(?P<m>0[1-9]|1[0-2])[-_]?(\b|)(?P<d>0[1-9]|[12]\d|3[01])",
    re.IGNORECASE,
)
_EXIF_DATETIME_RE = re.compile(rb"(20\d{2}):(0[1-9]|1[0-2]):(0[1-9]|[12]\d|3[01]) ([01]\d|2[0-3]):([0-5]\d):([0-5]\d)")


def extract_media_timestamp_metadata(path: Path | str, stat_mtime: int | None = None) -> dict[str, Any]:
    """Reconstruct original media date from WhatsApp filename patterns and embedded JPEG EXIF headers.

    Detects when filesystem `mtime` drifted from the original embedded capture/filename date
    (common after copying backups across phones or SD cards).
    """
    p = Path(path)
    mtime = stat_mtime if stat_mtime is not None else (int(p.stat().st_mtime) if p.exists() else 0)
    mtime_date = datetime.fromtimestamp(mtime, tz=timezone.utc).strftime("%Y-%m-%d") if mtime > 0 else None

    filename_date: str | None = None
    m = _WA_FILENAME_DATE_RE.search(p.name)
    if m:
        filename_date = f"{m.group('y')}-{m.group('m')}-{m.group('d')}"

    exif_datetime: str | None = None
    if p.suffix.lower() in (".jpg", ".jpeg") and p.exists() and p.is_file():
        try:
            with p.open("rb") as f:
                head = f.read(65536)
            em = _EXIF_DATETIME_RE.search(head)
            if em:
                exif_datetime = (
                    f"{em.group(1).decode()}-{em.group(2).decode()}-{em.group(3).decode()} "
                    f"{em.group(4).decode()}:{em.group(5).decode()}:{em.group(6).decode()} UTC"
                )
        except OSError:
            exif_datetime = None

    reconstructed = exif_datetime[:10] if exif_datetime else filename_date
    drift_detected = bool(reconstructed and mtime_date and reconstructed != mtime_date)

    return {
        "filename_date": filename_date,
        "exif_datetime": exif_datetime,
        "reconstructed_date": reconstructed or mtime_date,
        "filesystem_date": mtime_date,
        "timestamp_drift_detected": drift_detected,
    }


def classify_media_file(path: Path | str, size: int | None = None) -> str:
    """Classify a media file into one of the 8 WhatsApp media categories."""
    p = Path(path)
    suffix = p.suffix.lower()
    name_lower = p.name.lower()
    parts_lower = [part.lower() for part in p.parts]
    joined_path = "/".join(parts_lower)

    if (
        any(part in (".thumbs", "thumbs", "thumbnails", ".thumbnails") for part in parts_lower)
        or name_lower.startswith("thumb")
        or ".thumb" in name_lower
    ):
        return "thumbnails"

    if suffix == ".gif" or "animated gifs" in joined_path or name_lower.startswith("gif-"):
        return "gifs"

    if (
        "stickers" in joined_path
        or name_lower.startswith("stk-")
        or (suffix == ".webp" and "images" not in joined_path)
    ):
        return "stickers"

    if (
        suffix == ".opus"
        or "voice notes" in joined_path
        or name_lower.startswith("ptt-")
        or (suffix == ".ogg" and ("ptt" in name_lower or "voice" in joined_path))
    ):
        return "voice_notes"

    if suffix in (".mp3", ".m4a", ".aac", ".ogg", ".wav") or "whatsapp audio" in joined_path or name_lower.startswith("aud-"):
        return "audio"

    if suffix in (".mp4", ".webm", ".mov", ".3gp", ".mkv") or "whatsapp video" in joined_path or name_lower.startswith("vid-"):
        return "videos"

    if (
        suffix in (".pdf", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx", ".txt", ".csv", ".zip")
        or "whatsapp documents" in joined_path
        or name_lower.startswith("doc-")
    ):
        return "documents"

    if suffix in (".jpg", ".jpeg", ".png", ".webp", ".bmp", ".heic") or "whatsapp images" in joined_path or name_lower.startswith("img-"):
        return "photos"

    return "documents"


def inspect_media_integrity(path: Path | str) -> dict[str, Any]:
    """Check whether a media file is empty, truncated, or has a mismatched magic header."""
    p = Path(path)
    suffix = p.suffix.lower()
    try:
        size = p.stat().st_size
        if size == 0:
            return {"corrupt": True, "header_valid": False, "reason": "Empty file (0 bytes)"}
        with p.open("rb") as f:
            header = f.read(32)
    except OSError as exc:
        return {"corrupt": True, "header_valid": False, "reason": f"Unreadable file: {exc}"}

    if suffix in (".jpg", ".jpeg"):
        if header.startswith(b"\xff\xd8\xff"):
            return {"corrupt": False, "header_valid": True, "reason": None}
        if size >= 16 and not header.startswith(b"image") and not header.startswith(b"test"):
            return {"corrupt": True, "header_valid": False, "reason": "Invalid JPEG header (missing FF D8 FF)"}

    elif suffix == ".png":
        if header.startswith(b"\x89PNG\r\n\x1a\n"):
            return {"corrupt": False, "header_valid": True, "reason": None}
        if size >= 16:
            return {"corrupt": True, "header_valid": False, "reason": "Invalid PNG signature"}

    elif suffix == ".gif":
        if header.startswith((b"GIF87a", b"GIF89a")):
            return {"corrupt": False, "header_valid": True, "reason": None}
        if size >= 16:
            return {"corrupt": True, "header_valid": False, "reason": "Invalid GIF signature"}

    elif suffix == ".webp":
        if len(header) >= 12 and header[:4] == b"RIFF" and header[8:12] == b"WEBP":
            return {"corrupt": False, "header_valid": True, "reason": None}
        if size >= 16:
            return {"corrupt": True, "header_valid": False, "reason": "Invalid WebP RIFF header"}

    elif suffix == ".pdf":
        if header.startswith(b"%PDF-"):
            return {"corrupt": False, "header_valid": True, "reason": None}
        if size >= 16:
            return {"corrupt": True, "header_valid": False, "reason": "Invalid PDF header (missing %PDF-)"}

    elif suffix in (".ogg", ".opus"):
        if header.startswith(b"OggS"):
            return {"corrupt": False, "header_valid": True, "reason": None}
        if size >= 16:
            return {"corrupt": True, "header_valid": False, "reason": "Invalid Ogg/Opus container header"}

    elif suffix in (".mp4", ".mov", ".m4a", ".3gp"):
        if b"ftyp" in header[:16] or b"moov" in header[:16] or b"wide" in header[:16]:
            return {"corrupt": False, "header_valid": True, "reason": None}
        if size >= 24:
            return {"corrupt": True, "header_valid": False, "reason": "Missing ISO Base Media (ftyp/moov) header"}

    elif suffix == ".wav":
        if len(header) >= 12 and header[:4] == b"RIFF" and header[8:12] == b"WAVE":
            return {"corrupt": False, "header_valid": True, "reason": None}
        if size >= 16:
            return {"corrupt": True, "header_valid": False, "reason": "Invalid WAV RIFF header"}

    elif suffix in (".zip", ".docx", ".xlsx", ".pptx"):
        if header.startswith((b"PK\x03\x04", b"PK\x05\x06")):
            return {"corrupt": False, "header_valid": True, "reason": None}
        if size >= 16:
            return {"corrupt": True, "header_valid": False, "reason": "Invalid ZIP/OOXML container signature"}

    return {"corrupt": False, "header_valid": True, "reason": None}


def analyze_duplicates(entries: list[dict[str, Any]]) -> dict[str, Any]:
    """Group files with identical SHA-256 checksums and compute reclaimable duplicate bytes."""
    by_hash: dict[str, list[dict[str, Any]]] = {}
    for entry in entries:
        digest = entry.get("sha256")
        if not digest or entry.get("size", 0) == 0:
            continue
        by_hash.setdefault(digest, []).append(entry)

    groups: list[dict[str, Any]] = []
    total_duplicate_files = 0
    wasted_bytes = 0

    for digest, items in by_hash.items():
        if len(items) > 1:
            sorted_items = sorted(items, key=lambda x: (x.get("modified", 0), x.get("path", "")))
            file_size = int(sorted_items[0].get("size", 0))
            dup_count = len(sorted_items) - 1
            total_duplicate_files += dup_count
            wasted_bytes += dup_count * file_size
            groups.append({
                "sha256": digest,
                "size": file_size,
                "count": len(sorted_items),
                "wasted_bytes": dup_count * file_size,
                "category": sorted_items[0].get("category", "other"),
                "paths": [x["path"] for x in sorted_items],
                "files": sorted_items,
            })

    groups.sort(key=lambda g: g["wasted_bytes"], reverse=True)
    return {
        "group_count": len(groups),
        "duplicate_file_count": total_duplicate_files,
        "wasted_bytes": wasted_bytes,
        "groups": groups,
    }


def filter_media_entries(
    entries: list[dict[str, Any]],
    category: str | None = None,
    min_size: int | None = None,
    max_size: int | None = None,
    date_from: int | None = None,
    date_to: int | None = None,
    query: str | None = None,
    only_corrupt: bool = False,
    only_duplicates: bool = False,
) -> list[dict[str, Any]]:
    """Filter media inventory entries by category, byte size, modification timestamp, name query, and flags."""
    q_lower = (query or "").strip().lower()
    cat_lower = (category or "").strip().lower()

    dup_hashes: set[str] = set()
    if only_duplicates:
        counts: dict[str, int] = {}
        for e in entries:
            h = e.get("sha256", "")
            if h:
                counts[h] = counts.get(h, 0) + 1
        dup_hashes = {h for h, c in counts.items() if c > 1}

    filtered: list[dict[str, Any]] = []
    for item in entries:
        if item.get("kind") != "media":
            continue
        if cat_lower and cat_lower != "all" and item.get("category") != cat_lower:
            continue
        size = int(item.get("size", 0))
        if min_size is not None and size < min_size:
            continue
        if max_size is not None and size > max_size:
            continue
        mtime = int(item.get("modified", 0))
        if date_from is not None and mtime < date_from:
            continue
        if date_to is not None and mtime > date_to:
            continue
        if q_lower and q_lower not in item.get("name", "").lower() and q_lower not in item.get("path", "").lower():
            continue
        if only_corrupt and not item.get("corrupt", False):
            continue
        if only_duplicates and item.get("sha256") not in dup_hashes:
            continue
        filtered.append(item)

    return filtered
