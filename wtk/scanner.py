from pathlib import Path
import hashlib
import sqlite3

MEDIA_MIME = {
    ".jpg": "image/jpeg", ".jpeg": "image/jpeg", ".png": "image/png",
    ".gif": "image/gif", ".webp": "image/webp", ".bmp": "image/bmp",
    ".mp4": "video/mp4", ".webm": "video/webm", ".mov": "video/quicktime",
    ".mp3": "audio/mpeg", ".m4a": "audio/mp4", ".ogg": "audio/ogg",
    ".opus": "audio/ogg", ".wav": "audio/wav"
}
MEDIA_EXTENSIONS = set(MEDIA_MIME) | {".heic", ".3gp", ".mkv", ".pdf", ".doc", ".docx", ".txt", ".zip"}
BACKUP_HINTS = ("msgstore", "crypt", "backup", "wa.db")

def sha256_file(path: Path, chunk_size: int = 1024 * 1024) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(chunk_size), b""):
            digest.update(chunk)
    return digest.hexdigest()

def is_within(path: Path, root: Path) -> bool:
    try:
        path.resolve().relative_to(root.resolve())
        return True
    except (ValueError, OSError):
        return False

def inspect_sqlite(path: Path) -> dict:
    try:
        uri = path.resolve().as_uri() + "?mode=ro"
        conn = sqlite3.connect(uri, uri=True, timeout=2)
        try:
            row = conn.execute("PRAGMA integrity_check").fetchone()
            result = str(row[0]) if row else "no result"
        finally:
            conn.close()
        return {"supported": True, "integrity": result, "ok": result == "ok"}
    except (sqlite3.DatabaseError, OSError, ValueError) as exc:
        return {"supported": False, "integrity": "unsupported_or_encrypted", "detail": str(exc)[:180], "ok": False}

def scan_tree(source: str | Path, max_files: int = 20000) -> dict:
    root = Path(source).expanduser().resolve()
    if not root.exists() or not root.is_dir():
        raise ValueError("Source must be an existing directory")
    entries, errors, hashes = [], [], {}
    visited = 0
    for item in root.rglob("*"):
        if visited >= max_files:
            errors.append(f"File limit reached ({max_files})")
            break
        try:
            if item.is_symlink() or not item.is_file() or not is_within(item, root):
                continue
            stat = item.stat()
            visited += 1
            suffix, name_lower = item.suffix.lower(), item.name.lower()
            kind = "media" if suffix in MEDIA_EXTENSIONS else (
                "backup_candidate" if any(h in name_lower for h in BACKUP_HINTS) else "other")
            record = {
                "name": item.name, "path": str(item), "size": stat.st_size,
                "modified": int(stat.st_mtime), "kind": kind, "sha256": sha256_file(item),
                "mime": MEDIA_MIME.get(suffix)
            }
            if kind == "media":
                hashes.setdefault(record["sha256"], []).append(str(item))
            if suffix in (".db", ".sqlite", ".sqlite3"):
                record["sqlite"] = inspect_sqlite(item)
            entries.append(record)
        except (OSError, PermissionError) as exc:
            errors.append(f"{item}: {str(exc)[:120]}")
    return {
        "version": 2, "source": str(root), "files_scanned": visited,
        "media_count": sum(x["kind"] == "media" for x in entries),
        "backup_candidates": sum(x["kind"] == "backup_candidate" for x in entries),
        "duplicates": [paths for paths in hashes.values() if len(paths) > 1],
        "errors": errors[:100], "entries": entries
    }
