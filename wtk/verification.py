"""Recovery Verification Engine (`wtk/verification.py`).

Implements:
- Safe export of selected files to a separate directory outside the scanned source
- Pre-copy SHA-256 calculation
- Post-copy SHA-256 calculation
- Checksum comparison and automatic cleanup of failed copies
- Overwrite prevention and original backup preservation
- Cryptographic Verification Certificate generation
"""

from __future__ import annotations

import hashlib
import shutil
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .media_engine import MEDIA_EXTENSIONS
from .security import has_symlink_in_chain, is_within, sha256_file

EXPORTABLE_EXTENSIONS = MEDIA_EXTENSIONS | {
    ".db", ".sqlite", ".sqlite3", ".crypt12", ".crypt14", ".crypt15", ".json", ".html", ".htm"
}


def verified_export(
    source_root: str | Path,
    file_paths: list[str],
    destination: str | Path,
    allow_backups: bool = False,
) -> dict[str, Any]:
    """Copy selected files to a separate directory and verify SHA-256 before and after copying."""
    root = Path(source_root).expanduser().resolve()
    dest = Path(destination).expanduser().resolve()
    if dest == root or is_within(dest, root):
        raise ValueError("Export destination must be outside the scanned source directory")
    if has_symlink_in_chain(dest):
        raise ValueError("Export destination cannot traverse symbolic links")

    dest.mkdir(parents=True, exist_ok=True)
    results: list[dict[str, Any]] = []
    timestamp_utc = datetime.now(tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

    for raw in file_paths[:250]:
        raw_path = Path(raw).expanduser()
        if raw_path.is_symlink() or has_symlink_in_chain(raw_path, stop_at=root):
            results.append({
                "source": str(raw),
                "verified": False,
                "error": "Symbolic links are rejected for security",
            })
            continue

        try:
            src = raw_path.resolve()
        except OSError:
            results.append({"source": str(raw), "verified": False, "error": "Invalid source path"})
            continue

        if not is_within(src, root) or not src.is_file():
            results.append({
                "source": str(raw),
                "verified": False,
                "error": "File is outside source or unavailable",
            })
            continue

        suffix_lower = src.suffix.lower()
        eligible_exts = EXPORTABLE_EXTENSIONS if allow_backups else MEDIA_EXTENSIONS
        if suffix_lower not in eligible_exts and not (allow_backups and "crypt" in src.name.lower()):
            results.append({
                "source": str(src),
                "verified": False,
                "error": "Unsupported export type",
            })
            continue

        target = dest / src.name
        if target.exists() or target.is_symlink():
            results.append({
                "source": str(src),
                "destination": str(target),
                "verified": False,
                "error": "Destination already exists (overwrite prevented)",
            })
            continue

        try:
            before_sha = sha256_file(src)
            shutil.copyfile(src, target)
            after_sha = sha256_file(target)
            ok = before_sha == after_sha
            if not ok:
                target.unlink(missing_ok=True)
            results.append({
                "name": src.name,
                "source": str(src),
                "destination": str(target),
                "size": src.stat().st_size,
                "source_sha256": before_sha,
                "destination_sha256": after_sha,
                "verified": ok,
                "timestamp": timestamp_utc,
            })
        except OSError as exc:
            results.append({
                "source": str(src),
                "verified": False,
                "error": str(exc)[:160],
            })

    verified_count = sum(1 for x in results if x.get("verified") is True)
    failed_count = len(results) - verified_count

    manifest_lines = [
        f"{r.get('source','')}|{r.get('destination','')}|{r.get('source_sha256','')}|{r.get('destination_sha256','')}|{r.get('verified',False)}"
        for r in results
    ]
    manifest_sha256 = hashlib.sha256("\n".join(manifest_lines).encode("utf-8")).hexdigest()
    cert_id = f"WRE-CERT-{uuid.uuid4().hex[:12].upper()}"

    return {
        "certificate_id": cert_id,
        "timestamp": timestamp_utc,
        "source_root": str(root),
        "destination": str(dest),
        "total_requested": len(results),
        "verified_count": verified_count,
        "failed_count": failed_count,
        "manifest_sha256": manifest_sha256,
        "results": results,
    }
