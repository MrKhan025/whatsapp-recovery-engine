"""Recovery Workspace, Operation Preview & Dual SHA-256/SHA-512 Verification (`wtk/verification.py`).

Implements:
- Recovery session management (`RSESS-...`)
- Recovery operation preview (`preview_recovery_operation`) before copying any bytes
- Safe export of selected files to a separate directory outside the scanned source
- Pre-copy and post-copy dual SHA-256 and SHA-512 calculation
- Checksum comparison and automatic cleanup of failed copies
- Overwrite prevention and original backup preservation
- Cryptographic Verification Certificate generation (supporting optional HMAC-SHA256 signing)
"""

from __future__ import annotations

from datetime import datetime, timezone
import hashlib
import hmac
import shutil
import uuid
from pathlib import Path
from typing import Any

from .evidence import EVIDENCE_LEDGER
from .media_engine import MEDIA_EXTENSIONS
from .security import dual_checksum_file, has_symlink_in_chain, is_within

EXPORTABLE_EXTENSIONS = MEDIA_EXTENSIONS | {
    ".db", ".sqlite", ".sqlite3", ".crypt12", ".crypt14", ".crypt15", ".json", ".html", ".htm"
}


def preview_recovery_operation(
    source_root: str | Path,
    file_paths: list[str],
    destination: str | Path,
    allow_backups: bool = False,
) -> dict[str, Any]:
    """Preview a recovery export operation (checking eligibility, collisions, and byte totals) without writing files."""
    root = Path(source_root).expanduser().resolve()
    dest = Path(destination).expanduser().resolve()
    if dest == root or is_within(dest, root):
        raise ValueError("Export destination must be outside the scanned source directory")
    if has_symlink_in_chain(dest):
        raise ValueError("Export destination cannot traverse symbolic links")

    items: list[dict[str, Any]] = []
    total_bytes = 0
    ready_count = 0

    for raw in file_paths[:250]:
        raw_path = Path(raw).expanduser()
        if raw_path.is_symlink() or has_symlink_in_chain(raw_path, stop_at=root):
            items.append({"source": str(raw), "ready": False, "reason": "Symbolic link rejected"})
            continue
        try:
            src = raw_path.resolve()
        except OSError:
            items.append({"source": str(raw), "ready": False, "reason": "Invalid source path"})
            continue
        if not is_within(src, root) or not src.is_file():
            items.append({"source": str(raw), "ready": False, "reason": "Outside source root or not a regular file"})
            continue

        suffix_lower = src.suffix.lower()
        eligible_exts = EXPORTABLE_EXTENSIONS if allow_backups else MEDIA_EXTENSIONS
        if suffix_lower not in eligible_exts and not (allow_backups and "crypt" in src.name.lower()):
            items.append({"source": str(src), "ready": False, "reason": "Unsupported export file type"})
            continue

        target = dest / src.name
        if target.exists() or target.is_symlink():
            items.append({
                "source": str(src),
                "destination": str(target),
                "ready": False,
                "reason": "Destination file already exists (overwrite prevented)",
            })
            continue

        sz = src.stat().st_size
        total_bytes += sz
        ready_count += 1
        items.append({
            "name": src.name,
            "source": str(src),
            "destination": str(target),
            "size": sz,
            "ready": True,
            "reason": "Ready for verified copy",
        })

    return {
        "preview_only": True,
        "source_root": str(root),
        "destination": str(dest),
        "total_requested": len(items),
        "ready_count": ready_count,
        "blocked_count": len(items) - ready_count,
        "total_bytes_to_copy": total_bytes,
        "items": items,
    }


def verified_export(
    source_root: str | Path,
    file_paths: list[str],
    destination: str | Path,
    allow_backups: bool = False,
    signing_key: str | bytes | None = None,
) -> dict[str, Any]:
    """Copy selected files to a separate directory and verify both SHA-256 and SHA-512 before and after copying."""
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
            before_hashes = dual_checksum_file(src)
            shutil.copyfile(src, target)
            after_hashes = dual_checksum_file(target)
            ok = (
                before_hashes["sha256"] == after_hashes["sha256"]
                and before_hashes["sha512"] == after_hashes["sha512"]
            )
            if not ok:
                target.unlink(missing_ok=True)
            results.append({
                "name": src.name,
                "source": str(src),
                "destination": str(target),
                "size": src.stat().st_size,
                "source_sha256": before_hashes["sha256"],
                "destination_sha256": after_hashes["sha256"],
                "source_sha512": before_hashes["sha512"],
                "destination_sha512": after_hashes["sha512"],
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
        f"{r.get('source','')}|{r.get('destination','')}|{r.get('source_sha256','')}|{r.get('destination_sha256','')}|{r.get('source_sha512','')}|{r.get('verified',False)}"
        for r in results
    ]
    manifest_bytes = "\n".join(manifest_lines).encode("utf-8")
    manifest_sha256 = hashlib.sha256(manifest_bytes).hexdigest()
    manifest_sha512 = hashlib.sha512(manifest_bytes).hexdigest()

    if signing_key:
        key_bytes = signing_key.encode("utf-8") if isinstance(signing_key, str) else signing_key
        signature = hmac.new(key_bytes, manifest_bytes, hashlib.sha256).hexdigest()
        verification_mode = "cryptographically_signed_hmac_sha256"
    else:
        signature = None
        verification_mode = "checksum_verified_only"

    cert_id = f"WRE-CERT-{uuid.uuid4().hex[:12].upper()}"
    session_id = f"RSESS-{uuid.uuid4().hex[:10].upper()}"

    out_payload = {
        "certificate_id": cert_id,
        "session_id": session_id,
        "timestamp": timestamp_utc,
        "verification_mode": verification_mode,
        "cryptographically_signed": signature is not None,
        "signature": signature,
        "source_root": str(root),
        "destination": str(dest),
        "total_requested": len(results),
        "verified_count": verified_count,
        "failed_count": failed_count,
        "manifest_sha256": manifest_sha256,
        "manifest_sha512": manifest_sha512,
        "results": results,
    }
    EVIDENCE_LEDGER.record_export_event(out_payload)
    return out_payload
