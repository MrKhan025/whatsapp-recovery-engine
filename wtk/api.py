"""FastAPI Backend (`wtk/api.py`) for WhatsApp Recovery Engine v2.0."""

from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any

from fastapi import FastAPI, Header, HTTPException
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles

from . import __version__
from .adb import device_check, get_android_guidance
from .chat_analyzer import (
    compare_chat_databases,
    export_chat_records,
    inspect_chat_database,
    link_chat_media,
    match_contacts,
    parse_chat_export,
    parse_contacts_file,
    search_chat_messages,
)
from .decryptor import decrypt_backup_with_user_key, inspect_crypt_header
from .engine import (
    compare_multiple_snapshots,
    compare_snapshots,
    preview_recovery_operation,
    verified_export,
)
from .estimator import estimate_recovery_readiness
from .evidence import EVIDENCE_LEDGER
from .forensic_ai import generate_forensic_findings, summarize_conversation
from .i18n import get_text
from .media_engine import MEDIA_MIME, filter_media_entries, generate_media_thumbnail
from .reports import (
    generate_all_scan_reports,
    write_backup_comparison_report,
    write_forensic_bundle,
    write_json,
    write_verification_certificate,
)
from .sample_bootstrap import ensure_sample_data
from .scanner import is_within, scan_tree
from .security import (
    AUDIT_LOG,
    SESSION_MANAGER,
    audit_dependencies,
    validate_safe_path,
)

app = FastAPI(
    title="WhatsApp Recovery Engine v2.0",
    version=__version__,
    description="Professional Digital Forensics & Backup Recovery Platform.",
)

BASE = Path(__file__).resolve().parent.parent
SAMPLE_DATA_DIR = ensure_sample_data(BASE / "sample-data")
REPORT_DIR = Path.home() / ".wte-reports"
REPORT_DIR.mkdir(parents=True, exist_ok=True)

LAST_REPORT: dict[str, Any] | None = None
LAST_COMPARISON: dict[str, Any] | None = None
LAST_DB_COMPARISON: dict[str, Any] | None = None
LAST_VERIFICATION: dict[str, Any] | None = None
SCAN_HISTORY: list[dict[str, Any]] = []


def _allowed_roots() -> list[Path]:
    roots = [SAMPLE_DATA_DIR.resolve(), REPORT_DIR.resolve()]
    if LAST_REPORT and LAST_REPORT.get("source"):
        try:
            roots.append(Path(LAST_REPORT["source"]).resolve())
        except OSError:
            return roots
    return roots


def _check_within_allowed(target: Path) -> bool:
    return any(is_within(target, r) for r in _allowed_roots())


def _enforce_auth_if_enabled(
    x_wre_token: str | None = None,
    x_csrf_token: str | None = None,
    require_csrf: bool = False,
) -> None:
    if not SESSION_MANAGER.verify_request(
        token=x_wre_token,
        csrf_token=x_csrf_token,
        require_csrf=require_csrf,
    ):
        AUDIT_LOG.log("api_unauthorized_access", status="denied")
        raise HTTPException(401, "Valid local session token required")


@app.get("/api/status")
def status() -> dict[str, Any]:
    """Return service health, offline posture, ADB check, security posture, and active session metadata."""
    ensure_sample_data(SAMPLE_DATA_DIR)
    return {
        "status": "ok",
        "offline": True,
        "version": __version__,
        "adb": device_check(),
        "sample_data_path": str(SAMPLE_DATA_DIR),
        "sample_snapshot_v1": str(SAMPLE_DATA_DIR / "snapshot_v1"),
        "sample_snapshot_v2": str(SAMPLE_DATA_DIR / "snapshot_v2"),
        "security": audit_dependencies(BASE),
        "auth_enforced": SESSION_MANAGER.enforce_auth,
    }


@app.post("/api/auth/session")
def create_auth_session(payload: dict[str, Any] | None = None) -> dict[str, Any]:
    """Create a local operator session token with TTL expiration and CSRF protection token."""
    body = payload or {}
    label = str(body.get("label", "local-operator"))
    ttl = int(body.get("ttl_seconds", 3600))
    session = SESSION_MANAGER.create_session(label=label, ttl_seconds=ttl)
    AUDIT_LOG.log("auth_session_created", status="ok", details={"label": label, "ttl": ttl})
    return session


@app.post("/api/auth/policy")
def set_auth_policy(payload: dict[str, Any]) -> dict[str, Any]:
    """Enable or disable strict session token enforcement on API endpoints."""
    enforce = bool(payload.get("enforce_auth", False))
    SESSION_MANAGER.enforce_auth = enforce
    AUDIT_LOG.log("auth_policy_updated", status="ok", details={"enforce_auth": enforce})
    return {
        "enforce_auth": SESSION_MANAGER.enforce_auth,
        "default_session": SESSION_MANAGER.default_session if enforce else None,
    }


@app.get("/api/audit-log")
def get_audit_log() -> dict[str, Any]:
    """Return the secret-free operational audit trail."""
    return {"events": AUDIT_LOG.get_events(limit=100)}


@app.get("/api/i18n/{lang}")
def language(lang: str) -> dict[str, Any]:
    """Return localized dictionary for English ('en'), Hindi ('hi'), or Urdu ('ur')."""
    return get_text(lang)


@app.get("/api/android-guidance")
def android_guidance() -> dict[str, Any]:
    """Return Termux setup commands, Android scoped-storage guidance, and ADB diagnostics."""
    return get_android_guidance()


@app.get("/api/security-audit")
def security_audit() -> dict[str, Any]:
    """Return local security and dependency posture report."""
    return audit_dependencies(BASE)


@app.post("/api/scan")
def scan(
    payload: dict[str, Any],
    x_wre_token: str | None = Header(default=None),
    x_csrf_token: str | None = Header(default=None),
) -> dict[str, Any]:
    """Scan a user-authorized directory in read-only mode, register evidence, and generate forensic reports."""
    global LAST_REPORT
    _enforce_auth_if_enabled(x_wre_token, x_csrf_token, require_csrf=True)
    ensure_sample_data(SAMPLE_DATA_DIR)
    source = payload.get("source")
    enable_ai = bool(payload.get("enable_ai", True))
    if not isinstance(source, str) or not source.strip():
        raise HTTPException(400, "A source directory is required")
    try:
        safe_dir = validate_safe_path(source, must_exist=True, allow_symlinks=False)
        report = scan_tree(safe_dir, enable_ai=enable_ai)
        stamp = time.strftime("%Y%m%d-%H%M%S")
        snap_file = write_json(report, REPORT_DIR, f"scan-{stamp}.json")
        generate_all_scan_reports(report, REPORT_DIR)
        LAST_REPORT = report

        # Automatically register discovered backup candidates in the Evidence Ledger
        for entry in report.get("entries", []):
            if entry.get("kind") == "backup_candidate":
                try:
                    EVIDENCE_LEDGER.register_evidence(
                        entry["path"],
                        category=entry.get("encryption_format") or "sqlite_database",
                        notes=f"Auto-registered during scan {stamp}",
                    )
                except ValueError:
                    continue

        SCAN_HISTORY.append({
            "timestamp": report.get("timestamp", stamp),
            "source": report["source"],
            "snapshot_file": snap_file.name,
            "snapshot_path": str(snap_file),
            "files_scanned": report["files_scanned"],
            "media_count": report["media_count"],
            "backup_candidates": report["backup_candidates"],
            "readiness": report.get("recovery_estimate", {}).get("readiness", "Low"),
        })
        AUDIT_LOG.log(
            "directory_scan_completed",
            status="ok",
            details={"files_scanned": report["files_scanned"], "media_count": report["media_count"]},
        )
        return {
            **report,
            "entries": report["entries"][:1500],
            "history": SCAN_HISTORY[-25:],
            "evidence_summary": EVIDENCE_LEDGER.list_state(),
        }
    except (ValueError, OSError) as exc:
        AUDIT_LOG.log("directory_scan_failed", status="error", details={"reason": str(exc)})
        raise HTTPException(400, str(exc)) from exc


@app.get("/api/history")
def get_history() -> dict[str, Any]:
    """Return recent scan history from the current session."""
    return {"history": list(reversed(SCAN_HISTORY[-30:]))}


@app.get("/api/snapshots")
def snapshots() -> dict[str, Any]:
    """List saved scan snapshots available for comparison."""
    snaps = [
        {
            "name": p.name,
            "path": str(p),
            "modified": int(p.stat().st_mtime),
            "size": p.stat().st_size,
        }
        for p in sorted(REPORT_DIR.glob("scan-*.json"))[-40:]
    ]
    return {"snapshots": snaps}


@app.post("/api/compare")
def compare(
    payload: dict[str, Any],
    x_wre_token: str | None = Header(default=None),
) -> dict[str, Any]:
    """Compare two or more saved scan snapshots and write a backup comparison report."""
    global LAST_COMPARISON
    _enforce_auth_if_enabled(x_wre_token)
    try:
        snapshot_paths = payload.get("snapshots")
        if isinstance(snapshot_paths, list) and len(snapshot_paths) >= 2:
            loaded = []
            for raw_p in snapshot_paths:
                p = validate_safe_path(raw_p, allowed_root=REPORT_DIR, must_exist=True)
                loaded.append(json.loads(p.read_text(encoding="utf-8")))
            multi_diff = compare_multiple_snapshots(loaded)
            write_backup_comparison_report(multi_diff["net_comparison"], REPORT_DIR)
            write_forensic_bundle(REPORT_DIR)
            LAST_COMPARISON = multi_diff["net_comparison"]
            AUDIT_LOG.log("multi_snapshot_comparison", status="ok", details={"count": len(loaded)})
            return multi_diff

        old_raw = payload.get("old", "")
        new_raw = payload.get("new", "")
        old = Path(old_raw).resolve()
        new = Path(new_raw).resolve()
        if not is_within(old, REPORT_DIR) or not is_within(new, REPORT_DIR):
            raise ValueError("Choose snapshots created by this toolkit")
        old_data = json.loads(old.read_text(encoding="utf-8"))
        new_data = json.loads(new.read_text(encoding="utf-8"))
        diff = compare_snapshots(old_data, new_data)
        diff["updated_readiness"] = estimate_recovery_readiness(new_data, snapshot_comparison=diff)
        diff["forensic_ai"] = generate_forensic_findings(new_data, snapshot_comparison=diff)
        write_backup_comparison_report(diff, REPORT_DIR)
        write_forensic_bundle(REPORT_DIR)
        LAST_COMPARISON = diff
        AUDIT_LOG.log("snapshot_comparison", status="ok", details=diff["summary"])
        return diff
    except (ValueError, OSError, json.JSONDecodeError, KeyError) as exc:
        raise HTTPException(400, str(exc)) from exc


@app.post("/api/backup/inspect-crypt")
def api_inspect_crypt(payload: dict[str, Any]) -> dict[str, Any]:
    """Inspect format-specific CRYPT12/14/15 header metadata without decrypting."""
    raw_path = payload.get("path", "")
    if not isinstance(raw_path, str) or not raw_path.strip():
        raise HTTPException(400, "Encrypted backup path is required")
    try:
        target = validate_safe_path(raw_path, must_exist=True, allow_symlinks=False)
        if not _check_within_allowed(target):
            raise ValueError("Backup file must be inside the scanned directory or sample data")
        return inspect_crypt_header(target)
    except (ValueError, OSError) as exc:
        raise HTTPException(400, str(exc)) from exc


@app.post("/api/backup/decrypt-key")
def api_decrypt_with_key(
    payload: dict[str, Any],
    x_wre_token: str | None = Header(default=None),
) -> dict[str, Any]:
    """Decrypt a user-owned .crypt12/.crypt14/.crypt15 backup using a user-supplied key."""
    _enforce_auth_if_enabled(x_wre_token)
    encrypted_path = payload.get("encrypted_path", "")
    key_input = payload.get("key", "")
    if not isinstance(encrypted_path, str) or not encrypted_path.strip() or not isinstance(key_input, str) or not key_input.strip():
        raise HTTPException(400, "Both encrypted_path and user key are required")
    try:
        target = validate_safe_path(encrypted_path, must_exist=True, allow_symlinks=False)
        if not _check_within_allowed(target):
            raise ValueError("Backup file must be inside the scanned directory or sample data")
        out_db = REPORT_DIR / f"decrypted-{target.stem}.db"
        res = decrypt_backup_with_user_key(target, key_input.strip(), out_db)
        AUDIT_LOG.log("authorized_key_decryption", status="ok", details={"format": res["format"], "key": "[REDACTED]"})
        return res
    except (ValueError, RuntimeError, OSError) as exc:
        AUDIT_LOG.log("authorized_key_decryption_failed", status="error", details={"key": "[REDACTED]"})
        raise HTTPException(400, str(exc)) from exc


@app.post("/api/chat/inspect-db")
def api_inspect_db(payload: dict[str, Any]) -> dict[str, Any]:
    """Inspect an accessible SQLite chat database in read-only mode."""
    raw_path = payload.get("path", "")
    if not isinstance(raw_path, str) or not raw_path.strip():
        raise HTTPException(400, "Database path is required")
    try:
        target = validate_safe_path(raw_path, must_exist=True, allow_symlinks=False)
        if not _check_within_allowed(target):
            raise ValueError("Database must be inside the scanned directory or sample data")
        return inspect_chat_database(target, sample_limit=200)
    except (ValueError, OSError) as exc:
        raise HTTPException(400, str(exc)) from exc


@app.post("/api/chat/link-media")
def api_link_chat_media(payload: dict[str, Any]) -> dict[str, Any]:
    """Cross-reference SQLite message_media rows against scanned media files on disk."""
    raw_path = payload.get("path", "")
    if not isinstance(raw_path, str) or not raw_path.strip():
        raise HTTPException(400, "Database path is required")
    entries = LAST_REPORT.get("entries", []) if LAST_REPORT else []
    try:
        target = validate_safe_path(raw_path, must_exist=True, allow_symlinks=False)
        if not _check_within_allowed(target):
            raise ValueError("Database must be inside the scanned directory or sample data")
        return link_chat_media(target, entries)
    except (ValueError, OSError) as exc:
        raise HTTPException(400, str(exc)) from exc


@app.post("/api/chat/parse-export")
def api_parse_export(payload: dict[str, Any]) -> dict[str, Any]:
    """Parse a TXT, JSON, or HTML chat export file in read-only mode."""
    raw_path = payload.get("path", "")
    if not isinstance(raw_path, str) or not raw_path.strip():
        raise HTTPException(400, "Chat export file path is required")
    try:
        target = validate_safe_path(raw_path, must_exist=True, allow_symlinks=False)
        if not _check_within_allowed(target):
            raise ValueError("Chat export file must be inside the scanned directory or sample data")
        return parse_chat_export(target, max_messages=1000)
    except (ValueError, OSError) as exc:
        raise HTTPException(400, str(exc)) from exc


def _collect_current_messages(file_path: str | None = None) -> list[dict[str, Any]]:
    messages: list[dict[str, Any]] = []
    if isinstance(file_path, str) and file_path.strip():
        target = validate_safe_path(file_path, must_exist=True, allow_symlinks=False)
        if not _check_within_allowed(target):
            raise ValueError("Target file must be inside the scanned directory or sample data")
        if target.suffix.lower() in (".db", ".sqlite", ".sqlite3"):
            db_info = inspect_chat_database(target, sample_limit=2000)
            messages = db_info.get("sample_messages", [])
        else:
            exp_info = parse_chat_export(target, max_messages=2000)
            messages = exp_info.get("messages", [])
    elif LAST_REPORT is not None:
        for db in LAST_REPORT.get("chat_databases", []):
            for m in db.get("sample_messages", []):
                messages.append({**m, "source_file": db.get("name", "db")})
        for exp in LAST_REPORT.get("chat_exports", []):
            for m in exp.get("messages", []):
                messages.append({**m, "source_file": exp.get("name", "export")})
    else:
        raise ValueError("Run a scan first or specify an accessible file path")
    return messages


@app.post("/api/chat/search")
def api_search_chat(payload: dict[str, Any]) -> dict[str, Any]:
    """Search messages across accessible DBs or exports by keyword, sender, and date range."""
    try:
        messages = _collect_current_messages(payload.get("path"))
        contact_file = payload.get("contact_file")
        if isinstance(contact_file, str) and contact_file.strip():
            c_target = validate_safe_path(contact_file, must_exist=True, allow_symlinks=False)
            if not _check_within_allowed(c_target):
                raise ValueError("Contact file must be inside the scanned directory or sample data")
            cmap = parse_contacts_file(c_target)
            messages = match_contacts(messages, cmap)

        return search_chat_messages(
            messages,
            query=payload.get("query", ""),
            sender=payload.get("sender", ""),
            date_from=payload.get("date_from"),
            date_to=payload.get("date_to"),
            limit=300,
        )
    except (ValueError, OSError) as exc:
        raise HTTPException(400, str(exc)) from exc


@app.post("/api/chat/export")
def api_export_chat(payload: dict[str, Any]) -> dict[str, Any]:
    """Export searched or accessible chat messages to JSON, CSV, HTML, or PDF preserving IDs & timestamps."""
    fmt = str(payload.get("format", "json")).lower()
    try:
        messages = _collect_current_messages(payload.get("path"))
        filtered = search_chat_messages(
            messages,
            query=payload.get("query", ""),
            sender=payload.get("sender", ""),
            date_from=payload.get("date_from"),
            date_to=payload.get("date_to"),
            limit=1000,
        )["results"]
        out_file = export_chat_records(filtered, REPORT_DIR, fmt=fmt)
        return {
            "format": fmt,
            "exported_count": len(filtered),
            "file_name": out_file.name,
            "path": str(out_file),
            "download_url": f"/api/report/chat-{fmt}",
        }
    except (ValueError, OSError) as exc:
        raise HTTPException(400, str(exc)) from exc


@app.post("/api/chat/compare-db")
def api_compare_db(payload: dict[str, Any]) -> dict[str, Any]:
    """Compare two accessible SQLite chat database snapshots at the message record level."""
    global LAST_DB_COMPARISON
    old_raw = payload.get("old_db", "")
    new_raw = payload.get("new_db", "")
    if not isinstance(old_raw, str) or not isinstance(new_raw, str) or not old_raw.strip() or not new_raw.strip():
        raise HTTPException(400, "Both old_db and new_db paths are required")
    try:
        old_p = validate_safe_path(old_raw, must_exist=True, allow_symlinks=False)
        new_p = validate_safe_path(new_raw, must_exist=True, allow_symlinks=False)
        if not _check_within_allowed(old_p) or not _check_within_allowed(new_p):
            raise ValueError("Database paths must be inside the scanned directory or sample data")
        res = compare_chat_databases(old_p, new_p)
        LAST_DB_COMPARISON = res
        return res
    except (ValueError, OSError) as exc:
        raise HTTPException(400, str(exc)) from exc


@app.post("/api/media/filter")
def api_filter_media(payload: dict[str, Any]) -> dict[str, Any]:
    """Filter media entries from the latest scan by category, size, date, corrupt, duplicate, or orphaned flag."""
    if LAST_REPORT is None:
        raise HTTPException(400, "Run a scan first")
    entries = LAST_REPORT.get("entries", [])
    filtered = filter_media_entries(
        entries,
        category=payload.get("category"),
        min_size=payload.get("min_size"),
        max_size=payload.get("max_size"),
        date_from=payload.get("date_from"),
        date_to=payload.get("date_to"),
        query=payload.get("query"),
        only_corrupt=bool(payload.get("only_corrupt", False)),
        only_duplicates=bool(payload.get("only_duplicates", False)),
        only_orphaned=bool(payload.get("only_orphaned", False)),
    )
    return {"count": len(filtered), "entries": filtered[:1000]}


@app.post("/api/media/thumbnail")
def api_generate_thumbnail(payload: dict[str, Any]) -> dict[str, Any]:
    """Generate a safe thumbnail in the report workspace without modifying the source media file."""
    if LAST_REPORT is None:
        raise HTTPException(400, "Run a scan first")
    raw_path = payload.get("path", "")
    try:
        candidate = validate_safe_path(raw_path, must_exist=True, allow_symlinks=False)
        allowed = {Path(e["path"]).resolve() for e in LAST_REPORT["entries"] if e.get("kind") == "media"}
        if candidate not in allowed:
            raise ValueError("Thumbnail generation is restricted to media in the latest scan")
        return generate_media_thumbnail(candidate, REPORT_DIR / "thumbnails")
    except (ValueError, OSError) as exc:
        raise HTTPException(400, str(exc)) from exc


@app.get("/api/preview")
def preview(path: str) -> FileResponse:
    """Stream an accessible media file from the latest scan with strict MIME validation."""
    if LAST_REPORT is None:
        raise HTTPException(400, "Run a scan first")
    try:
        candidate = validate_safe_path(path, must_exist=True, allow_symlinks=False)
    except ValueError as exc:
        raise HTTPException(403, str(exc)) from exc

    root = Path(LAST_REPORT["source"]).resolve()
    allowed = {
        Path(e["path"]).resolve()
        for e in LAST_REPORT["entries"]
        if e.get("kind") == "media"
    }
    suffix = candidate.suffix.lower()
    if candidate not in allowed or not is_within(candidate, root) or suffix not in MEDIA_MIME:
        raise HTTPException(403, "Preview is restricted to supported media in the latest scan")

    return FileResponse(
        candidate,
        media_type=MEDIA_MIME[suffix],
        headers={"Content-Disposition": "inline", "X-Content-Type-Options": "nosniff"},
    )


@app.post("/api/export/preview")
def api_export_preview(payload: dict[str, Any]) -> dict[str, Any]:
    """Preview a recovery export operation (checking collisions and byte totals) before copying files."""
    if LAST_REPORT is None:
        raise HTTPException(400, "Run a scan first")
    paths = payload.get("paths")
    destination = payload.get("destination")
    if not isinstance(paths, list) or not isinstance(destination, str) or not destination.strip():
        raise HTTPException(400, "paths and destination are required")
    try:
        return preview_recovery_operation(LAST_REPORT["source"], paths, destination)
    except (ValueError, OSError) as exc:
        raise HTTPException(400, str(exc)) from exc


@app.post("/api/export")
def export(
    payload: dict[str, Any],
    x_wre_token: str | None = Header(default=None),
    x_csrf_token: str | None = Header(default=None),
) -> dict[str, Any]:
    """Export selected media files to a separate directory, verify SHA-256 and SHA-512 checksums, and issue a certificate."""
    global LAST_VERIFICATION
    _enforce_auth_if_enabled(x_wre_token, x_csrf_token, require_csrf=True)
    if LAST_REPORT is None:
        raise HTTPException(400, "Run a scan first")
    paths = payload.get("paths")
    destination = payload.get("destination")
    signing_key = payload.get("signing_key")
    if not isinstance(paths, list) or not isinstance(destination, str) or not destination.strip():
        raise HTTPException(400, "paths and destination are required")
    try:
        allowed = {e["path"] for e in LAST_REPORT["entries"] if e.get("kind") == "media"}
        if any(p not in allowed for p in paths):
            raise ValueError("Select media from the latest scan only")
        result = verified_export(LAST_REPORT["source"], paths, destination, signing_key=signing_key)
        write_verification_certificate(result, REPORT_DIR)
        write_forensic_bundle(REPORT_DIR)
        LAST_VERIFICATION = result
        AUDIT_LOG.log(
            "verified_media_export",
            status="ok",
            details={"verified_count": result["verified_count"], "certificate_id": result["certificate_id"]},
        )
        return result
    except (ValueError, OSError) as exc:
        raise HTTPException(400, str(exc)) from exc


@app.get("/api/evidence")
def api_get_evidence() -> dict[str, Any]:
    """Return registered evidence items, chain-of-custody records, and export history."""
    return EVIDENCE_LEDGER.list_state()


@app.post("/api/evidence/register")
def api_register_evidence(payload: dict[str, Any]) -> dict[str, Any]:
    """Register a file from the scanned source or sample data as a tracked forensic evidence item."""
    raw_path = payload.get("path", "")
    category = str(payload.get("category", "forensic_artifact"))
    notes = str(payload.get("notes", ""))
    try:
        target = validate_safe_path(raw_path, must_exist=True, allow_symlinks=False)
        if not _check_within_allowed(target):
            raise ValueError("Evidence file must reside inside an authorized scanned folder")
        rec = EVIDENCE_LEDGER.register_evidence(target, category=category, notes=notes)
        AUDIT_LOG.log("evidence_registered", status="ok", details={"evidence_id": rec["evidence_id"]})
        return rec
    except (ValueError, OSError) as exc:
        raise HTTPException(400, str(exc)) from exc


@app.post("/api/evidence/verify")
def api_verify_evidence(payload: dict[str, Any]) -> dict[str, Any]:
    """Re-verify both SHA-256 and SHA-512 of a registered evidence item."""
    evid_id = str(payload.get("evidence_id", ""))
    try:
        return EVIDENCE_LEDGER.verify_evidence_integrity(evid_id)
    except ValueError as exc:
        raise HTTPException(404, str(exc)) from exc


@app.post("/api/evidence/manifest")
def api_generate_evidence_manifest(payload: dict[str, Any] | None = None) -> dict[str, Any]:
    """Generate a signed (HMAC-SHA256) or checksum-verified Evidence Manifest."""
    body = payload or {}
    signing_key = body.get("signing_key")
    manifest = EVIDENCE_LEDGER.generate_signed_manifest(signing_key=signing_key)
    write_json(manifest, REPORT_DIR, "evidence-manifest.json")
    AUDIT_LOG.log(
        "evidence_manifest_generated",
        status="ok",
        details={"manifest_id": manifest["manifest_id"], "mode": manifest["verification_mode"]},
    )
    return manifest


@app.post("/api/ai/analyze")
def api_ai_analyze(payload: dict[str, Any] | None = None) -> dict[str, Any]:
    """Run local offline AI-assisted forensic analysis and conversation summarization."""
    if LAST_REPORT is None:
        raise HTTPException(400, "Run a scan first")
    body = payload or {}
    enabled = bool(body.get("enabled", True))
    messages = _collect_current_messages()
    conv_summary = summarize_conversation(messages, enabled=enabled)
    findings = generate_forensic_findings(
        LAST_REPORT,
        snapshot_comparison=LAST_COMPARISON,
        db_comparison=LAST_DB_COMPARISON,
        enabled=enabled,
    )
    return {
        "conversation_summary": conv_summary,
        "forensic_findings": findings,
    }


@app.get("/api/report/{kind}")
def download_report(kind: str) -> FileResponse:
    """Download generated forensic reports and exports."""
    file_map = {
        "pdf": "recovery-report.pdf",
        "json": "recovery-scan.json",
        "csv": "file-inventory.csv",
        "media": "media-recovery-report.json",
        "db-health": "database-health-report.json",
        "comparison": "backup-comparison-report.json",
        "certificate-json": "verification-certificate.json",
        "certificate-pdf": "verification-certificate.pdf",
        "manifest": "evidence-manifest.json",
        "bundle": "forensic-evidence-bundle.zip",
        "chat-json": "chat-records-export.json",
        "chat-csv": "chat-records-export.csv",
        "chat-html": "chat-records-export.html",
        "chat-pdf": "chat-records-export.pdf",
    }
    if kind not in file_map:
        raise HTTPException(404, "Unknown report type")
    if kind == "bundle" and LAST_REPORT is not None:
        write_forensic_bundle(REPORT_DIR)
    path = REPORT_DIR / file_map[kind]
    if not path.exists():
        raise HTTPException(
            404,
            f"Report '{kind}' has not been generated yet. Run the corresponding scan, comparison, or verification first.",
        )
    return FileResponse(path, filename=path.name)


app.mount("/", StaticFiles(directory=BASE / "web", html=True), name="web")
