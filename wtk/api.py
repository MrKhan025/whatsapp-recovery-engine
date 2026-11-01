"""FastAPI Backend (`wtk/api.py`) for WhatsApp Recovery Engine – Advanced Edition."""

from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any

from fastapi import FastAPI, HTTPException
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles

from . import __version__
from .adb import device_check, get_android_guidance
from .chat_analyzer import (
    compare_chat_databases,
    inspect_chat_database,
    parse_chat_export,
    search_chat_messages,
)
from .engine import compare_multiple_snapshots, compare_snapshots, verified_export
from .estimator import estimate_recovery_readiness
from .i18n import get_text
from .media_engine import MEDIA_MIME, filter_media_entries
from .reports import (
    generate_all_scan_reports,
    write_backup_comparison_report,
    write_json,
    write_verification_certificate,
)
from .scanner import is_within, scan_tree
from .security import audit_dependencies, validate_safe_path

app = FastAPI(
    title="WhatsApp Recovery Engine – Advanced Edition",
    version=__version__,
    description="Offline-first WhatsApp backup analysis, chat inspection, media discovery, SHA-256 verification, and forensic reporting platform.",
)

BASE = Path(__file__).resolve().parent.parent
SAMPLE_DATA_DIR = BASE / "sample-data"
REPORT_DIR = Path.home() / ".wte-reports"
REPORT_DIR.mkdir(parents=True, exist_ok=True)

LAST_REPORT: dict[str, Any] | None = None
LAST_COMPARISON: dict[str, Any] | None = None
LAST_VERIFICATION: dict[str, Any] | None = None
SCAN_HISTORY: list[dict[str, Any]] = []


def _allowed_roots() -> list[Path]:
    roots = [SAMPLE_DATA_DIR.resolve(), REPORT_DIR.resolve()]
    if LAST_REPORT and LAST_REPORT.get("source"):
        try:
            roots.append(Path(LAST_REPORT["source"]).resolve())
        except OSError:
            pass
    return roots


def _check_within_allowed(target: Path) -> bool:
    return any(is_within(target, r) for r in _allowed_roots())


@app.get("/api/status")
def status() -> dict[str, Any]:
    """Return service health, offline posture, ADB check, and sample data availability."""
    return {
        "status": "ok",
        "offline": True,
        "version": __version__,
        "adb": device_check(),
        "sample_data_path": str(SAMPLE_DATA_DIR),
        "sample_snapshot_v1": str(SAMPLE_DATA_DIR / "snapshot_v1"),
        "sample_snapshot_v2": str(SAMPLE_DATA_DIR / "snapshot_v2"),
        "security": audit_dependencies(BASE),
    }


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
def scan(payload: dict[str, Any]) -> dict[str, Any]:
    """Scan a user-authorized directory in read-only mode and generate forensic reports."""
    global LAST_REPORT
    source = payload.get("source")
    if not isinstance(source, str) or not source.strip():
        raise HTTPException(400, "A source directory is required")
    try:
        safe_dir = validate_safe_path(source, must_exist=True, allow_symlinks=False)
        report = scan_tree(safe_dir)
        stamp = time.strftime("%Y%m%d-%H%M%S")
        snap_file = write_json(report, REPORT_DIR, f"scan-{stamp}.json")
        generate_all_scan_reports(report, REPORT_DIR)
        LAST_REPORT = report

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
        return {**report, "entries": report["entries"][:1500], "history": SCAN_HISTORY[-25:]}
    except (ValueError, OSError) as exc:
        raise HTTPException(400, str(exc)) from exc


@app.get("/api/history")
def get_history() -> dict[str, Any]:
    """Return recent scan history from the current session and saved snapshots."""
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
def compare(payload: dict[str, Any]) -> dict[str, Any]:
    """Compare two or more saved scan snapshots and write a backup comparison report."""
    global LAST_COMPARISON
    try:
        snapshot_paths = payload.get("snapshots")
        if isinstance(snapshot_paths, list) and len(snapshot_paths) >= 2:
            loaded = []
            for raw_p in snapshot_paths:
                p = validate_safe_path(raw_p, allowed_root=REPORT_DIR, must_exist=True)
                loaded.append(json.loads(p.read_text(encoding="utf-8")))
            multi_diff = compare_multiple_snapshots(loaded)
            write_backup_comparison_report(multi_diff["net_comparison"], REPORT_DIR)
            LAST_COMPARISON = multi_diff["net_comparison"]
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
        write_backup_comparison_report(diff, REPORT_DIR)
        LAST_COMPARISON = diff
        return diff
    except (ValueError, OSError, json.JSONDecodeError, KeyError) as exc:
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


@app.post("/api/chat/search")
def api_search_chat(payload: dict[str, Any]) -> dict[str, Any]:
    """Search messages across the latest scanned databases/exports or a specific file."""
    query = payload.get("query", "")
    sender = payload.get("sender", "")
    file_path = payload.get("path")

    messages: list[dict[str, Any]] = []
    try:
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

        return search_chat_messages(messages, query=query, sender=sender, limit=300)
    except (ValueError, OSError) as exc:
        raise HTTPException(400, str(exc)) from exc


@app.post("/api/chat/compare-db")
def api_compare_db(payload: dict[str, Any]) -> dict[str, Any]:
    """Compare two accessible SQLite chat database snapshots at the message record level."""
    old_raw = payload.get("old_db", "")
    new_raw = payload.get("new_db", "")
    if not isinstance(old_raw, str) or not isinstance(new_raw, str) or not old_raw.strip() or not new_raw.strip():
        raise HTTPException(400, "Both old_db and new_db paths are required")
    try:
        old_p = validate_safe_path(old_raw, must_exist=True, allow_symlinks=False)
        new_p = validate_safe_path(new_raw, must_exist=True, allow_symlinks=False)
        return compare_chat_databases(old_p, new_p)
    except (ValueError, OSError) as exc:
        raise HTTPException(400, str(exc)) from exc


@app.post("/api/media/filter")
def api_filter_media(payload: dict[str, Any]) -> dict[str, Any]:
    """Filter media entries from the latest scan by category, size, date, corrupt flag, or duplicates."""
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
    )
    return {"count": len(filtered), "entries": filtered[:1000]}


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


@app.post("/api/export")
def export(payload: dict[str, Any]) -> dict[str, Any]:
    """Export selected media files to a separate directory, verify SHA-256 checksums, and issue a certificate."""
    global LAST_VERIFICATION
    if LAST_REPORT is None:
        raise HTTPException(400, "Run a scan first")
    paths = payload.get("paths")
    destination = payload.get("destination")
    if not isinstance(paths, list) or not isinstance(destination, str) or not destination.strip():
        raise HTTPException(400, "paths and destination are required")
    try:
        allowed = {e["path"] for e in LAST_REPORT["entries"] if e.get("kind") == "media"}
        if any(p not in allowed for p in paths):
            raise ValueError("Select media from the latest scan only")
        result = verified_export(LAST_REPORT["source"], paths, destination)
        write_verification_certificate(result, REPORT_DIR)
        LAST_VERIFICATION = result
        return result
    except (ValueError, OSError) as exc:
        raise HTTPException(400, str(exc)) from exc


@app.get("/api/report/{kind}")
def download_report(kind: str) -> FileResponse:
    """Download generated forensic reports (pdf, json, csv, media, db-health, comparison, certificate-json, certificate-pdf)."""
    file_map = {
        "pdf": "recovery-report.pdf",
        "json": "recovery-scan.json",
        "csv": "file-inventory.csv",
        "media": "media-recovery-report.json",
        "db-health": "database-health-report.json",
        "comparison": "backup-comparison-report.json",
        "certificate-json": "verification-certificate.json",
        "certificate-pdf": "verification-certificate.pdf",
    }
    if kind not in file_map:
        raise HTTPException(404, "Unknown report type")
    path = REPORT_DIR / file_map[kind]
    if not path.exists():
        raise HTTPException(404, f"Report '{kind}' has not been generated yet. Run the corresponding scan, comparison, or verification first.")
    return FileResponse(path, filename=path.name)


app.mount("/", StaticFiles(directory=BASE / "web", html=True), name="web")
