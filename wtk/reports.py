"""Advanced Forensic Reporting Engine (`wtk/reports.py`).

Generates all 7 required forensic report formats:
1. PDF Reports (`recovery-report.pdf`)
2. JSON Reports (`recovery-scan.json`)
3. CSV File Inventories (`file-inventory.csv`)
4. Backup Comparison Reports (`backup-comparison-report.json` & `.pdf`)
5. Media Recovery Reports (`media-recovery-report.json`)
6. Database Health Reports (`database-health-report.json`)
7. Recovery Verification Certificates (`verification-certificate.json` & `.pdf`)

All reports include timestamps, file counts, SHA-256 checksums, warnings, and explicit limitations.
"""

from __future__ import annotations

import csv
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from reportlab.lib.pagesizes import A4
from reportlab.pdfgen import canvas

STANDARD_LIMITATIONS = [
    "Offline-first inventory and analysis only: no telemetry, cloud upload, or external network calls.",
    "Encrypted WhatsApp backups (.crypt12/.crypt14/.crypt15) are cataloged by metadata and SHA-256 only; they are never decrypted without a legitimate user-owned key/restore flow.",
    "Deleted messages or media that do not exist in any accessible database, export, or snapshot cannot be recovered.",
    "Removed files in snapshot comparisons indicate absence from the newer scan, not guaranteed recoverability.",
    "Android scoped-storage and app sandbox restrictions are strictly respected.",
]


def _utc_now() -> str:
    return datetime.now(tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")


def write_json(report: dict[str, Any], output: Path | str, filename: str = "recovery-scan.json") -> Path:
    """Write a structured JSON forensic report to `output / filename`."""
    out_dir = Path(output)
    out_dir.mkdir(parents=True, exist_ok=True)
    enriched = {
        "report_generated_at": _utc_now(),
        **report,
        "limitations": report.get("limitations", STANDARD_LIMITATIONS),
    }
    target = out_dir / filename
    target.write_text(json.dumps(enriched, indent=2, ensure_ascii=False), encoding="utf-8")
    return target


def write_csv_inventory(report: dict[str, Any], output: Path | str, filename: str = "file-inventory.csv") -> Path:
    """Write a complete CSV file inventory with SHA-256 checksums, categories, sizes, timestamps, and flags."""
    out_dir = Path(output)
    out_dir.mkdir(parents=True, exist_ok=True)
    target = out_dir / filename

    entries = report.get("entries", [])
    dup_hashes = {
        g.get("sha256")
        for g in report.get("duplicate_analysis", {}).get("groups", [])
        if g.get("sha256")
    }

    fieldnames = [
        "name",
        "relative_path",
        "path",
        "kind",
        "category",
        "size_bytes",
        "modified_timestamp",
        "modified_iso",
        "sha256",
        "mime",
        "corrupt",
        "is_duplicate",
        "encrypted",
        "sqlite_integrity",
        "warnings",
    ]
    with target.open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        for e in entries:
            sqlite_info = e.get("sqlite") or {}
            warns = list(e.get("warnings") or [])
            if e.get("corruption_reason"):
                warns.append(str(e["corruption_reason"]))
            writer.writerow({
                "name": e.get("name", ""),
                "relative_path": e.get("relative_path", e.get("name", "")),
                "path": e.get("path", ""),
                "kind": e.get("kind", ""),
                "category": e.get("category", ""),
                "size_bytes": e.get("size", 0),
                "modified_timestamp": e.get("modified", 0),
                "modified_iso": e.get("modified_iso", ""),
                "sha256": e.get("sha256", ""),
                "mime": e.get("mime", ""),
                "corrupt": bool(e.get("corrupt", False)),
                "is_duplicate": e.get("sha256") in dup_hashes,
                "encrypted": bool(e.get("encrypted", False)),
                "sqlite_integrity": sqlite_info.get("integrity", ""),
                "warnings": "; ".join(warns),
            })
    return target


def write_media_recovery_report(
    report: dict[str, Any],
    output: Path | str,
    filename: str = "media-recovery-report.json",
) -> Path:
    """Generate a dedicated Media Recovery Report with category breakdowns, duplicates, corrupt files, and checksums."""
    out_dir = Path(output)
    out_dir.mkdir(parents=True, exist_ok=True)
    media_entries = [e for e in report.get("entries", []) if e.get("kind") == "media"]
    corrupt_entries = [e for e in media_entries if e.get("corrupt")]

    payload = {
        "report_type": "media_recovery_report",
        "generated_at": _utc_now(),
        "source": report.get("source", ""),
        "total_media_files": len(media_entries),
        "total_media_bytes": sum(int(e.get("size", 0)) for e in media_entries),
        "corrupt_media_count": len(corrupt_entries),
        "category_counts": report.get("category_counts", {}),
        "duplicate_summary": {
            "duplicate_groups": report.get("duplicate_analysis", {}).get("group_count", 0),
            "duplicate_files": report.get("duplicate_analysis", {}).get("duplicate_file_count", 0),
            "wasted_bytes": report.get("duplicate_analysis", {}).get("wasted_bytes", 0),
        },
        "corrupt_files": [
            {
                "name": e.get("name"),
                "path": e.get("path"),
                "size": e.get("size"),
                "sha256": e.get("sha256"),
                "reason": e.get("corruption_reason"),
            }
            for e in corrupt_entries
        ],
        "media_inventory": [
            {
                "name": e.get("name"),
                "category": e.get("category"),
                "size": e.get("size"),
                "modified_iso": e.get("modified_iso"),
                "sha256": e.get("sha256"),
                "corrupt": bool(e.get("corrupt", False)),
            }
            for e in media_entries
        ],
        "warnings": report.get("errors", []),
        "limitations": STANDARD_LIMITATIONS,
    }
    target = out_dir / filename
    target.write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")
    return target


def write_database_health_report(
    report: dict[str, Any],
    output: Path | str,
    filename: str = "database-health-report.json",
) -> Path:
    """Generate a dedicated Database & Backup Health Report."""
    out_dir = Path(output)
    out_dir.mkdir(parents=True, exist_ok=True)
    backup_health = report.get("backup_health", {})
    chat_dbs = report.get("chat_databases", [])

    payload = {
        "report_type": "database_health_report",
        "generated_at": _utc_now(),
        "source": report.get("source", ""),
        "health_status": backup_health.get("health_status", "Unknown"),
        "summary": {
            "total_backup_files": backup_health.get("total_backup_files", 0),
            "encrypted_crypt_count": backup_health.get("encrypted_crypt_count", 0),
            "accessible_sqlite_count": backup_health.get("accessible_sqlite_count", 0),
            "healthy_sqlite_count": backup_health.get("healthy_sqlite_count", 0),
            "corrupt_sqlite_count": backup_health.get("corrupt_sqlite_count", 0),
            "suspicious_or_empty_count": backup_health.get("suspicious_or_empty_count", 0),
        },
        "databases": chat_dbs,
        "backups": backup_health.get("backups", []),
        "warnings": backup_health.get("warnings", []),
        "limitations": STANDARD_LIMITATIONS,
    }
    target = out_dir / filename
    target.write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")
    return target


def write_backup_comparison_report(
    comparison: dict[str, Any],
    output: Path | str,
    filename: str = "backup-comparison-report.json",
) -> Path:
    """Write a structured Backup Comparison Report."""
    out_dir = Path(output)
    out_dir.mkdir(parents=True, exist_ok=True)
    payload = {
        "report_type": "backup_comparison_report",
        "generated_at": _utc_now(),
        **comparison,
        "limitations": STANDARD_LIMITATIONS,
    }
    target = out_dir / filename
    target.write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")
    return target


def write_verification_certificate(
    verification_result: dict[str, Any],
    output: Path | str,
    json_filename: str = "verification-certificate.json",
    pdf_filename: str = "verification-certificate.pdf",
) -> dict[str, Path]:
    """Write both JSON and printable PDF Recovery Verification Certificates."""
    out_dir = Path(output)
    out_dir.mkdir(parents=True, exist_ok=True)

    cert_payload = {
        "report_type": "recovery_verification_certificate",
        "generated_at": _utc_now(),
        **verification_result,
        "limitations": [
            "This certificate attests that exported files matched their source SHA-256 digests at copy time.",
            "Original source backup files were preserved without modification.",
        ],
    }
    json_target = out_dir / json_filename
    json_target.write_text(json.dumps(cert_payload, indent=2, ensure_ascii=False), encoding="utf-8")

    pdf_target = out_dir / pdf_filename
    pdf = canvas.Canvas(str(pdf_target), pagesize=A4)
    width, height = A4
    y = height - 48
    pdf.setTitle("WhatsApp Recovery Engine - Verification Certificate")

    header_lines = [
        "WHATSAPP RECOVERY ENGINE - RECOVERY VERIFICATION CERTIFICATE",
        f"Certificate ID: {verification_result.get('certificate_id', 'N/A')}",
        f"Timestamp: {verification_result.get('timestamp', _utc_now())}",
        f"Source Root: {verification_result.get('source_root', '')}",
        f"Destination: {verification_result.get('destination', '')}",
        f"Files Requested: {verification_result.get('total_requested', 0)} | Verified OK: {verification_result.get('verified_count', 0)} | Failed: {verification_result.get('failed_count', 0)}",
        f"Manifest SHA-256: {verification_result.get('manifest_sha256', '')}",
        "-" * 95,
        "Verified File Checksums (Pre-Copy vs Post-Copy SHA-256):",
    ]
    for line in header_lines:
        pdf.drawString(36, y, line[:115])
        y -= 15

    for item in verification_result.get("results", [])[:60]:
        status_label = "VERIFIED" if item.get("verified") else f"FAILED ({item.get('error', 'mismatch')})"
        name_str = Path(item.get("source", "")).name
        pdf.drawString(36, y, f"[{status_label}] {name_str} ({item.get('size', 0)} bytes)"[:115])
        y -= 13
        if item.get("source_sha256"):
            pdf.drawString(48, y, f"Pre-SHA256 : {item.get('source_sha256')}"[:115])
            y -= 12
            pdf.drawString(48, y, f"Post-SHA256: {item.get('destination_sha256')}"[:115])
            y -= 14
        if y < 60:
            pdf.showPage()
            y = height - 48

    pdf.save()
    return {"json": json_target, "pdf": pdf_target}


def write_pdf(report: dict[str, Any], output: Path | str, filename: str = "recovery-report.pdf") -> Path:
    """Generate a comprehensive multi-section PDF forensic scan report."""
    out_dir = Path(output)
    out_dir.mkdir(parents=True, exist_ok=True)
    target = out_dir / filename
    pdf = canvas.Canvas(str(target), pagesize=A4)
    width, height = A4
    y = height - 45
    pdf.setTitle("WhatsApp Recovery Engine - Forensic Scan Report")

    est = report.get("recovery_estimate", {})
    bh = report.get("backup_health", {})
    cats = report.get("category_counts", {})

    lines = [
        "WHATSAPP RECOVERY ENGINE (v3.0) - FORENSIC SCAN & HEALTH REPORT",
        f"Generated At: {report.get('timestamp', _utc_now())}",
        f"Scanned Source: {report.get('source', '')}",
        f"Total Files Scanned: {report.get('files_scanned', 0)} | Media Files: {report.get('media_count', 0)} | Corrupt Media: {report.get('corrupt_media_count', 0)}",
        f"Backup Candidates: {report.get('backup_candidates', 0)} | Duplicate Groups: {len(report.get('duplicates', []))}",
        f"Recovery Readiness Assessment: {est.get('readiness', 'N/A')} (Qualitative assessment, never a guaranteed percentage)",
        f"Backup Health Status: {bh.get('health_status', 'N/A')} (Encrypted .crypt*: {bh.get('encrypted_crypt_count', 0)}, Accessible SQLite: {bh.get('accessible_sqlite_count', 0)})",
        "",
        "Media Breakdown by Category:",
        (
            f"  Photos: {cats.get('photos', 0)} | Videos: {cats.get('videos', 0)} | Voice Notes: {cats.get('voice_notes', 0)} | "
            f"Audio: {cats.get('audio', 0)} | Docs: {cats.get('documents', 0)} | Stickers: {cats.get('stickers', 0)} | "
            f"GIFs: {cats.get('gifs', 0)} | Thumbnails: {cats.get('thumbnails', 0)}"
        ),
        "",
        "Supporting Evidence:",
    ]
    for ev in est.get("evidence", [])[:5]:
        lines.append(f"  * {ev}")

    if bh.get("warnings") or report.get("errors"):
        lines.append("")
        lines.append("Warnings & Anomalies:")
        for w in (bh.get("warnings", []) + report.get("errors", []))[:6]:
            lines.append(f"  ! {w}")

    lines.extend([
        "",
        "Forensic Limitations & Disclaimers:",
        "  - Read-only local inventory: no decryption of .crypt* files and no guarantee of deleted-data recovery.",
        "  - Deleted chats/media cannot be recovered unless present in an accessible database or backup snapshot.",
        "",
        "Scanned File Inventory (with SHA-256 Checksums):",
    ])

    for line in lines:
        pdf.drawString(36, y, str(line)[:112])
        y -= 14
        if y < 55:
            pdf.showPage()
            y = height - 45

    for entry in report.get("entries", [])[:60]:
        kind_or_cat = entry.get("category") or entry.get("kind", "file")
        sha_short = str(entry.get("sha256", ""))[:24]
        corrupt_tag = " [CORRUPT]" if entry.get("corrupt") else ""
        row_str = f"{kind_or_cat:<14} | {entry.get('name', ''):<28} | {entry.get('size', 0)} B | sha256:{sha_short}...{corrupt_tag}"
        pdf.drawString(36, y, row_str[:112])
        y -= 12
        if y < 55:
            pdf.showPage()
            y = height - 45

    pdf.save()
    return target


def generate_all_scan_reports(report: dict[str, Any], output: Path | str) -> dict[str, str]:
    """Generate all core reports (JSON, PDF, CSV inventory, Media Recovery, DB Health) in one call."""
    out_dir = Path(output)
    paths = {
        "json": str(write_json(report, out_dir, "recovery-scan.json")),
        "pdf": str(write_pdf(report, out_dir, "recovery-report.pdf")),
        "csv": str(write_csv_inventory(report, out_dir, "file-inventory.csv")),
        "media": str(write_media_recovery_report(report, out_dir, "media-recovery-report.json")),
        "db_health": str(write_database_health_report(report, out_dir, "database-health-report.json")),
    }
    return paths
