"""AI-Assisted Local Forensic Analysis Engine (`wtk/forensic_ai.py`).

A modular, offline-first heuristic and statistical analysis engine that:
- Summarizes selected conversations
- Identifies missing date ranges and anomalous timeline gaps
- Explains backup differences between snapshots
- Identifies suspicious file inconsistencies (0-byte files, header mismatches, timestamp drift, uncheckpointed WAL frames)
- Generates evidence-based recovery recommendations
- Explains corruption indicators
- Explicitly separates `verified_findings` (cryptographically/structurally proven facts)
  from `inferred_observations` (analytical interpretations)

AI is optional and defaults strictly to 100% local processing. Private conversations,
keys, and backup contents are never transmitted to external services.
"""

from __future__ import annotations

from collections import Counter
import re
from typing import Any


def summarize_conversation(messages: list[dict[str, Any]], enabled: bool = True) -> dict[str, Any]:
    """Generate a local, offline summary of a conversation's participants, timeline, and frequent terms."""
    if not enabled:
        return {"enabled": False, "summary": "AI-assisted analysis is disabled in settings."}

    if not messages:
        return {
            "enabled": True,
            "processing_mode": "local_offline_heuristic",
            "external_transmission": False,
            "message_count": 0,
            "summary": "No accessible messages available to summarize.",
            "verified_findings": [],
            "inferred_observations": [],
        }

    senders = Counter(str(m.get("sender") or "unknown") for m in messages)
    words: Counter[str] = Counter()
    stop_words = {"the", "and", "for", "that", "this", "with", "from", "have", "are", "was", "were", "all", "now"}
    for m in messages:
        for token in re.findall(r"[A-Za-z]{3,}", str(m.get("text") or "").lower()):
            if token not in stop_words:
                words[token] += 1

    timestamps = [str(m.get("timestamp")) for m in messages if m.get("timestamp")]
    top_senders = [{"sender": k, "count": v} for k, v in senders.most_common(5)]
    top_terms = [w for w, _ in words.most_common(8)]

    verified = [
        f"Conversation contains {len(messages)} accessible message record(s) across {len(senders)} distinct participant identifier(s).",
    ]
    if timestamps:
        verified.append(f"Accessible message timestamps span from {timestamps[0]} to {timestamps[-1]}.")

    inferred = []
    if top_terms:
        inferred.append(f"Frequent topical keywords observed in accessible text: {', '.join(top_terms)}.")
    if len(senders) > 2:
        inferred.append("Multi-participant distribution indicates a group conversation structure.")

    return {
        "enabled": True,
        "processing_mode": "local_offline_heuristic",
        "external_transmission": False,
        "message_count": len(messages),
        "participant_count": len(senders),
        "top_participants": top_senders,
        "top_keywords": top_terms,
        "earliest_timestamp": timestamps[0] if timestamps else None,
        "latest_timestamp": timestamps[-1] if timestamps else None,
        "verified_findings": verified,
        "inferred_observations": inferred,
    }


def generate_forensic_findings(
    scan_report: dict[str, Any],
    snapshot_comparison: dict[str, Any] | None = None,
    db_comparison: dict[str, Any] | None = None,
    enabled: bool = True,
) -> dict[str, Any]:
    """Generate structured forensic findings separating verified facts from inferred observations."""
    if not enabled:
        return {
            "enabled": False,
            "processing_mode": "disabled",
            "external_transmission": False,
            "verified_findings": [],
            "inferred_observations": [],
            "corruption_explanations": [],
            "suspicious_inconsistencies": [],
            "missing_date_ranges": [],
            "backup_difference_explanation": "",
            "recommendations": [],
        }

    verified_findings: list[dict[str, Any]] = []
    inferred_observations: list[dict[str, Any]] = []
    corruption_explanations: list[dict[str, str]] = []
    suspicious_inconsistencies: list[dict[str, str]] = []
    missing_date_ranges: list[dict[str, Any]] = []
    recommendations: list[str] = []

    entries = scan_report.get("entries", [])
    media_entries = [e for e in entries if e.get("kind") == "media"]
    corrupt_media = [e for e in media_entries if e.get("corrupt")]
    drifted_media = [
        e for e in media_entries
        if e.get("timestamp_meta", {}).get("timestamp_drift_detected")
    ]
    orphaned_media = [e for e in media_entries if e.get("orphaned")]

    # 1. Verified file & media findings
    verified_findings.append({
        "type": "inventory_count",
        "statement": (
            f"Scanned {scan_report.get('files_scanned', 0)} file(s): "
            f"{len(media_entries)} media item(s), {scan_report.get('backup_candidates', 0)} backup candidate(s), "
            f"and {scan_report.get('chat_export_count', 0)} chat export(s)."
        ),
        "confidence": "verified_100_percent",
    })

    if corrupt_media:
        verified_findings.append({
            "type": "corrupt_media_headers",
            "statement": f"{len(corrupt_media)} media file(s) failed magic-byte signature validation or are 0 bytes.",
            "confidence": "verified_100_percent",
        })
        for cm in corrupt_media[:10]:
            corruption_explanations.append({
                "file": cm.get("name", ""),
                "reason": str(cm.get("corruption_reason") or "Header signature mismatch"),
                "explanation": (
                    "The file extension does not match its leading binary magic bytes or the file was truncated during write/transfer."
                ),
            })

    if drifted_media:
        suspicious_inconsistencies.append({
            "category": "timestamp_drift",
            "count": str(len(drifted_media)),
            "detail": (
                f"{len(drifted_media)} media file(s) have an OS modification date that differs from their embedded EXIF or WhatsApp filename date."
            ),
        })
        inferred_observations.append({
            "type": "transfer_history_inference",
            "statement": (
                "Filesystem modification dates differ from embedded EXIF/WhatsApp filename dates, indicating the backup folder was likely copied or moved after original media creation."
            ),
            "basis": "Comparison between stat.st_mtime and EXIF/IMG-YYYYMMDD filename metadata.",
        })

    if orphaned_media:
        inferred_observations.append({
            "type": "orphaned_media_observation",
            "statement": (
                f"{len(orphaned_media)} media file(s) exist on disk without a corresponding row in an accessible SQLite message_media table."
            ),
            "basis": "Either the chat database predates/postdates those files, the database lacks a message_media table, or the message rows were deleted while leaving media files intact on storage.",
        })

    # 2. Database & WAL analysis
    for db in scan_report.get("chat_databases", []):
        verified_findings.append({
            "type": "sqlite_database",
            "statement": (
                f"Database '{db.get('name')}' ({db.get('format_type')}) reported PRAGMA integrity_check='{db.get('integrity')}' "
                f"with {db.get('message_count', 0)} accessible message(s)."
            ),
            "sha256": db.get("sha256", ""),
            "confidence": "verified_100_percent",
        })
        wal = db.get("wal_diagnostics", {})
        if wal.get("wal_present") and wal.get("uncheckpointed_frames", 0) > 0:
            suspicious_inconsistencies.append({
                "category": "uncheckpointed_wal",
                "count": str(wal["uncheckpointed_frames"]),
                "detail": (
                    f"Database '{db.get('name')}' has a companion -wal file containing {wal['uncheckpointed_frames']} uncheckpointed frame(s)."
                ),
            })
            recommendations.append(
                f"Preserve '{db.get('name')}-wal' alongside '{db.get('name')}' so uncheckpointed WAL frames are not lost."
            )

        gaps = db.get("timeline_analysis", {}).get("gaps", [])
        for g in gaps[:10]:
            missing_date_ranges.append({
                "source": db.get("name"),
                **g,
            })

    # 3. Backup anomalies
    bh = scan_report.get("backup_health", {})
    for b in bh.get("backups", []):
        if b.get("suspicious"):
            suspicious_inconsistencies.append({
                "category": "suspicious_backup_file",
                "count": "1",
                "detail": f"Backup '{b.get('name')}' ({b.get('size')} B) is flagged as '{b.get('status')}'.",
            })
            corruption_explanations.append({
                "file": b.get("name", ""),
                "reason": "; ".join(b.get("warnings", [])) or b.get("status", "suspicious"),
                "explanation": "A 0-byte or truncated .crypt* file indicates an interrupted local backup write or storage exhaustion.",
            })

    # 4. Snapshot & DB comparison explanation
    diff_narrative = "No snapshot comparison has been run yet."
    if snapshot_comparison and isinstance(snapshot_comparison.get("summary"), dict):
        s = snapshot_comparison["summary"]
        diff_narrative = (
            f"Between snapshots, {s.get('added', 0)} file(s) were added, {s.get('removed', 0)} file(s) were absent in the newer scan, "
            f"{s.get('changed', 0)} file(s) changed content/hash, and {s.get('unchanged', 0)} file(s) remained identical."
        )
        if s.get("removed", 0) > 0:
            recommendations.append(
                f"Recover the {s.get('removed', 0)} file(s) absent from the newer scan directly from the older snapshot directory."
            )

    if db_comparison and isinstance(db_comparison.get("summary"), dict):
        ds = db_comparison["summary"]
        verified_findings.append({
            "type": "database_snapshot_diff",
            "statement": (
                f"SQLite comparison identified {ds.get('missing_in_new', 0)} historical message(s) present in the older DB but absent from the newer DB, "
                f"{ds.get('changed_records', 0)} modified message(s), and {ds.get('newly_discovered', 0)} newly added message(s)."
            ),
            "confidence": "verified_100_percent",
        })

    if not recommendations:
        recommendations.append(
            "Export intact media and accessible databases to an isolated Recovery Workspace and generate a signed Evidence Manifest."
        )

    return {
        "enabled": True,
        "processing_mode": "local_offline_heuristic",
        "external_transmission": False,
        "verified_findings": verified_findings,
        "inferred_observations": inferred_observations,
        "corruption_explanations": corruption_explanations,
        "suspicious_inconsistencies": suspicious_inconsistencies,
        "missing_date_ranges": missing_date_ranges,
        "backup_difference_explanation": diff_narrative,
        "recommendations": recommendations,
        "disclaimer": (
            "Verified findings are directly backed by SHA-256 hashes, file headers, and SQLite records. "
            "Inferred observations are analytical interpretations and never guarantee recovery of permanently deleted data."
        ),
    }
