"""Recovery Success Estimator (`wtk/estimator.py`).

Evaluates recovery readiness (Low / Medium / High) based on:
- Accessible database availability
- Database integrity
- Accessible media availability
- Backup file availability
- File corruption indicators
- Duplicate files
- Snapshot differences

Never presents estimates as guaranteed recovery percentages.
"""

from __future__ import annotations

from typing import Any


def estimate_recovery_readiness(
    scan_report: dict[str, Any],
    snapshot_comparison: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Evaluate recovery readiness (Low / Medium / High) with supporting evidence and next steps."""
    entries: list[dict[str, Any]] = scan_report.get("entries", [])
    media_entries = [e for e in entries if e.get("kind") == "media"]
    backup_entries = [e for e in entries if e.get("kind") == "backup_candidate" or e.get("sqlite")]

    accessible_dbs = [
        e for e in entries
        if e.get("sqlite") and e["sqlite"].get("supported")
    ]
    healthy_dbs = [e for e in accessible_dbs if e["sqlite"].get("ok")]
    corrupt_dbs = [e for e in accessible_dbs if not e["sqlite"].get("ok")]
    encrypted_backups = [
        e for e in backup_entries
        if e.get("encrypted") or "crypt" in e.get("name", "").lower()
    ]
    healthy_encrypted = [
        e for e in encrypted_backups
        if not e.get("suspicious") and e.get("size", 0) >= 256
    ]
    suspicious_backups = [
        e for e in backup_entries
        if e.get("suspicious") or e.get("size", 0) == 0
    ]

    corrupt_media = [e for e in media_entries if e.get("corrupt")]
    intact_media = [e for e in media_entries if not e.get("corrupt")]
    chat_exports = [e for e in entries if e.get("kind") == "chat_export"]
    duplicate_groups = scan_report.get("duplicates", [])

    evidence: list[str] = []
    missing_requirements: list[str] = []
    next_steps: list[str] = []

    # 1. Database & Chat evaluation
    if healthy_dbs:
        total_msgs = sum(int(e["sqlite"].get("message_count", 0)) for e in healthy_dbs)
        evidence.append(
            f"Found {len(healthy_dbs)} accessible, intact SQLite database(s) passing PRAGMA integrity_check ({total_msgs} accessible message records)."
        )
    if corrupt_dbs:
        evidence.append(
            f"Detected {len(corrupt_dbs)} SQLite database(s) failing integrity verification."
        )
    if chat_exports:
        evidence.append(
            f"Found {len(chat_exports)} accessible chat export file(s) (TXT/JSON/HTML) ready for immediate inspection."
        )
    if healthy_encrypted:
        evidence.append(
            f"Found {len(healthy_encrypted)} non-empty encrypted WhatsApp backup file(s) (.crypt*)."
        )
        if not healthy_dbs and not chat_exports:
            missing_requirements.append(
                "Encrypted .crypt* backups cannot be read directly without official WhatsApp account verification or a user-owned decryption key."
            )
    if suspicious_backups:
        evidence.append(
            f"Detected {len(suspicious_backups)} empty or suspiciously small backup file(s)."
        )

    # 2. Media evaluation
    if intact_media:
        evidence.append(
            f"Discovered {len(intact_media)} intact media file(s) across accessible folders ready for SHA-256 verified export."
        )
    if corrupt_media:
        evidence.append(
            f"Flagged {len(corrupt_media)} media file(s) with empty bytes or invalid file header signatures."
        )
    if duplicate_groups:
        evidence.append(
            f"Identified {len(duplicate_groups)} SHA-256 duplicate group(s), providing redundant copies for those files."
        )

    # 3. Snapshot comparison evaluation
    if snapshot_comparison and isinstance(snapshot_comparison.get("summary"), dict):
        summary = snapshot_comparison["summary"]
        removed_count = int(summary.get("removed", 0))
        changed_count = int(summary.get("changed", 0))
        added_count = int(summary.get("added", 0))
        evidence.append(
            f"Snapshot diff shows {added_count} added, {removed_count} removed from newer scan, and {changed_count} modified file(s)."
        )
        if removed_count > 0:
            next_steps.append(
                "Check the older backup snapshot directory if you still retain the older folder copy to recover files absent from the newer scan."
            )

    # Determine Readiness Level: High / Medium / Low
    if (healthy_dbs and intact_media and not corrupt_dbs) or (healthy_dbs and len(healthy_dbs) >= 1 and not suspicious_backups) or (len(intact_media) >= 3 and (healthy_dbs or healthy_encrypted or chat_exports)):
        readiness = "High"
    elif intact_media or healthy_dbs or healthy_encrypted or chat_exports:
        readiness = "Medium"
    else:
        readiness = "Low"

    # Populate missing requirements & next steps
    if not healthy_dbs and not healthy_encrypted and not chat_exports:
        missing_requirements.append(
            "No valid WhatsApp chat database (msgstore.db / .crypt*) or chat export (TXT/JSON/HTML) was found in the scanned path."
        )
    if not intact_media:
        missing_requirements.append(
            "No intact accessible media files were found in the scanned path."
        )
    if corrupt_dbs or corrupt_media or suspicious_backups:
        missing_requirements.append(
            "One or more files exhibit corruption indicators (0-byte size, header mismatch, or failed SQLite integrity check)."
        )

    if intact_media:
        next_steps.append(
            "Use the Media Recovery or Recovery Verification tab to export intact media to a separate directory and verify SHA-256 checksums."
        )
    if healthy_dbs or chat_exports:
        next_steps.append(
            "Open the Chat Analyzer tab to inspect accessible SQLite tables, timestamps, and searchable chat exports."
        )
    if healthy_encrypted and not healthy_dbs:
        next_steps.append(
            "Preserve the original .crypt* backup files in place and follow WhatsApp's official in-app restore flow on an authorized device."
        )
    if not evidence:
        evidence.append("Scanned directory contained no recognizable WhatsApp databases, backups, or media files.")
        next_steps.append(
            "Verify that you selected the correct WhatsApp storage folder (e.g., Android/media/com.whatsapp/WhatsApp) and granted storage access."
        )

    return {
        "readiness": readiness,
        "factors": {
            "accessible_databases": len(accessible_dbs),
            "healthy_databases": len(healthy_dbs),
            "corrupt_databases": len(corrupt_dbs),
            "encrypted_backups": len(encrypted_backups),
            "healthy_encrypted_backups": len(healthy_encrypted),
            "suspicious_backups": len(suspicious_backups),
            "accessible_media": len(intact_media),
            "corrupt_media": len(corrupt_media),
            "duplicate_groups": len(duplicate_groups),
            "chat_exports": len(chat_exports),
        },
        "evidence": evidence,
        "missing_requirements": missing_requirements,
        "recommended_next_steps": next_steps,
        "disclaimer": (
            "Readiness is a qualitative assessment (Low / Medium / High) of currently accessible files and their structural integrity. "
            "It is never a guaranteed recovery percentage, and permanently deleted data absent from all accessible backups cannot be recovered."
        ),
    }
