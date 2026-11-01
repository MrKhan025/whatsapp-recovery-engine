"""Snapshot Comparison and Verified Export Engine (`wtk/engine.py`).

Preserves all v2.0 public functions (`compare_snapshots`, `load_snapshot`, `verified_export`)
and adds multi-snapshot timeline comparison (`compare_multiple_snapshots`).
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from .verification import verified_export


def compare_snapshots(old: dict[str, Any], new: dict[str, Any]) -> dict[str, Any]:
    """Compare two scan inventories by normalized relative path, size, and SHA-256 hash."""
    def indexed(snapshot: dict[str, Any]) -> dict[str, dict[str, Any]]:
        root = Path(snapshot["source"])
        out: dict[str, dict[str, Any]] = {}
        for entry in snapshot.get("entries", []):
            try:
                rel = str(Path(entry["path"]).relative_to(root))
            except (ValueError, KeyError):
                rel = entry.get("relative_path") or entry.get("name") or entry.get("path", "unknown")
            out[rel] = entry
        return out

    a, b = indexed(old), indexed(new)
    added: list[dict[str, Any]] = []
    removed: list[dict[str, Any]] = []
    changed: list[dict[str, Any]] = []
    unchanged: list[str] = []

    for key in sorted(a.keys() | b.keys()):
        if key not in a:
            added.append({"path": key, "new": b[key]})
        elif key not in b:
            removed.append({"path": key, "old": a[key]})
        elif a[key].get("sha256") != b[key].get("sha256") or a[key].get("size") != b[key].get("size"):
            changed.append({"path": key, "old": a[key], "new": b[key]})
        else:
            unchanged.append(key)

    return {
        "old_source": old.get("source", ""),
        "new_source": new.get("source", ""),
        "old_timestamp": old.get("timestamp", ""),
        "new_timestamp": new.get("timestamp", ""),
        "added": added,
        "removed": removed,
        "changed": changed,
        "unchanged": unchanged,
        "summary": {
            "added": len(added),
            "removed": len(removed),
            "changed": len(changed),
            "unchanged": len(unchanged),
        },
        "disclaimer": (
            "Removed entries indicate files present in the earlier snapshot that were absent in the newer snapshot. "
            "They are recoverable only if the earlier backup snapshot files are still accessible."
        ),
    }


def compare_multiple_snapshots(snapshots: list[dict[str, Any]]) -> dict[str, Any]:
    """Compare two or more backup snapshots sequentially and compute net changes from first to last."""
    if len(snapshots) < 2:
        raise ValueError("At least two snapshots are required for comparison")

    steps: list[dict[str, Any]] = []
    for idx in range(len(snapshots) - 1):
        diff = compare_snapshots(snapshots[idx], snapshots[idx + 1])
        steps.append({
            "step": idx + 1,
            "from_source": snapshots[idx].get("source", f"snapshot_{idx}"),
            "to_source": snapshots[idx + 1].get("source", f"snapshot_{idx + 1}"),
            "summary": diff["summary"],
            "added": diff["added"],
            "removed": diff["removed"],
            "changed": diff["changed"],
        })

    overall = compare_snapshots(snapshots[0], snapshots[-1])
    return {
        "snapshot_count": len(snapshots),
        "steps": steps,
        "net_comparison": overall,
    }


def load_snapshot(path: str | Path) -> dict[str, Any]:
    """Load and validate a saved JSON scan snapshot."""
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    if not isinstance(data, dict) or not isinstance(data.get("entries"), list) or not data.get("source"):
        raise ValueError("Invalid scan snapshot")
    return data


__all__ = ["compare_snapshots", "compare_multiple_snapshots", "load_snapshot", "verified_export"]
