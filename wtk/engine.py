from pathlib import Path
import json
import shutil
from .scanner import sha256_file, is_within, MEDIA_MIME

def compare_snapshots(old: dict, new: dict) -> dict:
    """Compare inventories by normalized relative path, size and hash."""
    def indexed(snapshot):
        root = Path(snapshot["source"])
        out = {}
        for entry in snapshot.get("entries", []):
            try:
                rel = str(Path(entry["path"]).relative_to(root))
            except (ValueError, KeyError):
                rel = entry.get("name", entry.get("path", "unknown"))
            out[rel] = entry
        return out
    a, b = indexed(old), indexed(new)
    added, removed, changed, unchanged = [], [], [], []
    for key in sorted(a.keys() | b.keys()):
        if key not in a:
            added.append({"path": key, "new": b[key]})
        elif key not in b:
            removed.append({"path": key, "old": a[key]})
        elif a[key].get("sha256") != b[key].get("sha256") or a[key].get("size") != b[key].get("size"):
            changed.append({"path": key, "old": a[key], "new": b[key]})
        else:
            unchanged.append(key)
    return {"added": added, "removed": removed, "changed": changed,
            "unchanged": unchanged, "summary": {
                "added": len(added), "removed": len(removed),
                "changed": len(changed), "unchanged": len(unchanged)}}

def load_snapshot(path: str | Path) -> dict:
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    if not isinstance(data, dict) or not isinstance(data.get("entries"), list) or not data.get("source"):
        raise ValueError("Invalid scan snapshot")
    return data

def verified_export(source_root: str | Path, file_paths: list[str], destination: str | Path) -> dict:
    root = Path(source_root).expanduser().resolve()
    dest = Path(destination).expanduser().resolve()
    if dest == root or is_within(dest, root):
        raise ValueError("Export destination must be outside the scanned source directory")
    dest.mkdir(parents=True, exist_ok=True)
    results = []
    for raw in file_paths[:100]:
        src = Path(raw).expanduser().resolve()
        if not is_within(src, root) or src.is_symlink() or not src.is_file():
            results.append({"source": raw, "verified": False, "error": "File is outside source or unavailable"})
            continue
        # Only media formats are eligible for this convenience export.
        if src.suffix.lower() not in MEDIA_MIME and src.suffix.lower() not in {".heic", ".3gp", ".mkv"}:
            results.append({"source": str(src), "verified": False, "error": "Unsupported export type"})
            continue
        target = dest / src.name
        if target.exists():
            results.append({"source": str(src), "verified": False, "error": "Destination already exists"})
            continue
        try:
            before = sha256_file(src)
            shutil.copyfile(src, target)
            after = sha256_file(target)
            ok = before == after
            if not ok:
                target.unlink(missing_ok=True)
            results.append({"source": str(src), "destination": str(target), "source_sha256": before,
                            "destination_sha256": after, "verified": ok})
        except OSError as exc:
            results.append({"source": str(src), "verified": False, "error": str(exc)[:160]})
    return {"destination": str(dest), "results": results,
            "verified_count": sum(x.get("verified", False) for x in results)}
