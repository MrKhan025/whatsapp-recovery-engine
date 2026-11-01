"""Automated tests for snapshot comparison, multi-snapshot diffing, and SHA-256 verified export."""

from pathlib import Path
from wtk.engine import compare_snapshots, compare_multiple_snapshots, verified_export


def entry(path: Path, digest: str, size: int = 3) -> dict:
    return {"path": str(path), "name": Path(path).name, "sha256": digest, "size": size, "kind": "media"}


def test_compare_snapshots_detects_changes(tmp_path: Path) -> None:
    oldroot = tmp_path / "old"
    newroot = tmp_path / "new"
    oldroot.mkdir()
    newroot.mkdir()
    old = {"source": str(oldroot), "entries": [entry(oldroot / "same.jpg", "a"), entry(oldroot / "gone.jpg", "b"), entry(oldroot / "mod.jpg", "oldhash", 10)]}
    new = {"source": str(newroot), "entries": [entry(newroot / "same.jpg", "a"), entry(newroot / "new.jpg", "c"), entry(newroot / "mod.jpg", "newhash", 12)]}
    result = compare_snapshots(old, new)
    assert result["summary"] == {"added": 1, "removed": 1, "changed": 1, "unchanged": 1}


def test_compare_multiple_snapshots(tmp_path: Path) -> None:
    s1 = {"source": str(tmp_path / "s1"), "entries": [entry(tmp_path / "s1" / "a.jpg", "h1")]}
    s2 = {"source": str(tmp_path / "s2"), "entries": [entry(tmp_path / "s2" / "a.jpg", "h1"), entry(tmp_path / "s2" / "b.jpg", "h2")]}
    s3 = {"source": str(tmp_path / "s3"), "entries": [entry(tmp_path / "s3" / "b.jpg", "h2"), entry(tmp_path / "s3" / "c.jpg", "h3")]}
    res = compare_multiple_snapshots([s1, s2, s3])
    assert res["snapshot_count"] == 3
    assert len(res["steps"]) == 2
    assert res["net_comparison"]["summary"] == {"added": 2, "removed": 1, "changed": 0, "unchanged": 0}


def test_verified_export(tmp_path: Path) -> None:
    src = tmp_path / "src"
    dst = tmp_path / "out"
    src.mkdir()
    photo = src / "pic.jpg"
    photo.write_bytes(b"my-photo")
    result = verified_export(src, [str(photo)], dst)
    assert result["verified_count"] == 1
    assert result["certificate_id"].startswith("WRE-CERT-")
    assert len(result["manifest_sha256"]) == 64
    assert (dst / "pic.jpg").read_bytes() == b"my-photo"


def test_export_refuses_inside_source(tmp_path: Path) -> None:
    src = tmp_path / "src"
    src.mkdir()
    f = src / "x.jpg"
    f.write_bytes(b"x")
    try:
        verified_export(src, [str(f)], src / "inside")
        assert False, "Expected ValueError when exporting inside source"
    except ValueError:
        assert True


def test_export_does_not_overwrite(tmp_path: Path) -> None:
    src = tmp_path / "src"
    dst = tmp_path / "dst"
    src.mkdir()
    dst.mkdir()
    f = src / "a.jpg"
    f.write_bytes(b"new")
    (dst / "a.jpg").write_bytes(b"existing")
    result = verified_export(src, [str(f)], dst)
    assert result["verified_count"] == 0
    assert (dst / "a.jpg").read_bytes() == b"existing"


def test_export_rejects_symlinks(tmp_path: Path) -> None:
    src = tmp_path / "src"
    dst = tmp_path / "dst"
    src.mkdir()
    outside = tmp_path / "outside.jpg"
    outside.write_bytes(b"outside")
    link = src / "link.jpg"
    link.symlink_to(outside)
    result = verified_export(src, [str(link)], dst)
    assert result["verified_count"] == 0
    assert not (dst / "link.jpg").exists()
