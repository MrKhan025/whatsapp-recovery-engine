"""Automated tests for backup discovery, SQLite integrity, media classification,
duplicates, invalid paths, path traversal, and symlink handling.
"""

from pathlib import Path
import sqlite3
from wtk.scanner import scan_tree, inspect_sqlite, sha256_file
from wtk.media_engine import classify_media_file, inspect_media_integrity, filter_media_entries
from wtk.security import validate_safe_path


def test_scan_media_and_backup(tmp_path: Path) -> None:
    (tmp_path / "photo.jpg").write_bytes(b"\xff\xd8\xff\xe0" + b"image-data-valid")
    (tmp_path / "msgstore.db.crypt14").write_bytes(b"encrypted-placeholder" * 20)
    report = scan_tree(tmp_path)
    assert report["files_scanned"] == 2
    assert report["media_count"] == 1
    assert report["backup_candidates"] == 1
    assert report["backup_health"]["encrypted_crypt_count"] == 1


def test_duplicate_detection(tmp_path: Path) -> None:
    payload = b"\xff\xd8\xff\xe0" + b"same-jpeg-bytes-12345"
    (tmp_path / "a.jpg").write_bytes(payload)
    (tmp_path / "b.jpg").write_bytes(payload)
    report = scan_tree(tmp_path)
    assert len(report["duplicates"]) == 1
    assert report["duplicate_analysis"]["group_count"] == 1
    assert report["duplicate_analysis"]["duplicate_file_count"] == 1
    assert report["duplicate_analysis"]["wasted_bytes"] == len(payload)


def test_sqlite_integrity(tmp_path: Path) -> None:
    db = tmp_path / "ok.db"
    c = sqlite3.connect(db)
    c.execute("CREATE TABLE message(_id INTEGER PRIMARY KEY, sender_jid_raw_string TEXT, text_data TEXT, timestamp INTEGER, from_me INTEGER);")
    c.execute("INSERT INTO message VALUES (1, 'alice@s.whatsapp.net', 'Hello world', 1730000000000, 0);")
    c.commit()
    c.close()
    res = inspect_sqlite(db)
    assert res["ok"] is True
    assert res["supported"] is True
    assert res["message_count"] == 1
    assert "message" in res["tables"]

    corrupt_db = tmp_path / "corrupt.db"
    corrupt_db.write_bytes(b"not-a-valid-sqlite-header-file-at-all")
    assert inspect_sqlite(corrupt_db)["ok"] is False


def test_hash(tmp_path: Path) -> None:
    f = tmp_path / "a.bin"
    f.write_bytes(b"abc")
    assert sha256_file(f) == "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"


def test_missing_directory_rejected(tmp_path: Path) -> None:
    try:
        scan_tree(tmp_path / "missing")
        assert False, "Expected ValueError for missing directory"
    except ValueError:
        assert True


def test_path_traversal_rejected(tmp_path: Path) -> None:
    traversal = str(tmp_path) + "/../" + tmp_path.name
    try:
        validate_safe_path(traversal, allowed_root=tmp_path)
        assert False, "Expected ValueError for '..' traversal"
    except ValueError:
        assert True

    try:
        validate_safe_path("/tmp/bad\x00path.jpg")
        assert False, "Expected ValueError for null byte"
    except ValueError:
        assert True


def test_symlink_handling(tmp_path: Path) -> None:
    real_dir = tmp_path / "real"
    real_dir.mkdir()
    secret = tmp_path / "secret.jpg"
    secret.write_bytes(b"\xff\xd8\xff\xe0secret-bytes-1234")
    normal = real_dir / "normal.jpg"
    normal.write_bytes(b"\xff\xd8\xff\xe0normal-bytes-1234")
    symlink_file = real_dir / "linked.jpg"
    symlink_file.symlink_to(secret)

    report = scan_tree(real_dir)
    scanned_names = [e["name"] for e in report["entries"]]
    assert "normal.jpg" in scanned_names
    assert "linked.jpg" not in scanned_names

    symlink_dir = tmp_path / "linked_dir"
    symlink_dir.symlink_to(real_dir)
    try:
        scan_tree(symlink_dir)
        assert False, "Expected symlinked root directory to be rejected"
    except ValueError:
        assert True


def test_media_classification_and_corruption(tmp_path: Path) -> None:
    assert classify_media_file("WhatsApp Images/IMG-01.jpg") == "photos"
    assert classify_media_file("WhatsApp Video/VID-01.mp4") == "videos"
    assert classify_media_file("WhatsApp Voice Notes/PTT-01.opus") == "voice_notes"
    assert classify_media_file("WhatsApp Audio/AUD-01.mp3") == "audio"
    assert classify_media_file("WhatsApp Documents/DOC-01.pdf") == "documents"
    assert classify_media_file("WhatsApp Stickers/STK-01.webp") == "stickers"
    assert classify_media_file("WhatsApp Animated Gifs/GIF-01.gif") == "gifs"
    assert classify_media_file("WhatsApp Images/.Thumbs/thumb-01.jpg") == "thumbnails"

    bad_jpg = tmp_path / "broken.jpg"
    bad_jpg.write_bytes(b"\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x10\x11\x12\x13\x14\x15\x16\x17")
    integrity = inspect_media_integrity(bad_jpg)
    assert integrity["corrupt"] is True

    good_jpg = tmp_path / "valid.jpg"
    good_jpg.write_bytes(b"\xff\xd8\xff\xe0\x00\x10JFIF\x00\x01\x01\x00\x00\x01\xff\xd9")
    assert inspect_media_integrity(good_jpg)["corrupt"] is False

    report = scan_tree(tmp_path)
    corrupt_only = filter_media_entries(report["entries"], only_corrupt=True)
    assert len(corrupt_only) == 1 and corrupt_only[0]["name"] == "broken.jpg"
