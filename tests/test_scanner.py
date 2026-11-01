from pathlib import Path
import sqlite3
from wtk.scanner import scan_tree, inspect_sqlite, sha256_file

def test_scan_media_and_backup(tmp_path):
    (tmp_path/"photo.jpg").write_bytes(b"image-data")
    (tmp_path/"msgstore.db.crypt14").write_bytes(b"encrypted-placeholder")
    report=scan_tree(tmp_path)
    assert report["files_scanned"]==2 and report["media_count"]==1 and report["backup_candidates"]==1

def test_duplicate_detection(tmp_path):
    (tmp_path/"a.jpg").write_bytes(b"same"); (tmp_path/"b.jpg").write_bytes(b"same")
    assert len(scan_tree(tmp_path)["duplicates"])==1

def test_sqlite_integrity(tmp_path):
    db=tmp_path/"ok.db"; c=sqlite3.connect(db); c.execute("create table sample(id integer)"); c.commit(); c.close()
    assert inspect_sqlite(db)["ok"] is True

def test_hash(tmp_path):
    f=tmp_path/"a.bin"; f.write_bytes(b"abc")
    assert sha256_file(f)=="ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"

def test_missing_directory_rejected(tmp_path):
    try: scan_tree(tmp_path/"missing"); assert False
    except ValueError: assert True
