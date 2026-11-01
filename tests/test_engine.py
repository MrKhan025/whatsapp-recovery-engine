from pathlib import Path
from wtk.engine import compare_snapshots, verified_export

def entry(path, digest, size=3):
    return {"path":str(path),"name":Path(path).name,"sha256":digest,"size":size,"kind":"media"}

def test_compare_snapshots_detects_changes(tmp_path):
    oldroot=tmp_path/"old"; newroot=tmp_path/"new"
    oldroot.mkdir(); newroot.mkdir()
    old={"source":str(oldroot),"entries":[entry(oldroot/"same.jpg","a"),entry(oldroot/"gone.jpg","b")]}
    new={"source":str(newroot),"entries":[entry(newroot/"same.jpg","a"),entry(newroot/"new.jpg","c")]}
    result=compare_snapshots(old,new)
    assert result["summary"] == {"added":1,"removed":1,"changed":0,"unchanged":1}

def test_verified_export(tmp_path):
    src=tmp_path/"src"; dst=tmp_path/"out"; src.mkdir()
    photo=src/"pic.jpg"; photo.write_bytes(b"my-photo")
    result=verified_export(src,[str(photo)],dst)
    assert result["verified_count"] == 1
    assert (dst/"pic.jpg").read_bytes() == b"my-photo"

def test_export_refuses_inside_source(tmp_path):
    src=tmp_path/"src"; src.mkdir()
    f=src/"x.jpg"; f.write_bytes(b"x")
    try:
        verified_export(src,[str(f)],src/"inside")
        assert False
    except ValueError:
        assert True

def test_export_does_not_overwrite(tmp_path):
    src=tmp_path/"src"; dst=tmp_path/"dst"; src.mkdir(); dst.mkdir()
    f=src/"a.jpg"; f.write_bytes(b"new")
    (dst/"a.jpg").write_bytes(b"existing")
    result=verified_export(src,[str(f)],dst)
    assert result["verified_count"] == 0
    assert (dst/"a.jpg").read_bytes() == b"existing"
