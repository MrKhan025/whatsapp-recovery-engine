from pathlib import Path
from fastapi import FastAPI, HTTPException
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from .scanner import scan_tree, MEDIA_MIME, is_within
from .reports import write_json, write_pdf
from .engine import compare_snapshots, verified_export
from .adb import device_check
from .i18n import get_text
import json

app = FastAPI(title="WhatsApp Recovery Engine", version="2.0.0")
BASE = Path(__file__).resolve().parent.parent
REPORT_DIR = Path.home() / ".wte-reports"
REPORT_DIR.mkdir(parents=True, exist_ok=True)
LAST_REPORT = None

@app.get("/api/status")
def status():
    return {"status":"ok","offline":True,"version":"2.0.0","adb":device_check()}

@app.get("/api/i18n/{lang}")
def language(lang: str):
    return get_text(lang)

@app.post("/api/scan")
def scan(payload: dict):
    global LAST_REPORT
    source = payload.get("source")
    if not isinstance(source, str) or not source.strip():
        raise HTTPException(400, "A source directory is required")
    try:
        report = scan_tree(source)
        stamp = __import__("time").strftime("%Y%m%d-%H%M%S")
        write_json(report, REPORT_DIR, f"scan-{stamp}.json")
        write_json(report, REPORT_DIR, "recovery-scan.json")
        write_pdf(report, REPORT_DIR)
        LAST_REPORT = report
        return {**report, "entries": report["entries"][:1000]}
    except (ValueError, OSError) as exc:
        raise HTTPException(400, str(exc))

@app.get("/api/snapshots")
def snapshots():
    return {"snapshots":[{"name":p.name,"path":str(p),"modified":int(p.stat().st_mtime)}
                         for p in sorted(REPORT_DIR.glob("scan-*.json"))[-30:]]}

@app.post("/api/compare")
def compare(payload: dict):
    try:
        old = Path(payload.get("old","")).resolve()
        new = Path(payload.get("new","")).resolve()
        if not is_within(old, REPORT_DIR) or not is_within(new, REPORT_DIR):
            raise ValueError("Choose snapshots created by this toolkit")
        return compare_snapshots(json.loads(old.read_text()), json.loads(new.read_text()))
    except (ValueError, OSError, json.JSONDecodeError, KeyError) as exc:
        raise HTTPException(400, str(exc))

@app.get("/api/preview")
def preview(path: str):
    if LAST_REPORT is None:
        raise HTTPException(400, "Run a scan first")
    candidate = Path(path).resolve()
    root = Path(LAST_REPORT["source"]).resolve()
    allowed = {Path(e["path"]).resolve() for e in LAST_REPORT["entries"] if e.get("kind") == "media"}
    if candidate not in allowed or not is_within(candidate, root) or candidate.suffix.lower() not in MEDIA_MIME:
        raise HTTPException(403, "Preview is restricted to supported media in the latest scan")
    return FileResponse(candidate, media_type=MEDIA_MIME[candidate.suffix.lower()],
                        headers={"Content-Disposition":"inline","X-Content-Type-Options":"nosniff"})

@app.post("/api/export")
def export(payload: dict):
    if LAST_REPORT is None:
        raise HTTPException(400, "Run a scan first")
    paths = payload.get("paths")
    destination = payload.get("destination")
    if not isinstance(paths, list) or not isinstance(destination, str):
        raise HTTPException(400, "paths and destination are required")
    try:
        allowed = {e["path"] for e in LAST_REPORT["entries"] if e.get("kind") == "media"}
        if any(p not in allowed for p in paths):
            raise ValueError("Select media from the latest scan only")
        return verified_export(LAST_REPORT["source"], paths, destination)
    except (ValueError, OSError) as exc:
        raise HTTPException(400, str(exc))

@app.get("/api/report/{kind}")
def download_report(kind: str):
    if kind not in ("pdf","json"):
        raise HTTPException(404,"Unknown report type")
    path = REPORT_DIR / ("recovery-report.pdf" if kind=="pdf" else "recovery-scan.json")
    if not path.exists():
        raise HTTPException(404,"Run a scan first")
    return FileResponse(path,filename=path.name)

app.mount("/", StaticFiles(directory=BASE/"web", html=True), name="web")
