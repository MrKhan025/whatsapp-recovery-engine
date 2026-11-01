import json
from pathlib import Path
from reportlab.lib.pagesizes import A4
from reportlab.pdfgen import canvas

def write_json(report: dict, output: Path, filename="recovery-scan.json") -> Path:
    output.mkdir(parents=True, exist_ok=True)
    target = output / filename
    target.write_text(json.dumps(report, indent=2, ensure_ascii=False), encoding="utf-8")
    return target

def write_pdf(report: dict, output: Path) -> Path:
    output.mkdir(parents=True, exist_ok=True)
    target = output / "recovery-report.pdf"
    pdf = canvas.Canvas(str(target), pagesize=A4)
    width, height = A4
    y = height - 48
    pdf.setTitle("WhatsApp Recovery Engine - Scan Report")
    lines = [
        "WhatsApp Recovery Engine - Scan Report", f"Source: {report.get('source', '')}",
        f"Files scanned: {report.get('files_scanned', 0)}",
        f"Media files: {report.get('media_count', 0)}",
        f"Backup candidates: {report.get('backup_candidates', 0)}",
        f"Duplicate groups: {len(report.get('duplicates', []))}", "",
        "Inventory only: no decryption and no guarantee of deleted-data recovery.", "",
        "First 35 entries:"
    ]
    for line in lines:
        pdf.drawString(42, y, line[:110]); y -= 16
    for entry in report.get("entries", [])[:35]:
        pdf.drawString(42, y, f"{entry.get('kind')} | {entry.get('name')} | {entry.get('size')} bytes"[:110])
        y -= 13
        if y < 55:
            pdf.showPage(); y = height - 48
    pdf.save()
    return target
