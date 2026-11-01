"""Automated tests for FastAPI endpoints, chat analyzer, backup analyzer,
recovery estimator, and report generation.
"""

from pathlib import Path
from fastapi.testclient import TestClient
from wtk.api import app, SAMPLE_DATA_DIR
from wtk.chat_analyzer import compare_chat_databases, inspect_chat_database, parse_chat_export, search_chat_messages
from wtk.reports import (
    generate_all_scan_reports,
    write_backup_comparison_report,
    write_verification_certificate,
)
from wtk.sample_bootstrap import ensure_sample_data


def test_status_and_i18n() -> None:
    client = TestClient(app)
    r = client.get("/api/status")
    assert r.status_code == 200
    data = r.json()
    assert data["offline"] is True
    assert data["version"] == "1.0.0"

    for lang in ("en", "hi", "ur"):
        ir = client.get(f"/api/i18n/{lang}")
        assert ir.status_code == 200
        assert "title" in ir.json()


def test_android_and_security_endpoints() -> None:
    client = TestClient(app)
    ag = client.get("/api/android-guidance")
    assert ag.status_code == 200
    assert "termux_commands" in ag.json()

    sec = client.get("/api/security-audit")
    assert sec.status_code == 200
    assert sec.json()["local_only_processing"] is True
    assert sec.json()["telemetry_enabled"] is False


def test_full_api_workflow(tmp_path: Path) -> None:
    ensure_sample_data(SAMPLE_DATA_DIR)
    client = TestClient(app)
    v1_path = SAMPLE_DATA_DIR / "snapshot_v1"
    v2_path = SAMPLE_DATA_DIR / "snapshot_v2"

    # 1. Scan v1 and v2
    r1 = client.post("/api/scan", json={"source": str(v1_path)})
    assert r1.status_code == 200
    r2 = client.post("/api/scan", json={"source": str(v2_path)})
    assert r2.status_code == 200
    scan_data = r2.json()
    assert scan_data["media_count"] >= 8
    assert scan_data["recovery_estimate"]["readiness"] in ("Low", "Medium", "High")

    # 2. Filter media
    mf = client.post("/api/media/filter", json={"category": "photos"})
    assert mf.status_code == 200
    assert mf.json()["count"] >= 2

    # 3. Chat search & DB comparison via API
    cs = client.post("/api/chat/search", json={"query": "verification"})
    assert cs.status_code == 200
    assert cs.json()["match_count"] >= 1

    dbc = client.post(
        "/api/chat/compare-db",
        json={
            "old_db": str(v1_path / "Databases" / "msgstore.db"),
            "new_db": str(v2_path / "Databases" / "msgstore.db"),
        },
    )
    assert dbc.status_code == 200
    assert dbc.json()["summary"]["missing_in_new"] == 1
    assert dbc.json()["summary"]["changed_records"] == 1
    assert dbc.json()["summary"]["newly_discovered"] == 2

    # 4. Preview valid media & reject non-scanned path
    photo_path = str(v2_path / "Media" / "WhatsApp Images" / "IMG-20261001-WA0001.jpg")
    prev = client.get("/api/preview", params={"path": photo_path})
    assert prev.status_code == 200

    bad_prev = client.get("/api/preview", params={"path": "/etc/passwd"})
    assert bad_prev.status_code == 403

    # 5. Export & verify
    export_dest = tmp_path / "verified_out"
    exp = client.post("/api/export", json={"paths": [photo_path], "destination": str(export_dest)})
    assert exp.status_code == 200
    assert exp.json()["verified_count"] == 1

    # 6. Download generated reports
    for kind in ("pdf", "json", "csv", "media", "db-health", "certificate-json", "certificate-pdf"):
        rep = client.get(f"/api/report/{kind}")
        assert rep.status_code == 200


def test_chat_exports_and_reports(tmp_path: Path) -> None:
    ensure_sample_data(SAMPLE_DATA_DIR)
    v2_exports = SAMPLE_DATA_DIR / "snapshot_v2" / "Exports"
    txt_res = parse_chat_export(v2_exports / "WhatsApp Chat with Operations Team.txt")
    json_res = parse_chat_export(v2_exports / "chat_export.json")
    html_res = parse_chat_export(v2_exports / "chat_export.html")

    assert txt_res["message_count"] == 3
    assert json_res["message_count"] == 2
    assert html_res["message_count"] == 2

    s_res = search_chat_messages(txt_res["messages"], query="checksums")
    assert s_res["match_count"] == 1

    from wtk.scanner import scan_tree
    report = scan_tree(SAMPLE_DATA_DIR / "snapshot_v2")
    out_dir = tmp_path / "reports_out"
    paths = generate_all_scan_reports(report, out_dir)
    for p in paths.values():
        assert Path(p).exists() and Path(p).stat().st_size > 0

    cmp_path = write_backup_comparison_report({"summary": {"added": 1, "removed": 0, "changed": 0, "unchanged": 5}}, out_dir)
    assert cmp_path.exists()

    certs = write_verification_certificate(
        {
            "certificate_id": "WRE-CERT-TEST",
            "timestamp": "2026-11-01 00:00:00 UTC",
            "source_root": "/src",
            "destination": "/dst",
            "total_requested": 1,
            "verified_count": 1,
            "failed_count": 0,
            "manifest_sha256": "a" * 64,
            "results": [{"source": "/src/a.jpg", "destination": "/dst/a.jpg", "size": 10, "source_sha256": "b" * 64, "destination_sha256": "b" * 64, "verified": True}],
        },
        out_dir,
    )
    assert certs["json"].exists() and certs["pdf"].exists()
