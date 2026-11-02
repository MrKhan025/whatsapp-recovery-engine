"""End-to-end API, session/CSRF, CLI, and main.py entrypoint tests for WhatsApp Recovery Engine v2.0."""
from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from fastapi.testclient import TestClient

from wtk.api import app
from wtk.cli import main as cli_main
from wtk.sample_bootstrap import ensure_sample_data


client = TestClient(app)


class TestApiAndCliV2(unittest.TestCase):
    def test_api_status_and_dashboard_12_sections(self) -> None:
        r = client.get("/api/status")
        self.assertEqual(r.status_code, 200)
        body = r.json()
        self.assertEqual(body["status"], "ok")
        self.assertEqual(body["version"], "2.0.0")

        html = client.get("/")
        self.assertEqual(html.status_code, 200)
        for section_id in (
            "tab-overview",
            "tab-workspace",
            "tab-chat",
            "tab-backup",
            "tab-media",
            "tab-timeline",
            "tab-adb",
            "tab-evidence",
            "tab-verify",
            "tab-reports",
            "tab-security",
            "tab-settings",
        ):
            self.assertIn(section_id, html.text)

    def test_api_session_csrf_and_security_audit(self) -> None:
        sess_res = client.post("/api/auth/session", json={"label": "pytest-client"})
        self.assertEqual(sess_res.status_code, 200)
        sess = sess_res.json()
        self.assertIn("token", sess)
        self.assertIn("csrf_token", sess)

        sec_res = client.get("/api/security-audit")
        self.assertEqual(sec_res.status_code, 200)
        sec_data = sec_res.json()
        self.assertTrue(sec_data["loopback_only_default"])
        self.assertFalse(sec_data["telemetry_enabled"])

    def test_api_scan_compare_preview_verify_and_evidence(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            tmp_path = Path(td)
            sample_root = ensure_sample_data(tmp_path / "samples")
            snap_v1 = sample_root / "snapshot_v1"
            snap_v2 = sample_root / "snapshot_v2"

            scan_1 = client.post("/api/scan", json={"source": str(snap_v1)})
            self.assertEqual(scan_1.status_code, 200)

            scan_2 = client.post("/api/scan", json={"source": str(snap_v2)})
            self.assertEqual(scan_2.status_code, 200)
            scan_data = scan_2.json()
            self.assertIn(scan_data["recovery_estimate"]["readiness"], ("Low", "Medium", "High"))
            self.assertIn("forensic_ai", scan_data)

            snaps = client.get("/api/snapshots").json()["snapshots"]
            self.assertGreaterEqual(len(snaps), 2)

            cmp_res = client.post(
                "/api/compare",
                json={"old": snaps[-2]["path"], "new": snaps[-1]["path"]},
            )
            self.assertEqual(cmp_res.status_code, 200)

            target_media = str(snap_v2 / "Media" / "WhatsApp Images" / "IMG-20261001-WA0001.jpg")
            target_db = str(snap_v2 / "Databases" / "msgstore.db")
            dest_dir = tmp_path / "api_exports"

            prev_res = client.post(
                "/api/export/preview",
                json={
                    "paths": [target_media],
                    "destination": str(dest_dir),
                },
            )
            self.assertEqual(prev_res.status_code, 200)
            self.assertEqual(prev_res.json()["ready_count"], 1)

            ver_res = client.post(
                "/api/export",
                json={
                    "paths": [target_media],
                    "destination": str(dest_dir),
                    "signing_key": "11" * 32,
                },
            )
            self.assertEqual(ver_res.status_code, 200)
            ver_data = ver_res.json()
            self.assertEqual(ver_data["verified_count"], 1)

            ev_reg = client.post(
                "/api/evidence/register",
                json={
                    "path": target_db,
                    "category": "sqlite_database",
                    "notes": "Primary chat database",
                    "operator": "api_test",
                },
            )
            self.assertEqual(ev_reg.status_code, 200)
            ev_id = ev_reg.json()["evidence_id"]

            ev_ver = client.post("/api/evidence/verify", json={"evidence_id": ev_id})
            self.assertEqual(ev_ver.status_code, 200)
            self.assertTrue(ev_ver.json()["verified"])

            man_res = client.post("/api/evidence/manifest", json={"signing_key": "22" * 32})
            self.assertEqual(man_res.status_code, 200)
            self.assertEqual(man_res.json()["verification_mode"], "cryptographically_signed_hmac_sha256")

    def test_api_rejects_unauthorized_path_traversal(self) -> None:
        bad_preview = client.get("/api/preview", params={"path": "../../etc/passwd"})
        self.assertIn(bad_preview.status_code, (400, 403))

    def test_cli_entrypoints(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            tmp_path = Path(td)
            sample_root = ensure_sample_data(tmp_path / "cli_samples")
            cli_main(["scan", "--source", str(sample_root / "snapshot_v2"), "--output", str(tmp_path / "cli_out")])
            self.assertTrue((tmp_path / "cli_out" / "recovery-scan.json").exists())


if __name__ == "__main__":
    unittest.main()
