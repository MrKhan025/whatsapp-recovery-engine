"""Automated tests for v2.0 forensic subsystems: CRYPT12/14/15, SQLite/WAL, Media, AI, Evidence, Verification, Reports."""
from __future__ import annotations

import sqlite3
import struct
import tempfile
import unittest
from pathlib import Path

from wtk.adb import device_check, discover_local_whatsapp_folders, get_android_guidance, verify_adb_transfer
from wtk.chat_analyzer import (
    analyze_conversation_gaps,
    analyze_group_conversations,
    compare_chat_databases,
    detect_duplicate_messages,
    export_chat_records,
    inspect_chat_database,
    inspect_sqlite_wal,
    link_chat_media,
    match_contacts,
    parse_chat_export,
    parse_contacts_file,
    search_chat_messages,
)
from wtk.decryptor import (
    FORMAT_SPECS,
    create_synthetic_crypt_fixture,
    decrypt_backup_with_user_key,
    identify_crypt_format,
    inspect_crypt_header,
    parse_user_key,
)
from wtk.engine import compare_multiple_snapshots, compare_snapshots
from wtk.evidence import EvidenceManager
from wtk.forensic_ai import generate_forensic_findings, summarize_conversation
from wtk.media_engine import (
    classify_media_file,
    extract_media_timestamp_metadata,
    generate_media_thumbnail,
    inspect_media_integrity,
)
from wtk.reports import (
    generate_all_scan_reports,
    write_forensic_bundle,
    write_verification_certificate,
)
from wtk.sample_bootstrap import ensure_sample_data
from wtk.scanner import scan_tree
from wtk.security import sha256_file
from wtk.verification import preview_recovery_operation, verified_export


class TestForensicEngineV2(unittest.TestCase):
    def test_crypt12_crypt14_crypt15_format_specs_and_decryption_fixtures(self) -> None:
        self.assertEqual(set(FORMAT_SPECS.keys()), {"crypt12", "crypt14", "crypt15"})
        self.assertNotEqual(FORMAT_SPECS["crypt12"]["key_derivation"], FORMAT_SPECS["crypt15"]["key_derivation"])

        with tempfile.TemporaryDirectory() as td:
            tmp_path = Path(td)
            raw_key = bytes(range(32))
            parsed_hex = parse_user_key(raw_key.hex())
            self.assertTrue(parsed_hex["valid"])
            self.assertEqual(parsed_hex["aes_key"], raw_key)

            key_file_158 = tmp_path / "key"
            key_file_158.write_bytes(b"\xac\xed\x00\x05" + b"\x00" * 122 + raw_key)
            parsed_158 = parse_user_key(key_file_158)
            self.assertTrue(parsed_158["valid"])
            self.assertEqual(parsed_158["aes_key"], raw_key)

            sample_db = tmp_path / "plain.db"
            conn = sqlite3.connect(sample_db)
            conn.execute("CREATE TABLE messages (_id INTEGER PRIMARY KEY, data TEXT);")
            conn.execute("INSERT INTO messages (data) VALUES ('Forensic fixture verification row');")
            conn.commit()
            conn.close()
            sqlite_bytes = sample_db.read_bytes()
            expected_sha = sha256_file(sample_db)

            for fmt in ("crypt12", "crypt14", "crypt15"):
                enc_file = tmp_path / f"msgstore.db.{fmt}"
                fixture = create_synthetic_crypt_fixture(fmt, sqlite_bytes, raw_key, enc_file)
                self.assertEqual(fixture["format"], fmt)
                self.assertEqual(identify_crypt_format(enc_file), fmt)

                header_info = inspect_crypt_header(enc_file)
                self.assertEqual(header_info["format"], fmt)
                self.assertTrue(header_info["header_complete"])

                out_db = tmp_path / f"decrypted_{fmt}.db"
                dec_result = decrypt_backup_with_user_key(
                    encrypted_path=enc_file,
                    key_input=raw_key.hex(),
                    output_db_path=out_db,
                )
                self.assertTrue(dec_result["decrypted"])
                self.assertEqual(dec_result["output_sha256"], expected_sha)

    def test_sqlite_inspection_wal_timeline_duplicates_and_contacts(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            tmp_path = Path(td)
            sample_root = ensure_sample_data(tmp_path / "samples")
            snap_v1 = sample_root / "snapshot_v1"
            snap_v2 = sample_root / "snapshot_v2"
            db_v1 = snap_v1 / "Databases" / "msgstore.db"
            db_v2 = snap_v2 / "Databases" / "msgstore.db"

            contacts = parse_contacts_file(snap_v2 / "Exports" / "contacts.vcf")
            self.assertGreaterEqual(len(contacts), 1)

            info_v2 = inspect_chat_database(db_v2)
            self.assertTrue(info_v2["is_sqlite"])
            self.assertTrue(info_v2["ok"])
            messages = info_v2["sample_messages"]
            self.assertGreaterEqual(len(messages), 4)

            matched = match_contacts(messages, contacts)
            self.assertEqual(len(matched), len(messages))

            dups = detect_duplicate_messages(messages)
            self.assertIn("duplicate_group_count", dups)

            gaps = analyze_conversation_gaps(messages)
            self.assertIn("gaps", gaps)

            groups = analyze_group_conversations(messages)
            self.assertIn("participant_count", groups)

            search_res = search_chat_messages(messages, query="backup")
            self.assertIn("results", search_res)

            diff = compare_chat_databases(db_v1, db_v2)
            self.assertIn("summary", diff)
            self.assertGreaterEqual(diff["summary"]["newly_discovered"], 1)

            export_dir = tmp_path / "chat_exports"
            for fmt in ("json", "csv", "html", "pdf"):
                out_path = export_chat_records(messages, export_dir, fmt=fmt)
                self.assertTrue(out_path.exists())

            txt_parsed = parse_chat_export(snap_v2 / "Exports" / "WhatsApp Chat with Operations Team.txt")
            self.assertGreaterEqual(txt_parsed["message_count"], 1)

    def test_wal_sidecar_inspection(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            tmp_path = Path(td)
            db_file = tmp_path / "test.db"
            db_file.write_bytes(b"SQLite format 3\x00" + b"\x00" * 84)
            wal_file = tmp_path / "test.db-wal"
            wal_header = struct.pack(">IIIIIIII", 0x377F0682, 3007000, 4096, 5, 111, 222, 333, 444)
            wal_file.write_bytes(wal_header + b"\x00" * (24 + 4096))

            wal_info = inspect_sqlite_wal(db_file)
            self.assertTrue(wal_info["wal_present"])
            self.assertTrue(wal_info["wal_valid_header"])
            self.assertEqual(wal_info["page_size"], 4096)
            self.assertEqual(wal_info["uncheckpointed_frames"], 1)

    def test_media_categories_orphaned_detection_and_thumbnails(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            tmp_path = Path(td)
            sample_root = ensure_sample_data(tmp_path / "samples")
            snap_v2 = sample_root / "snapshot_v2"
            scan_res = scan_tree(snap_v2)

            cat_counts = scan_res["category_counts"]
            for required_cat in ("photos", "videos", "voice_notes", "audio", "documents", "stickers", "gifs", "thumbnails"):
                self.assertIn(required_cat, cat_counts)
                self.assertGreaterEqual(cat_counts[required_cat], 1)

            db_v2 = snap_v2 / "Databases" / "msgstore.db"
            linkage = link_chat_media(db_v2, scan_res["entries"])
            self.assertIn("linked_count", linkage)
            self.assertIn("orphaned_media_count", linkage)

            photo_path = snap_v2 / "Media" / "WhatsApp Images" / "IMG-20261001-WA0001.jpg"
            self.assertEqual(classify_media_file(photo_path), "photos")

            ts_meta = extract_media_timestamp_metadata(photo_path)
            self.assertIn("reconstructed_date", ts_meta)

            thumb = generate_media_thumbnail(photo_path, tmp_path / "thumbs")
            self.assertTrue(thumb["generated"])
            self.assertTrue(Path(thumb["thumbnail_path"]).exists())

            integrity = inspect_media_integrity(photo_path)
            self.assertFalse(integrity["corrupt"])

    def test_forensic_ai_and_evidence_management(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            tmp_path = Path(td)
            sample_root = ensure_sample_data(tmp_path / "samples")
            snap_v1 = sample_root / "snapshot_v1"
            snap_v2 = sample_root / "snapshot_v2"

            res_v1 = scan_tree(snap_v1)
            res_v2 = scan_tree(snap_v2)
            cmp_res = compare_snapshots(res_v1, res_v2)
            multi_cmp = compare_multiple_snapshots([res_v1, res_v2])
            self.assertEqual(multi_cmp["snapshot_count"], 2)

            ai_report = generate_forensic_findings(res_v2, snapshot_comparison=cmp_res, enabled=True)
            self.assertEqual(ai_report["processing_mode"], "local_offline_heuristic")
            self.assertFalse(ai_report["external_transmission"])
            self.assertIsInstance(ai_report["verified_findings"], list)
            self.assertIsInstance(ai_report["inferred_observations"], list)

            db_info = inspect_chat_database(snap_v2 / "Databases" / "msgstore.db")
            conv_summary = summarize_conversation(db_info["sample_messages"], enabled=True)
            self.assertIn("message_count", conv_summary)

            ev_mgr = EvidenceManager()
            db_path = snap_v2 / "Databases" / "msgstore.db"
            ev_item = ev_mgr.register_evidence(db_path, category="sqlite_database", operator="examiner_test")
            self.assertTrue(ev_item["evidence_id"].startswith("EVID-"))
            self.assertEqual(len(ev_item["sha256"]), 64)
            self.assertEqual(len(ev_item["sha512"]), 128)

            verify_res = ev_mgr.verify_evidence_integrity(ev_item["evidence_id"])
            self.assertTrue(verify_res["verified"])

            unsigned_manifest = ev_mgr.generate_signed_manifest()
            self.assertEqual(unsigned_manifest["verification_mode"], "checksum_verified_only")

            signed_manifest = ev_mgr.generate_signed_manifest(signing_key="aa" * 32)
            self.assertEqual(signed_manifest["verification_mode"], "cryptographically_signed_hmac_sha256")
            self.assertTrue(signed_manifest["cryptographically_signed"])

    def test_recovery_preview_verification_and_reports(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            tmp_path = Path(td)
            sample_root = ensure_sample_data(tmp_path / "samples")
            snap_v2 = sample_root / "snapshot_v2"
            dest = tmp_path / "exports"
            target_file = str(snap_v2 / "Databases" / "msgstore.db")

            preview = preview_recovery_operation(
                source_root=snap_v2,
                file_paths=[target_file],
                destination=dest,
                allow_backups=True,
            )
            self.assertEqual(preview["ready_count"], 1)
            self.assertGreater(preview["total_bytes_to_copy"], 0)

            export_res = verified_export(
                source_root=snap_v2,
                file_paths=[target_file],
                destination=dest,
                allow_backups=True,
                signing_key="bb" * 32,
            )
            self.assertEqual(export_res["verified_count"], 1)
            self.assertEqual(
                export_res["verification_mode"],
                "cryptographically_signed_hmac_sha256",
            )

            scan_res = scan_tree(snap_v2)
            reports_dir = tmp_path / "reports"
            suite = generate_all_scan_reports(scan_res, reports_dir)
            for key in ("json", "csv", "pdf", "media", "db_health", "bundle"):
                self.assertIn(key, suite)
                self.assertTrue(Path(suite[key]).exists())

            cert_paths = write_verification_certificate(export_res, reports_dir)
            self.assertTrue(cert_paths["pdf"].exists())

            bundle_path = write_forensic_bundle(reports_dir)
            self.assertTrue(bundle_path.exists())

    def test_adb_helpers_and_transfer_verification(self) -> None:
        guidance = get_android_guidance()
        self.assertIn("wireless_adb_steps", guidance)
        adb_status = device_check()
        self.assertIn("available", adb_status)
        folders = discover_local_whatsapp_folders()
        self.assertIn("whatsapp", folders)

        with tempfile.TemporaryDirectory() as td:
            local_dir = Path(td)
            f1 = local_dir / "local_pull.db"
            f1.write_bytes(b"SQLite format 3\x00" + b"X" * 200)
            digest = sha256_file(f1)
            ver = verify_adb_transfer({"local_pull.db": digest}, local_dir)
            self.assertEqual(ver["verified_count"], 1)


if __name__ == "__main__":
    unittest.main()
