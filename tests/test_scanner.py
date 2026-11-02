"""Automated tests for scanner, security controls, path/symlink protection, sessions, and encrypted temp store."""
from __future__ import annotations

import os
import tempfile
import unittest
from pathlib import Path

from wtk.engine import compare_snapshots
from wtk.scanner import scan_tree
from wtk.security import (
    AuditLogger,
    EncryptedTempStore,
    LocalSessionManager,
    audit_dependencies,
    dual_checksum_file,
    has_symlink_in_chain,
    is_within,
    sanitize_search_query,
    sha256_file,
    sha512_file,
    validate_safe_path,
)


class TestScannerAndSecurity(unittest.TestCase):
    def test_security_path_traversal_and_null_byte_blocked(self) -> None:
        with self.assertRaises(ValueError):
            validate_safe_path("bad\x00path", must_exist=False)

        with tempfile.TemporaryDirectory() as td:
            tmp_path = Path(td)
            base = tmp_path / "workspace"
            base.mkdir()
            outside = tmp_path / "secret.txt"
            outside.write_text("top secret", encoding="utf-8")

            with self.assertRaises(ValueError):
                validate_safe_path(f"{base}/../secret.txt", allowed_root=base)

    def test_security_symlink_rejection(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            tmp_path = Path(td)
            real_dir = tmp_path / "real"
            real_dir.mkdir()
            secret_file = tmp_path / "outside.db"
            secret_file.write_bytes(b"SQLite format 3\x00" + b"\x00" * 100)

            symlink_dir = tmp_path / "symlink_dir"
            try:
                os.symlink(real_dir, symlink_dir)
            except OSError:
                self.skipTest("Symlinks not supported on this platform")

            self.assertTrue(has_symlink_in_chain(symlink_dir))
            with self.assertRaises(ValueError):
                validate_safe_path(symlink_dir, allow_symlinks=False)

            symlink_file = real_dir / "linked.db"
            os.symlink(secret_file, symlink_file)

            with self.assertRaises(ValueError):
                validate_safe_path(symlink_file, allowed_root=real_dir, allow_symlinks=False)

            scan_res = scan_tree(real_dir)
            self.assertEqual(scan_res["files_scanned"], 0)

    def test_security_file_size_limit_enforcement(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            sample = Path(td) / "blob.bin"
            sample.write_bytes(b"A" * 2048)
            resolved = validate_safe_path(sample, max_file_size=4096)
            self.assertTrue(resolved.exists())

            with self.assertRaises(ValueError):
                validate_safe_path(sample, max_file_size=512)

    def test_security_dual_hashes_and_query_sanitization(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            sample = Path(td) / "payload.txt"
            sample.write_bytes(b"forensic verification payload")
            sha256_hex = sha256_file(sample)
            sha512_hex = sha512_file(sample)
            dual = dual_checksum_file(sample)

            self.assertEqual(len(sha256_hex), 64)
            self.assertEqual(len(sha512_hex), 128)
            self.assertEqual(dual, {"sha256": sha256_hex, "sha512": sha512_hex})
            self.assertEqual(sanitize_search_query("hello\x00world"), "helloworld")
            self.assertTrue(is_within(sample, Path(td)))

    def test_security_local_session_manager_and_csrf(self) -> None:
        mgr = LocalSessionManager(ttl_seconds=120, enforce_by_default=False)
        sess = mgr.create_session(label="unit-test")
        self.assertTrue(sess["token"])
        self.assertTrue(sess["csrf_token"])

        valid = mgr.verify_request(
            token=sess["token"],
            csrf_token=sess["csrf_token"],
            require_csrf=True,
        )
        self.assertTrue(valid)

        strict_mgr = LocalSessionManager(ttl_seconds=120, enforce_by_default=True)
        strict_sess = strict_mgr.create_session(label="strict")
        self.assertFalse(
            strict_mgr.verify_request(
                token="invalid_token",
                csrf_token=strict_sess["csrf_token"],
                require_csrf=True,
            )
        )
        self.assertFalse(
            strict_mgr.verify_request(
                token=strict_sess["token"],
                csrf_token="bad_csrf",
                require_csrf=True,
            )
        )
        self.assertTrue(strict_mgr.revoke_session(strict_sess["token"]))

    def test_security_encrypted_temp_store_and_audit_redaction(self) -> None:
        store = EncryptedTempStore()
        plaintext = b"sensitive temporary key material 0123456789abcdef"
        enc_path = store.write_encrypted_temp(plaintext)
        self.assertTrue(enc_path.exists())
        recovered = store.read_encrypted_temp(enc_path)
        self.assertEqual(recovered, plaintext)
        cleaned = store.cleanup_all()
        self.assertGreaterEqual(cleaned, 1)
        self.assertFalse(enc_path.exists())

        logger = AuditLogger()
        entry = logger.log(
            "decrypt_attempt",
            status="ok",
            details={
                "backup": "msgstore.db.crypt15",
                "key_hex": "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff",
                "message_body": "Private message content that must never be logged",
            },
        )
        self.assertEqual(entry["details"]["key_hex"], "[REDACTED]")
        self.assertEqual(entry["details"]["message_body"], "[REDACTED]")
        self.assertEqual(entry["details"]["backup"], "msgstore.db.crypt15")

        dep_audit = audit_dependencies()
        self.assertIn("dependencies", dep_audit)

    def test_scan_tree_and_compare_snapshots(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            tmp_path = Path(td)
            snap_a = tmp_path / "snap_a"
            snap_b = tmp_path / "snap_b"
            snap_a.mkdir()
            snap_b.mkdir()

            (snap_a / "msgstore.db.crypt14").write_bytes(b"\x00\x02" + b"A" * 600)
            (snap_a / "IMG-20250101-WA0001.jpg").write_bytes(b"\xff\xd8\xff\xe0" + b"J" * 300)

            (snap_b / "msgstore.db.crypt14").write_bytes(b"\x00\x02" + b"B" * 650)
            (snap_b / "IMG-20250101-WA0001.jpg").write_bytes(b"\xff\xd8\xff\xe0" + b"J" * 300)
            (snap_b / "PTT-20250102-WA0001.opus").write_bytes(b"OggS" + b"O" * 200)

            res_a = scan_tree(snap_a)
            res_b = scan_tree(snap_b)
            self.assertEqual(res_a["files_scanned"], 2)
            self.assertEqual(res_b["files_scanned"], 3)

            diff = compare_snapshots(res_a, res_b)
            self.assertEqual(len(diff["added"]), 1)
            self.assertEqual(len(diff["changed"]), 1)
            self.assertEqual(len(diff["unchanged"]), 1)


if __name__ == "__main__":
    unittest.main()
