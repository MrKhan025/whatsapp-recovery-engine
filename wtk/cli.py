"""Command-Line Interface (`wtk/cli.py`) for WhatsApp Recovery Engine v2.0."""

from __future__ import annotations

import argparse
import json
import sys
import time
from pathlib import Path

import uvicorn

from .adb import get_android_guidance
from .chat_analyzer import compare_chat_databases, inspect_chat_database, parse_chat_export
from .engine import compare_snapshots, load_snapshot, preview_recovery_operation, verified_export
from .reports import generate_all_scan_reports, write_json, write_verification_certificate
from .sample_bootstrap import ensure_sample_data
from .scanner import scan_tree
from .security import audit_dependencies


def main(argv: list[str] | None = None) -> int:
    """Main CLI entry point for `python main.py` and `python -m wtk`."""
    args_list = list(sys.argv[1:] if argv is None else argv)
    if not args_list:
        args_list = ["serve"]

    parser = argparse.ArgumentParser(
        prog="python main.py",
        description="WhatsApp Recovery Engine v2.0 — Professional Digital Forensics & Backup Recovery Platform",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    s = sub.add_parser("scan", help="Scan an accessible directory and generate forensic reports")
    s.add_argument("pos_source", nargs="?", default=None, help="Directory to scan (positional or --source)")
    s.add_argument("--source", dest="opt_source", default=None, help="Directory to scan in read-only mode")
    s.add_argument("--output", "--report-dir", dest="output", default="./reports", help="Output directory for generated reports")

    c = sub.add_parser("compare", help="Compare two saved scan JSON snapshots")
    c.add_argument("old", help="Older snapshot JSON path")
    c.add_argument("new", help="Newer snapshot JSON path")

    db = sub.add_parser("inspect-db", help="Inspect an accessible SQLite chat database in read-only mode")
    db.add_argument("path", help="Path to SQLite database file")

    db_cmp = sub.add_parser("compare-db", help="Compare two accessible SQLite chat database snapshots")
    db_cmp.add_argument("old_db", help="Older SQLite database path")
    db_cmp.add_argument("new_db", help="Newer SQLite database path")

    exp = sub.add_parser("parse-export", help="Parse a TXT, JSON, or HTML chat export")
    exp.add_argument("path", help="Path to chat export file")

    ver = sub.add_parser("verify-export", help="Copy files safely and verify SHA-256 and SHA-512 checksums")
    ver.add_argument("--source", required=True, help="Source root directory")
    ver.add_argument("--destination", required=True, help="Destination directory outside source")
    ver.add_argument("--preview", action="store_true", help="Preview operation without copying bytes")
    ver.add_argument("files", nargs="+", help="Files to copy and verify")

    sub.add_parser("adb-check", help="Check connected ADB devices and Android guidance")
    sub.add_parser("security-audit", help="Run local security and dependency posture check")

    init_s1 = sub.add_parser("init-sample", help="Generate synthetic zero-PII sample data in ./sample-data")
    init_s1.add_argument("--target", default=None, help="Optional target directory for sample snapshots")

    init_s2 = sub.add_parser("init-samples", help="Alias for init-sample")
    init_s2.add_argument("--target", default=None, help="Optional target directory for sample snapshots")

    srv = sub.add_parser("serve", help="Start the local responsive web dashboard (default)")
    srv.add_argument("--host", default="127.0.0.1", help="Bind host (default: 127.0.0.1)")
    srv.add_argument("--port", type=int, default=8000, help="Bind port (default: 8000)")

    args = parser.parse_args(args_list)
    default_sample_dir = Path(__file__).resolve().parent.parent / "sample-data"

    if args.command in ("init-sample", "init-samples"):
        target_dir = Path(args.target) if getattr(args, "target", None) else default_sample_dir
        root = ensure_sample_data(target_dir)
        print(f"Sample data initialized at: {root}")
        return 0

    if args.command == "scan":
        scan_source = args.opt_source or args.pos_source
        if not scan_source:
            parser.error("scan requires a source directory (pass positional path or --source PATH)")
        ensure_sample_data(default_sample_dir)
        report = scan_tree(scan_source)
        out = Path(args.output)
        stamp = time.strftime("%Y%m%d-%H%M%S")
        snap_path = write_json(report, out, f"scan-{stamp}.json")
        generated = generate_all_scan_reports(report, out)
        print(f"Snapshot: {snap_path}")
        for k, v in generated.items():
            print(f"Report [{k}]: {v}")
        summary = {k: v for k, v in report.items() if k not in ("entries", "chat_exports", "chat_databases")}
        print(json.dumps(summary, indent=2))
        return 0

    if args.command == "compare":
        print(json.dumps(compare_snapshots(load_snapshot(args.old), load_snapshot(args.new)), indent=2))
        return 0

    if args.command == "inspect-db":
        print(json.dumps(inspect_chat_database(Path(args.path)), indent=2))
        return 0

    if args.command == "compare-db":
        print(json.dumps(compare_chat_databases(Path(args.old_db), Path(args.new_db)), indent=2))
        return 0

    if args.command == "parse-export":
        print(json.dumps(parse_chat_export(Path(args.path)), indent=2))
        return 0

    if args.command == "verify-export":
        if args.preview:
            print(json.dumps(preview_recovery_operation(args.source, args.files, args.destination), indent=2))
        else:
            res = verified_export(args.source, args.files, args.destination)
            certs = write_verification_certificate(res, Path(args.destination))
            print(json.dumps({**res, "certificates": {k: str(v) for k, v in certs.items()}}, indent=2))
        return 0

    if args.command == "adb-check":
        print(json.dumps(get_android_guidance(), indent=2))
        return 0

    if args.command == "security-audit":
        print(json.dumps(audit_dependencies(), indent=2))
        return 0

    if args.command == "serve":
        ensure_sample_data(default_sample_dir)
        print("==========================================================")
        print("  WhatsApp Recovery Engine v2.0 — Forensic Dashboard      ")
        print(f"  URL: http://{args.host}:{args.port}                     ")
        print("  Press Ctrl+C to stop the server.                        ")
        print("==========================================================")
        uvicorn.run("wtk.api:app", host=args.host, port=args.port, reload=False)
        return 0

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
