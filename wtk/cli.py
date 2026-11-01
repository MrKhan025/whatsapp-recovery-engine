import argparse, json
from pathlib import Path
import uvicorn
from .scanner import scan_tree, inspect_sqlite
from .reports import write_json, write_pdf
from .engine import compare_snapshots, load_snapshot
from .adb import device_check

def main():
    parser=argparse.ArgumentParser(prog="wtk",description="Offline WhatsApp backup/media diagnostics")
    sub=parser.add_subparsers(dest="command",required=True)
    s=sub.add_parser("scan"); s.add_argument("--source",required=True); s.add_argument("--output",default="./reports")
    c=sub.add_parser("compare"); c.add_argument("old"); c.add_argument("new")
    db=sub.add_parser("inspect-db"); db.add_argument("path")
    sub.add_parser("adb-check")
    srv=sub.add_parser("serve"); srv.add_argument("--host",default="127.0.0.1"); srv.add_argument("--port",type=int,default=8000)
    a=parser.parse_args()
    if a.command=="scan":
        report=scan_tree(a.source); out=Path(a.output)
        stamp=__import__("time").strftime("%Y%m%d-%H%M%S")
        print(write_json(report,out,f"scan-{stamp}.json")); print(write_json(report,out)); print(write_pdf(report,out))
        print(json.dumps({k:v for k,v in report.items() if k!="entries"},indent=2))
    elif a.command=="compare":
        print(json.dumps(compare_snapshots(load_snapshot(a.old),load_snapshot(a.new)),indent=2))
    elif a.command=="inspect-db":
        from .scanner import inspect_sqlite
        print(json.dumps(inspect_sqlite(Path(a.path)),indent=2))
    elif a.command=="adb-check": print(json.dumps(device_check(),indent=2))
    elif a.command=="serve": uvicorn.run("wtk.api:app",host=a.host,port=a.port,reload=False)

if __name__=="__main__": main()
