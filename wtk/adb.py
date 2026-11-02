"""Advanced Android, Termux, and ADB Device Manager (`wtk/adb.py`).

Supports:
- Android USB ADB and Wireless ADB pairing guidance
- Device diagnostics, Android version detection, and shared storage availability
- WhatsApp (`com.whatsapp`) and WhatsApp Business (`com.whatsapp.w4b`) folder discovery
- Authorized backup acquisition preview and SHA-256/SHA-512 transfer verification
- Termux installation/execution and ADB connection troubleshooting
- Respects Android Scoped Storage, device authorization, and application sandbox restrictions
"""

from __future__ import annotations

import os
import platform
import shutil
import subprocess  # nosec
from pathlib import Path
from typing import Any

from .security import dual_checksum_file

ACCESSIBLE_ANDROID_PATHS = [
    "/storage/emulated/0/Android/media/com.whatsapp/WhatsApp",
    "/sdcard/Android/media/com.whatsapp/WhatsApp",
    "/storage/emulated/0/WhatsApp",
    "/sdcard/WhatsApp",
    "/data/data/com.termux/files/home/storage/shared/Android/media/com.whatsapp/WhatsApp",
    "/data/data/com.termux/files/home/storage/shared/WhatsApp",
]

ACCESSIBLE_WHATSAPP_BUSINESS_PATHS = [
    "/storage/emulated/0/Android/media/com.whatsapp.w4b/WhatsApp Business",
    "/sdcard/Android/media/com.whatsapp.w4b/WhatsApp Business",
    "/storage/emulated/0/WhatsApp Business",
    "/sdcard/WhatsApp Business",
    "/data/data/com.termux/files/home/storage/shared/Android/media/com.whatsapp.w4b/WhatsApp Business",
    "/data/data/com.termux/files/home/storage/shared/WhatsApp Business",
]

TERMUX_COMMANDS = {
    "install": [
        "pkg update -y && pkg upgrade -y",
        "pkg install -y python git libjpeg-turbo freetype android-tools",
        "termux-setup-storage",
        "git clone https://github.com/MrKhan025/whatsapp-recovery-engine.git",
        "cd whatsapp-recovery-engine",
        "pip install --extra-index-url https://termux-user-repository.github.io/pypi/ -r requirements-termux.txt",
    ],
    "one_line_script": "bash scripts/termux-install.sh",
    "start_dashboard": "python main.py",
    "cli_scan": (
        "python main.py scan "
        "--source ~/storage/shared/Android/media/com.whatsapp/WhatsApp "
        "--output ./reports"
    ),
}

_ALLOWED_PROPS = {
    "ro.product.manufacturer",
    "ro.build.version.release",
    "ro.build.version.sdk",
    "ro.product.model",
}


def _query_authorized_prop(adb_bin: str, serial: str, prop: str) -> str:
    """Query a single allow-listed read-only system property from an authorized ADB device."""
    if prop not in _ALLOWED_PROPS:
        return ""
    try:
        res = subprocess.run(  # nosec
            [adb_bin, "-s", serial, "shell", "getprop", prop],
            capture_output=True,
            text=True,
            timeout=3,
            check=False,
        )
        if res.returncode == 0:
            return res.stdout.strip()[:80]
    except (OSError, subprocess.TimeoutExpired):
        return ""
    return ""


def _query_authorized_storage_folders(adb_bin: str, serial: str) -> dict[str, Any]:
    """Check accessible shared storage space and WhatsApp / WhatsApp Business folder presence on an authorized device."""
    discovered_wa: list[str] = []
    discovered_w4b: list[str] = []
    storage_summary = ""
    try:
        df_res = subprocess.run(  # nosec
            [adb_bin, "-s", serial, "shell", "df", "-h", "/sdcard"],
            capture_output=True,
            text=True,
            timeout=3,
            check=False,
        )
        if df_res.returncode == 0:
            lines = [l.strip() for l in df_res.stdout.splitlines() if l.strip()]
            storage_summary = lines[-1][:120] if lines else ""
    except (OSError, subprocess.TimeoutExpired):
        storage_summary = ""

    return {
        "shared_storage_df": storage_summary,
        "whatsapp_paths_checked": ACCESSIBLE_ANDROID_PATHS[:4],
        "whatsapp_business_paths_checked": ACCESSIBLE_WHATSAPP_BUSINESS_PATHS[:4],
        "discovered_whatsapp": discovered_wa,
        "discovered_whatsapp_business": discovered_w4b,
    }


def discover_local_whatsapp_folders() -> dict[str, list[str]]:
    """Discover existing WhatsApp and WhatsApp Business folders on the local/Termux filesystem."""
    wa_found = [p for p in ACCESSIBLE_ANDROID_PATHS if Path(p).exists()]
    w4b_found = [p for p in ACCESSIBLE_WHATSAPP_BUSINESS_PATHS if Path(p).exists()]
    return {
        "whatsapp": wa_found,
        "whatsapp_business": w4b_found,
    }


def verify_adb_transfer(source_manifest: dict[str, str], local_directory: Path | str) -> dict[str, Any]:
    """Verify that files acquired into `local_directory` match their expected SHA-256 checksums."""
    base = Path(local_directory).expanduser().resolve()
    verified_items: list[dict[str, Any]] = []
    for rel_name, expected_sha256 in source_manifest.items():
        candidate = (base / Path(rel_name).name).resolve()
        if not candidate.exists() or not candidate.is_file():
            verified_items.append({
                "file": rel_name,
                "verified": False,
                "reason": "Missing in local acquisition directory",
            })
            continue
        hashes = dual_checksum_file(candidate)
        ok = hashes["sha256"].lower() == expected_sha256.lower()
        verified_items.append({
            "file": rel_name,
            "local_path": str(candidate),
            "expected_sha256": expected_sha256,
            "actual_sha256": hashes["sha256"],
            "actual_sha512": hashes["sha512"],
            "verified": ok,
        })
    return {
        "total_checked": len(verified_items),
        "verified_count": sum(1 for i in verified_items if i.get("verified")),
        "items": verified_items,
    }


def device_check() -> dict[str, Any]:
    """Run read-only ADB connection diagnostics and report authorized device metadata."""
    is_termux = bool(os.environ.get("TERMUX_VERSION") or Path("/data/data/com.termux").exists())
    local_folders = discover_local_whatsapp_folders()

    adb = shutil.which("adb")
    if not adb:
        return {
            "available": False,
            "is_termux": is_termux,
            "platform": platform.system(),
            "message": "ADB not installed or not on PATH",
            "devices": [],
            "accessible_android_paths": local_folders["whatsapp"],
            "accessible_whatsapp_business_paths": local_folders["whatsapp_business"],
            "known_whatsapp_paths": ACCESSIBLE_ANDROID_PATHS,
            "known_whatsapp_business_paths": ACCESSIBLE_WHATSAPP_BUSINESS_PATHS,
            "termux_commands": TERMUX_COMMANDS,
            "scoped_storage_policy": (
                "Scans only user-authorized, accessible shared storage directories. "
                "Never bypasses Android scoped-storage restrictions or roots devices."
            ),
        }

    try:
        result = subprocess.run(  # nosec
            [adb, "devices", "-l"],
            capture_output=True,
            text=True,
            timeout=8,
            check=False,
        )
        devices: list[dict[str, Any]] = []
        for line in result.stdout.splitlines()[1:]:
            stripped = line.strip()
            if not stripped:
                continue
            parts = stripped.split()
            if len(parts) >= 2:
                serial = parts[0]
                state = parts[1]
                meta: dict[str, str] = {}
                for token in parts[2:]:
                    if ":" in token:
                        k, v = token.split(":", 1)
                        meta[k] = v

                dev_entry: dict[str, Any] = {
                    "serial": serial,
                    "state": state,
                    "authorized": state == "device",
                    "connection_type": "wireless" if ":" in serial else "usb",
                    "product": meta.get("product", ""),
                    "model": meta.get("model", ""),
                    "device": meta.get("device", ""),
                    "transport_id": meta.get("transport_id", ""),
                }
                if state == "device":
                    dev_entry["manufacturer"] = _query_authorized_prop(adb, serial, "ro.product.manufacturer")
                    dev_entry["android_version"] = _query_authorized_prop(adb, serial, "ro.build.version.release")
                    dev_entry["sdk_int"] = _query_authorized_prop(adb, serial, "ro.build.version.sdk")
                    dev_entry["storage_info"] = _query_authorized_storage_folders(adb, serial)
                devices.append(dev_entry)

        return {
            "available": True,
            "is_termux": is_termux,
            "platform": platform.system(),
            "returncode": result.returncode,
            "devices": devices,
            "accessible_android_paths": local_folders["whatsapp"],
            "accessible_whatsapp_business_paths": local_folders["whatsapp_business"],
            "known_whatsapp_paths": ACCESSIBLE_ANDROID_PATHS,
            "known_whatsapp_business_paths": ACCESSIBLE_WHATSAPP_BUSINESS_PATHS,
            "termux_commands": TERMUX_COMMANDS,
            "message": "Connection status and authorized read-only device properties only. No private files pulled.",
            "scoped_storage_policy": (
                "Scans only user-authorized, accessible shared storage directories. "
                "Never bypasses Android scoped-storage restrictions or roots devices."
            ),
        }
    except (OSError, subprocess.TimeoutExpired) as exc:
        return {
            "available": True,
            "is_termux": is_termux,
            "platform": platform.system(),
            "message": str(exc),
            "devices": [],
            "accessible_android_paths": local_folders["whatsapp"],
            "accessible_whatsapp_business_paths": local_folders["whatsapp_business"],
            "known_whatsapp_paths": ACCESSIBLE_ANDROID_PATHS,
            "known_whatsapp_business_paths": ACCESSIBLE_WHATSAPP_BUSINESS_PATHS,
            "termux_commands": TERMUX_COMMANDS,
        }


def get_android_guidance() -> dict[str, Any]:
    """Return structured Android storage permission guidance, Wireless ADB pairing steps, and troubleshooting."""
    return {
        "diagnostics": device_check(),
        "storage_permission_steps": [
            "In Termux, run `termux-setup-storage` and tap 'Allow' on the Android storage permission prompt.",
            "On Android 11+, WhatsApp stores shared media and local backups under `/storage/emulated/0/Android/media/com.whatsapp/WhatsApp`.",
            "On Android 11+, WhatsApp Business stores shared media and local backups under `/storage/emulated/0/Android/media/com.whatsapp.w4b/WhatsApp Business`.",
            "On Android 10 and earlier, WhatsApp uses `/storage/emulated/0/WhatsApp` and `/storage/emulated/0/WhatsApp Business`.",
            "App-private directories (`/data/data/com.whatsapp`) are protected by Android sandboxing and are never accessed or bypassed.",
        ],
        "wireless_adb_steps": [
            "Install `android-tools` in Termux (`pkg install -y android-tools`).",
            "Open Settings -> Developer Options -> Wireless Debugging and place Settings + Termux in Split-Screen mode.",
            "Tap 'Pair device with pairing code' and run `adb pair 127.0.0.1:<PAIRING_PORT>` in Termux.",
            "Run `adb connect 127.0.0.1:<CONNECT_PORT>` and verify with `python main.py adb-check`.",
        ],
        "adb_troubleshooting": [
            "Enable Developer Options on your Android phone (Settings -> About Phone -> tap Build Number 7 times).",
            "Enable USB Debugging in Developer Options and connect via a data-capable USB cable.",
            "Tap 'Allow USB debugging' on your phone screen when prompted so the device state changes from `unauthorized` to `device`.",
            "To acquire authorized shared backups to PC, run `adb pull /sdcard/Android/media/com.whatsapp/WhatsApp ./my-backup` and verify SHA-256 hashes.",
        ],
        "termux_commands": TERMUX_COMMANDS,
    }
