"""Android, Termux, and ADB Integration (`wtk/adb.py`).

Capabilities:
- ADB device connection diagnostics (`adb devices -l`)
- Display connected device information (model, manufacturer, Android release, SDK level) ONLY when device state == 'device' (user-authorized)
- Provide Android scoped-storage permission guidance and standard accessible WhatsApp paths
- Provide exact Termux installation and startup commands
- Strictly prohibits rooting, privilege escalation, or bypassing Android scoped-storage restrictions
"""

from __future__ import annotations

import os
import platform
import shutil
import subprocess  # nosec B404
from pathlib import Path
from typing import Any

ACCESSIBLE_ANDROID_PATHS = [
    "/storage/emulated/0/Android/media/com.whatsapp/WhatsApp",
    "/sdcard/Android/media/com.whatsapp/WhatsApp",
    "/storage/emulated/0/WhatsApp",
    "/sdcard/WhatsApp",
    "/data/data/com.termux/files/home/storage/shared/Android/media/com.whatsapp/WhatsApp",
    "/data/data/com.termux/files/home/storage/shared/WhatsApp",
]

TERMUX_COMMANDS = {
    "install": [
        "pkg update -y && pkg upgrade -y",
        "pkg install -y python git libjpeg-turbo freetype",
        "termux-setup-storage",
        "git clone https://github.com/MrKhan025/whatsapp-recovery-engine.git",
        "cd whatsapp-recovery-engine",
        "pip install -r requirements-termux.txt",
    ],
    "start_dashboard": "python -m wtk serve --host 127.0.0.1 --port 8000",
    "cli_scan": (
        "python -m wtk scan "
        "--source ~/storage/shared/Android/media/com.whatsapp/WhatsApp "
        "--output ./reports"
    ),
}

_ALLOWED_PROPS = {
    "ro.product.manufacturer",
    "ro.build.version.release",
    "ro.build.version.sdk",
}


def _query_authorized_prop(adb_bin: str, serial: str, prop: str) -> str:
    """Query a single allow-listed read-only system property from an authorized ADB device."""
    if prop not in _ALLOWED_PROPS:
        return ""
    try:
        res = subprocess.run(  # nosec B603
            [adb_bin, "-s", serial, "shell", "getprop", prop],
            capture_output=True,
            text=True,
            timeout=3,
            check=False,
        )
        if res.returncode == 0:
            return res.stdout.strip()[:80]
    except (OSError, subprocess.TimeoutExpired):
        pass
    return ""


def device_check() -> dict[str, Any]:
    """Run read-only ADB connection diagnostics and report authorized device metadata."""
    is_termux = bool(os.environ.get("TERMUX_VERSION") or Path("/data/data/com.termux").exists())
    discovered_local_paths = [p for p in ACCESSIBLE_ANDROID_PATHS if Path(p).exists()]

    adb = shutil.which("adb")
    if not adb:
        return {
            "available": False,
            "is_termux": is_termux,
            "platform": platform.system(),
            "message": "ADB not installed or not on PATH",
            "devices": [],
            "accessible_android_paths": discovered_local_paths,
            "known_whatsapp_paths": ACCESSIBLE_ANDROID_PATHS,
            "termux_commands": TERMUX_COMMANDS,
            "scoped_storage_policy": (
                "Scans only user-authorized, accessible shared storage directories. "
                "Never bypasses Android scoped-storage restrictions or roots devices."
            ),
        }

    try:
        result = subprocess.run(  # nosec B603
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
                    "product": meta.get("product", ""),
                    "model": meta.get("model", ""),
                    "device": meta.get("device", ""),
                    "transport_id": meta.get("transport_id", ""),
                }
                if state == "device":
                    dev_entry["manufacturer"] = _query_authorized_prop(adb, serial, "ro.product.manufacturer")
                    dev_entry["android_version"] = _query_authorized_prop(adb, serial, "ro.build.version.release")
                    dev_entry["sdk_int"] = _query_authorized_prop(adb, serial, "ro.build.version.sdk")
                devices.append(dev_entry)

        return {
            "available": True,
            "is_termux": is_termux,
            "platform": platform.system(),
            "returncode": result.returncode,
            "devices": devices,
            "accessible_android_paths": discovered_local_paths,
            "known_whatsapp_paths": ACCESSIBLE_ANDROID_PATHS,
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
            "accessible_android_paths": discovered_local_paths,
            "known_whatsapp_paths": ACCESSIBLE_ANDROID_PATHS,
            "termux_commands": TERMUX_COMMANDS,
        }


def get_android_guidance() -> dict[str, Any]:
    """Return structured Android storage permission guidance, Termux instructions, and ADB diagnostics."""
    return {
        "diagnostics": device_check(),
        "storage_permission_steps": [
            "In Termux, run `termux-setup-storage` and tap 'Allow' on the Android storage permission prompt.",
            "On Android 11+, WhatsApp stores shared media and local backups under `/storage/emulated/0/Android/media/com.whatsapp/WhatsApp`.",
            "On Android 10 and earlier, WhatsApp uses `/storage/emulated/0/WhatsApp`.",
            "App-private directories (`/data/data/com.whatsapp`) are protected by Android sandboxing and are never accessed or bypassed by this toolkit.",
        ],
        "adb_troubleshooting": [
            "Enable Developer Options on your Android phone (Settings -> About Phone -> tap Build Number 7 times).",
            "Enable USB Debugging in Developer Options and connect via a data-capable USB cable.",
            "Tap 'Allow USB debugging' on your phone screen when prompted so the device state changes from `unauthorized` to `device`.",
            "Copy only user-authorized shared folders if inspecting on a desktop PC, or run WhatsApp Recovery Engine directly inside Termux on the phone.",
        ],
        "termux_commands": TERMUX_COMMANDS,
    }
