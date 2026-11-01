import shutil
import subprocess

def device_check() -> dict:
    adb = shutil.which("adb")
    if not adb:
        return {"available": False, "message": "ADB not installed or not on PATH", "devices": []}
    try:
        result = subprocess.run([adb, "devices"], capture_output=True, text=True, timeout=10, check=False)
        devices = []
        for line in result.stdout.splitlines()[1:]:
            parts = line.strip().split()
            if len(parts) >= 2:
                devices.append({"serial": parts[0], "state": parts[1]})
        return {"available": True, "returncode": result.returncode, "devices": devices,
                "message": "Connection status only. No files were pulled."}
    except (OSError, subprocess.TimeoutExpired) as exc:
        return {"available": True, "message": str(exc), "devices": []}
