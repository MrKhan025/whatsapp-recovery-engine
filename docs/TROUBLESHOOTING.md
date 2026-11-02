# Troubleshooting Guide — WhatsApp Recovery Engine v2.0

## 1. Android Termux Issues

### Error: `Installing pip is forbidden, this will break the python-pip package`
- **Cause:** Termux wraps `pip` inside its native `python-pip` apt package. Running `pip install --upgrade pip` breaks Termux.
- **Solution:** Never upgrade `pip` in Termux. If `pip` is broken, run:
  ```bash
  pkg reinstall -y python python-pip
  ```

### Error: `Rust not found` / `maturin failed` while building `pydantic-core`
- **Cause:** Installing from `requirements.txt` in Termux without the Termux User Repository (`tur-repo`) triggers a source build of `pydantic-core`.
- **Solution:** Install `tur-repo` and use `requirements-termux.txt`:
  ```bash
  pkg install -y tur-repo python
  pip install -r requirements-termux.txt
  ```

### Empty Scan Results on Android 11, 12, 13, 14, or 15
- **Cause:** Android 11+ relocated WhatsApp from `/sdcard/WhatsApp` to `/sdcard/Android/media/com.whatsapp/WhatsApp` (and `/sdcard/Android/media/com.whatsapp.w4b/WhatsApp Business` for WhatsApp Business).
- **Solution:** Run `termux-setup-storage`, grant permission, and scan `/sdcard/Android/media/com.whatsapp/WhatsApp` or use the built-in `./sample_data/snapshot_v2` workspace first.

---

## 2. USB & Wireless ADB Issues

### Device Shows `unauthorized` in `adb devices -l`
- Unlock your phone screen, unplug and reconnect the USB cable, and tap **Allow USB debugging** on the prompt. If no prompt appears, open **Developer Options → Revoke USB debugging authorizations** and reconnect.

### Wireless ADB (`adb pair`) Connection Refused
- Ensure both your phone and computer are on the same local Wi-Fi subnet (not a guest network with client isolation).
- Note that the **Pairing Port** shown under *Pair device with pairing code* is different from the **Connect Port** shown on the main *Wireless debugging* screen.

---

## 3. SQLite & Encrypted Backup Issues

### `.crypt12` / `.crypt14` / `.crypt15` Decryption Fails with `Authentication tag verification failed`
- Ensure the 64-character hex key or 158-byte `key` file matches the exact WhatsApp account and epoch when the backup was created.
- `.crypt15` uses End-to-End Encrypted backup key derivation (`HKDF-SHA256` with `backup encryption` info string), whereas `.crypt12` and `.crypt14` use the 32-byte cipher key directly from the 158-byte Android `key` file.
