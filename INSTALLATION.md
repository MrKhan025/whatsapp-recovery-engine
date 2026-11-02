# Step-by-Step Installation & ADB Guide (v2.0)

This guide covers installing and executing **WhatsApp Recovery Engine v2.0** across **Windows 10/11**, **Linux**, **macOS**, **Android Termux**, **Docker**, and **USB / Wireless ADB**.

---

## 1. Windows 10 & Windows 11

```powershell
git clone https://github.com/MrKhan025/whatsapp-recovery-engine.git
cd whatsapp-recovery-engine
git checkout feature/v2-advanced-recovery

python -m venv .venv
.venv\Scripts\activate
pip install -r requirements.txt

# Start the 12-Section Dashboard (auto-creates sample_data/snapshot_v1 & snapshot_v2)
python main.py serve --host 127.0.0.1 --port 8000
```
Or double-click **`start.bat`** in Windows Explorer. Open **`http://127.0.0.1:8000`**.

---

## 2. Linux & macOS

```bash
git clone https://github.com/MrKhan025/whatsapp-recovery-engine.git
cd whatsapp-recovery-engine
git checkout feature/v2-advanced-recovery

python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt

python3 main.py serve --host 127.0.0.1 --port 8000
```

---

## 3. Android Termux (Step-by-Step — No Root Required)

1. Install **Termux** from **F-Droid** (do not use the outdated Google Play Store build).
2. Run the following commands inside Termux:
   ```bash
   pkg update -y && pkg upgrade -y
   pkg install -y python git android-tools tur-repo
   termux-setup-storage
   ```
   *(Tap **Allow** when Android prompts for storage permission.)*
3. Clone and install using `requirements-termux.txt` (do **not** run `pip install --upgrade pip`):
   ```bash
   git clone https://github.com/MrKhan025/whatsapp-recovery-engine.git
   cd whatsapp-recovery-engine
   git checkout feature/v2-advanced-recovery

   pip install -r requirements-termux.txt
   python main.py serve --host 127.0.0.1 --port 8000
   ```
4. Open **`http://127.0.0.1:8000`** in Chrome or Firefox on your phone.
   - Standard Android 11+ WhatsApp path in Termux: `/sdcard/Android/media/com.whatsapp/WhatsApp`
   - WhatsApp Business path in Termux: `/sdcard/Android/media/com.whatsapp.w4b/WhatsApp Business`

---

## 4. Connecting an Android Phone via USB ADB or Wireless ADB

### Option A: USB ADB (Android 8 – 15)
1. On your phone, open **Settings → About Phone** and tap **Build Number** 7 times.
2. Open **Settings → System → Developer Options** and enable **USB Debugging**.
3. Connect the phone via USB cable and run:
   ```bash
   adb devices -l
   ```
4. Tap **Allow USB Debugging** on your phone screen.
5. In the dashboard, open **ADB Device Manager** and click **Refresh ADB Diagnostics**, or pull backups to a local workspace:
   ```bash
   mkdir -p ./phone_backup
   adb pull "/sdcard/Android/media/com.whatsapp/WhatsApp/Databases" ./phone_backup/Databases
   adb pull "/sdcard/Android/media/com.whatsapp/WhatsApp/Media" ./phone_backup/Media
   ```

### Option B: Wireless ADB Pairing (Android 11+ — No USB Cable Needed)
1. Connect your phone and computer (or Termux) to the same Wi-Fi network.
2. On your phone, open **Developer Options → Wireless debugging** and toggle it **ON**.
3. Tap **Pair device with pairing code** to view the IP, pairing port, and 6-digit code.
4. Pair and connect:
   ```bash
   adb pair <PHONE_IP>:<PAIRING_PORT> <6_DIGIT_CODE>
   adb connect <PHONE_IP>:<CONNECT_PORT>
   adb devices -l
   ```

---

## 5. Docker Deployment

```bash
docker compose up --build
```
Then open **`http://127.0.0.1:8000`**.
