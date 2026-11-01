# Security and privacy

- Use only data you own or are explicitly authorized to inspect.
- API binds to localhost by default; Docker binds host port to 127.0.0.1.
- Scanning and preview do not modify source files.
- Preview is allow-listed to media paths from the latest scan and known media MIME types.
- Export is limited to selected media files in the latest scan, refuses source-subdirectory destinations, does not overwrite, and verifies SHA-256 after copying.
- Symbolic links are skipped.
- ADB command is limited to `adb devices`; no `pull`, shell, root, package extraction, or private-data access.
- No cloud sync, telemetry, account passwords, OTPs, tokens, or WhatsApp login.
- Treat JSON/PDF reports as sensitive because they include filenames and full paths.

Do not expose this dashboard to untrusted networks. Do not upload private backups to unknown services.
