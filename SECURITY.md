# Security & Forensic Ethics Policy (v2.0)

## 1. Security Architecture & Threat Model

**WhatsApp Recovery Engine v2.0** is engineered for defensive, user-authorized digital forensics and backup recovery:

- **Loopback-Only Binding (`127.0.0.1`):** The FastAPI dashboard binds strictly to `127.0.0.1` by default (`validate_local_bind_host`). Remote binding requires explicit `--allow-remote` authorization.
- **Zero Telemetry & Offline-First Operation:** No analytics, crash dumps, conversation contents, or cryptographic keys are ever transmitted over the network. Even the AI-Assisted Forensic Analysis module (`wtk/forensic_ai.py`) operates 100% locally by default.
- **Read-Only Source Guarantee:** Every SQLite connection uses `file:<path>?mode=ro&immutable=1` alongside `PRAGMA query_only = ON;` so source databases and backups are never altered during inspection.
- **Path Traversal & Symlink Defense:** `validate_scan_directory` and `validate_subpath` reject null bytes, `..` traversal sequences, and symbolic links (`Path.is_symlink()`) before opening any file.
- **Local Session Authentication & CSRF Protection:** `LocalSessionManager` issues time-bounded session tokens and CSRF tokens (`X-WTK-Session-Token` / `X-WTK-CSRF-Token`) to protect local mutating API endpoints.
- **Encrypted Temporary Storage (`EncryptedTempStore`):** Ephemeral sensitive data is encrypted in memory/temp storage using an ephemeral 256-bit key and overwritten with zeros prior to unlinking via an `atexit` cleanup handler.
- **Secret-Free Audit Logging (`AuditLogger`):** Operational events are recorded while automatically redacting any field matching `key`, `secret`, `token`, `password`, or `message`.

## 2. Cryptographic Verification Standards

- **Dual Checksums (`SHA-256` & `SHA-512`):** Every registered evidence item, exported chat report, and verified media file is hashed with both `SHA-256` and `SHA-512`.
- **Transparent Certificate Signing Modes:** Forensic certificates and evidence manifests explicitly declare their `verification_mode`:
  - `"cryptographically_signed_hmac_sha256"` when signed with a user-supplied 32-byte key (`HMAC-SHA256` over canonical JSON).
  - `"checksum_verified_only"` when verified via `SHA-256` and `SHA-512` digests without a signing key.

## 3. Prohibited Operations

This project **never**:
- Brute-forces passwords, encryption keys, or PINs.
- Bypasses OTP, two-step verification, or account authentication.
- Exploits Android kernel vulnerabilities or bypasses Android 11+ Scoped Storage restrictions.
- Claims guaranteed recovery percentages for permanently overwritten data.
