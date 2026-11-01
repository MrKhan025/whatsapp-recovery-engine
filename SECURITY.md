# Security and Privacy Policy

## Security & Privacy Guarantees

1. **100% Local-Only Processing**: All scanning, SQLite inspection, chat export parsing, snapshot comparison, and report generation run strictly on the local machine. No telemetry, analytics, or automatic cloud uploads exist.
2. **Read-Only Source Scanning**: Source directories and SQLite databases are never modified. SQLite connections use URI `mode=ro&immutable=1` and enforce `PRAGMA query_only = ON;`.
3. **Path Traversal & Symlink Protection (`wtk/security.py`)**:
   - All user-supplied paths are validated against `..` traversal tokens, null bytes, and control characters.
   - Symbolic links (both target files and ancestor directory chains) are skipped during scanning and rejected during preview and export.
4. **Safe Export & Overwrite Prevention (`wtk/verification.py`)**:
   - Export destinations must reside outside the scanned source root.
   - Existing files at the destination are never overwritten.
   - Every exported file is verified by computing SHA-256 before copying and SHA-256 after copying; any mismatch triggers immediate cleanup of the incomplete target file.
5. **Strict Ethical & Platform Boundaries**:
   - Encrypted `.crypt12`, `.crypt14`, and `.crypt15` files are cataloged by metadata and SHA-256 only; this software never bypasses WhatsApp encryption.
   - Android scoped-storage and sandbox boundaries are strictly respected; `adb` diagnostics are limited to read-only connection and authorized device property checks (`adb devices -l` and `getprop`).
   - Never bypasses OTPs, passwords, device locks, or account authentication.

## Reporting a Vulnerability

If you discover a security issue in this repository, please open a security advisory on GitHub or report it privately to the repository maintainer before public disclosure.
