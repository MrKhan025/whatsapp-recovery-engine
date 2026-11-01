# Security and Privacy Policy

See the root [`SECURITY.md`](../SECURITY.md) for the complete security architecture.

- Use only data you own or are explicitly authorized to inspect.
- API binds to `127.0.0.1` by default; Docker publishes strictly to `127.0.0.1:8000`.
- Scanning and preview are strictly read-only (`mode=ro&immutable=1` and `PRAGMA query_only = ON`).
- Symbolic links and path traversal (`..`, null bytes) are blocked across all endpoints.
- Export is limited to verified paths outside the source folder, never overwrites existing files, and verifies pre-copy and post-copy SHA-256 digests.
- ADB diagnostics check only `adb devices -l` and read-only `getprop` on authorized devices; no rooting, exploit, or sandbox bypass is ever performed.
