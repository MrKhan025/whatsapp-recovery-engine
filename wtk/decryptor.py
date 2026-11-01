"""Legitimate User-Supplied Key Backup Inspector & Decryptor (`wtk/decryptor.py`).

Supports strictly authorized, user-supplied key operations:
- Validates 158-byte Android WhatsApp `key` files (extracting the 32-byte AES-256 key at offset 126)
  or 64-character hexadecimal (32-byte) E2EE backup keys.
- Inspects `.crypt12`, `.crypt14`, and `.crypt15` header structure (IV, payload offsets).
- Performs local AES-256-GCM + zlib decompression ONLY when the user explicitly provides
  their own valid 32-byte key. Never brute-forces, guesses, or bypasses encryption.
"""

from __future__ import annotations

import binascii
import zlib
from pathlib import Path
from typing import Any

from .security import sha256_bytes, sha256_file, validate_safe_path

WA_KEY_FILE_SIZE = 158
WA_KEY_FILE_MAGIC = b"\xac\xed\x00\x05"  # Java serialized stream header in standard Android WhatsApp key file


def parse_user_key(key_input: str | bytes | Path) -> dict[str, Any]:
    """Validate and extract a 32-byte AES-256 key from a hex string, raw bytes, or 158-byte `key` file."""
    if isinstance(key_input, Path) or (isinstance(key_input, str) and Path(key_input).exists()):
        key_path = validate_safe_path(key_input, must_exist=True, allow_symlinks=False)
        raw = key_path.read_bytes()
    elif isinstance(key_input, str):
        cleaned = key_input.strip().replace(" ", "").replace(":", "")
        if len(cleaned) != 64:
            raise ValueError("Hexadecimal key must be exactly 64 hex characters (32 bytes)")
        try:
            raw = binascii.unhexlify(cleaned)
        except (binascii.Error, ValueError) as exc:
            raise ValueError(f"Invalid hexadecimal key: {exc}") from exc
    elif isinstance(key_input, bytes):
        raw = key_input
    else:
        raise ValueError("Unsupported key input type")

    if len(raw) == 32:
        aes_key = raw
        key_format = "raw_32byte_aes256"
    elif len(raw) == WA_KEY_FILE_SIZE:
        aes_key = raw[126:158]
        key_format = "whatsapp_158byte_keyfile"
    else:
        raise ValueError(
            f"Unsupported key length ({len(raw)} bytes). Provide a 32-byte key (64 hex chars) or 158-byte WhatsApp key file."
        )

    return {
        "valid": True,
        "key_format": key_format,
        "key_length_bytes": len(aes_key),
        "key_fingerprint_sha256": sha256_bytes(aes_key)[:16],
        "aes_key": aes_key,
    }


def inspect_crypt_header(path: Path | str) -> dict[str, Any]:
    """Inspect structural header metadata of a `.crypt12`, `.crypt14`, or `.crypt15` file without decrypting."""
    file_path = validate_safe_path(path, must_exist=True, allow_symlinks=False, reject_traversal_tokens=False)
    size = file_path.stat().st_size
    name_lower = file_path.name.lower()

    if ".crypt15" in name_lower:
        fmt = "crypt15"
    elif ".crypt14" in name_lower:
        fmt = "crypt14"
    elif ".crypt12" in name_lower:
        fmt = "crypt12"
    else:
        fmt = "crypt_generic"

    if size < 67:
        return {
            "name": file_path.name,
            "path": str(file_path),
            "size": size,
            "format": fmt,
            "header_complete": False,
            "reason": "File is smaller than minimum .crypt* header length (67 bytes)",
        }

    with file_path.open("rb") as f:
        header = f.read(192)

    return {
        "name": file_path.name,
        "path": str(file_path),
        "size": size,
        "sha256": sha256_file(file_path),
        "format": fmt,
        "header_complete": True,
        "header_preview_hex": header[:32].hex(),
        "estimated_payload_bytes": max(0, size - len(header) - 16),
    }


def decrypt_backup_with_user_key(
    encrypted_path: Path | str,
    key_input: str | bytes | Path,
    output_db_path: Path | str,
    iv_offset: int = 51,
    payload_offset: int = 67,
) -> dict[str, Any]:
    """Decrypt a user-owned `.crypt*` backup using a user-supplied 32-byte key (AES-256-GCM + zlib).

    Strictly requires the user's legitimate key; never guesses or brute-forces keys.
    """
    src_path = validate_safe_path(encrypted_path, must_exist=True, allow_symlinks=False)
    out_path = Path(output_db_path).expanduser().resolve()
    if src_path == out_path:
        raise ValueError("Output database path must differ from encrypted source path")

    key_info = parse_user_key(key_input)
    aes_key: bytes = key_info["aes_key"]
    raw_data = src_path.read_bytes()

    if len(raw_data) < payload_offset + 32:
        raise ValueError("Encrypted file is too small to contain a valid header, IV, and GCM tag")

    iv = raw_data[iv_offset : iv_offset + 16]
    ciphertext_with_tag = raw_data[payload_offset:]

    try:
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    except ImportError as exc:
        raise RuntimeError("The 'cryptography' package is required for key-based AES-GCM decryption") from exc

    # Standard AES-GCM uses a 12-byte or 16-byte nonce; try 16-byte IV then 12-byte IV slice
    plaintext_compressed: bytes | None = None
    last_err: Exception | None = None
    for candidate_iv in (iv, iv[:12]):
        try:
            aesgcm = AESGCM(aes_key)
            plaintext_compressed = aesgcm.decrypt(candidate_iv, ciphertext_with_tag, None)
            break
        except Exception as err:
            last_err = err

    if plaintext_compressed is None:
        raise ValueError(
            f"AES-GCM authentication failed with the supplied key ({last_err}). "
            "Verify that the key matches this specific backup file and offsets."
        )

    try:
        sqlite_bytes = zlib.decompress(plaintext_compressed)
    except zlib.error:
        sqlite_bytes = plaintext_compressed

    if not sqlite_bytes.startswith(b"SQLite format 3\x00"):
        raise ValueError("Decrypted payload does not start with a valid SQLite3 header")

    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_bytes(sqlite_bytes)

    return {
        "decrypted": True,
        "source": str(src_path),
        "output_db": str(out_path),
        "output_size": len(sqlite_bytes),
        "output_sha256": sha256_bytes(sqlite_bytes),
        "key_format": key_info["key_format"],
        "key_fingerprint": key_info["key_fingerprint_sha256"],
    }
