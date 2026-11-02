"""Format-Specific Backup Cryptographic Validator & Authorized Decryptor (`wtk/decryptor.py`).

Implements distinct format specifications for CRYPT12, CRYPT14, and CRYPT15:
- CRYPT12: 67-byte fixed header (2-byte header prefix + 1-byte version + 32-byte server token t1 +
  16-byte t2 + 16-byte IV at offset 51..67) encrypted with raw 32-byte key from 158-byte `key` file (offset 126..158).
- CRYPT14: Variable-length protobuf header (1-byte protobuf size marker + protobuf metadata + 16-byte IV)
  encrypted with raw 32-byte AES-256 key.
- CRYPT15: E2EE 32-byte root key (64 hex chars) -> HKDF-SHA256 key derivation (`info=b"backup encryption"`)
  producing a derived 32-byte AES-256-GCM key, with a framed protobuf header.

Never assumes all `.crypt*` formats share identical offsets or key derivation.
Never brute-forces passwords or bypasses encryption.
"""

from __future__ import annotations

import binascii
import hashlib
import hmac
import zlib
from pathlib import Path
from typing import Any

from .security import sha256_bytes, sha256_file, validate_safe_path

WA_KEY_FILE_SIZE = 158
CRYPT15_HKDF_INFO = b"backup encryption"

FORMAT_SPECS: dict[str, dict[str, Any]] = {
    "crypt12": {
        "name": "WhatsApp CRYPT12",
        "header_type": "fixed_67_byte",
        "min_header_bytes": 67,
        "iv_offset": 51,
        "iv_length": 16,
        "payload_offset": 67,
        "key_derivation": "direct_32byte_from_158b_keyfile",
        "cipher": "AES-256-GCM + zlib",
    },
    "crypt14": {
        "name": "WhatsApp CRYPT14",
        "header_type": "protobuf_variable_header",
        "min_header_bytes": 82,
        "iv_offset": 66,
        "iv_length": 16,
        "payload_offset": 82,
        "key_derivation": "direct_32byte_from_158b_keyfile",
        "cipher": "AES-256-GCM + zlib",
    },
    "crypt15": {
        "name": "WhatsApp CRYPT15 (E2EE)",
        "header_type": "protobuf_e2ee_header",
        "min_header_bytes": 75,
        "iv_offset": 59,
        "iv_length": 16,
        "payload_offset": 75,
        "key_derivation": "HKDF-SHA256(root_key, info='backup encryption')",
        "cipher": "AES-256-GCM + zlib",
    },
}


def hkdf_sha256_derive(ikm: bytes, info: bytes = CRYPT15_HKDF_INFO, length: int = 32, salt: bytes = b"\x00" * 32) -> bytes:
    """RFC 5869 HKDF-SHA256 key derivation used by CRYPT15 E2EE backup keys."""
    prk = hmac.new(salt, ikm, hashlib.sha256).digest()
    t = b""
    okm = b""
    counter = 1
    while len(okm) < length:
        t = hmac.new(prk, t + info + bytes([counter]), hashlib.sha256).digest()
        okm += t
        counter += 1
    return okm[:length]


def parse_user_key(key_input: str | bytes | Path) -> dict[str, Any]:
    """Validate and extract a 32-byte key from a 64-char hex string, raw bytes, or 158-byte `key` file."""
    if isinstance(key_input, Path) or (isinstance(key_input, str) and len(key_input) < 240 and Path(key_input).exists()):
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

    t1_token: bytes | None = None
    if len(raw) == 32:
        aes_key = raw
        key_format = "raw_32byte_root_key"
    elif len(raw) == WA_KEY_FILE_SIZE:
        t1_token = raw[30:62]
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
        "t1_token_hex": t1_token.hex()[:16] if t1_token else None,
        "aes_key": aes_key,
        "crypt15_derived_key": hkdf_sha256_derive(aes_key, CRYPT15_HKDF_INFO, 32),
    }


def identify_crypt_format(path: Path | str) -> str:
    """Identify whether a backup file is crypt12, crypt14, crypt15, or unknown."""
    name_lower = Path(path).name.lower()
    if ".crypt15" in name_lower:
        return "crypt15"
    if ".crypt14" in name_lower:
        return "crypt14"
    if ".crypt12" in name_lower:
        return "crypt12"
    return "crypt_generic"


def inspect_crypt_header(path: Path | str) -> dict[str, Any]:
    """Inspect format-specific header metadata of a `.crypt12`, `.crypt14`, or `.crypt15` file without decrypting."""
    file_path = validate_safe_path(path, must_exist=True, allow_symlinks=False, reject_traversal_tokens=False)
    size = file_path.stat().st_size
    fmt = identify_crypt_format(file_path)
    spec = FORMAT_SPECS.get(fmt, FORMAT_SPECS["crypt14"])
    min_hdr = int(spec["min_header_bytes"])

    if size < min_hdr:
        return {
            "name": file_path.name,
            "path": str(file_path),
            "size": size,
            "format": fmt,
            "specification": spec,
            "header_complete": False,
            "reason": f"File ({size} B) is smaller than minimum {fmt.upper()} header length ({min_hdr} B)",
        }

    with file_path.open("rb") as f:
        header = f.read(192)

    iv_off = int(spec["iv_offset"])
    iv_hex = header[iv_off : iv_off + 16].hex() if len(header) >= iv_off + 16 else ""

    return {
        "name": file_path.name,
        "path": str(file_path),
        "size": size,
        "sha256": sha256_file(file_path),
        "format": fmt,
        "specification": spec,
        "header_complete": True,
        "header_preview_hex": header[:32].hex(),
        "extracted_iv_hex": iv_hex,
        "estimated_payload_bytes": max(0, size - int(spec["payload_offset"]) - 16),
    }


def create_synthetic_crypt_fixture(
    fmt: str,
    sqlite_bytes: bytes,
    raw_key: bytes,
    output_path: Path | str,
) -> dict[str, Any]:
    """Create a format-specific synthetic `.crypt12`, `.crypt14`, or `.crypt15` test fixture."""
    if fmt not in FORMAT_SPECS:
        raise ValueError(f"Unsupported fixture format: {fmt}")
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM

    spec = FORMAT_SPECS[fmt]
    iv_offset = int(spec["iv_offset"])
    payload_offset = int(spec["payload_offset"])
    iv = b"\x22" * 16

    if fmt == "crypt15":
        active_key = hkdf_sha256_derive(raw_key, CRYPT15_HKDF_INFO, 32)
        prefix = b"WRE_CRYPT15_PROTO_HDR".ljust(iv_offset, b"\x01")
    elif fmt == "crypt14":
        active_key = raw_key
        prefix = b"WRE_CRYPT14_PROTO_HDR".ljust(iv_offset, b"\x02")
    else:
        active_key = raw_key
        prefix = b"WRE_CRYPT12_FIXED_HDR".ljust(iv_offset, b"\x03")

    compressed = zlib.compress(sqlite_bytes)
    ciphertext = AESGCM(active_key).encrypt(iv[:12], compressed, None)
    blob = prefix + iv + ciphertext
    assert len(prefix) + len(iv) == payload_offset

    out = Path(output_path)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_bytes(blob)
    return {
        "format": fmt,
        "path": str(out),
        "size": len(blob),
        "iv_offset": iv_offset,
        "payload_offset": payload_offset,
    }


def decrypt_backup_with_user_key(
    encrypted_path: Path | str,
    key_input: str | bytes | Path,
    output_db_path: Path | str,
    iv_offset: int | None = None,
    payload_offset: int | None = None,
) -> dict[str, Any]:
    """Decrypt a user-owned `.crypt12`, `.crypt14`, or `.crypt15` backup using format-specific offsets & key derivation."""
    src_path = validate_safe_path(encrypted_path, must_exist=True, allow_symlinks=False)
    out_path = Path(output_db_path).expanduser().resolve()
    if src_path == out_path:
        raise ValueError("Output database path must differ from encrypted source path")

    fmt = identify_crypt_format(src_path)
    spec = FORMAT_SPECS.get(fmt, FORMAT_SPECS["crypt14"])
    eff_iv_offset = iv_offset if iv_offset is not None else int(spec["iv_offset"])
    eff_payload_offset = payload_offset if payload_offset is not None else int(spec["payload_offset"])

    key_info = parse_user_key(key_input)
    raw_data = src_path.read_bytes()

    if len(raw_data) < eff_payload_offset + 32:
        raise ValueError(f"Encrypted {fmt.upper()} file is too small to contain header, IV, and GCM tag")

    iv = raw_data[eff_iv_offset : eff_iv_offset + 16]
    ciphertext_with_tag = raw_data[eff_payload_offset:]

    try:
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    except ImportError as exc:
        raise RuntimeError("The 'cryptography' package is required for key-based AES-GCM decryption") from exc

    # Select format-appropriate key (HKDF-SHA256 derived key for crypt15, direct key for crypt12/crypt14)
    candidate_keys = (
        [key_info["crypt15_derived_key"], key_info["aes_key"]]
        if fmt == "crypt15"
        else [key_info["aes_key"], key_info["crypt15_derived_key"]]
    )

    plaintext_compressed: bytes | None = None
    last_err: Exception | None = None
    for k in candidate_keys:
        for candidate_iv in (iv[:12], iv):
            try:
                plaintext_compressed = AESGCM(k).decrypt(candidate_iv, ciphertext_with_tag, None)
                break
            except Exception as err:
                last_err = err
        if plaintext_compressed is not None:
            break

    if plaintext_compressed is None:
        raise ValueError(
            f"AES-GCM authentication failed for {fmt.upper()} with the supplied key ({last_err}). "
            "Verify that the key matches this specific backup format and header layout."
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
        "format": fmt,
        "specification": spec,
        "source": str(src_path),
        "output_db": str(out_path),
        "output_size": len(sqlite_bytes),
        "output_sha256": sha256_bytes(sqlite_bytes),
        "key_format": key_info["key_format"],
        "key_fingerprint": key_info["key_fingerprint_sha256"],
    }
