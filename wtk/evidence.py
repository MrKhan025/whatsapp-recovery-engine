"""Professional Evidence Management & Chain-of-Custody Ledger (`wtk/evidence.py`).

Implements:
- Unique Evidence IDs (`EVID-YYYYMMDD-XXXXXXXX`)
- Dual SHA-256 and SHA-512 checksums for every registered evidence item
- Chain-of-custody records with UTC acquisition timestamps and operator metadata
- Signed evidence manifests (supporting HMAC-SHA256 cryptographic signing when a key is provided,
  and clearly distinguishing `"cryptographically_signed_hmac_sha256"` vs `"checksum_verified_only"`)
- Export history tracking
"""

from __future__ import annotations

from datetime import datetime, timezone
import hashlib
import hmac
import json
import uuid
from pathlib import Path
from typing import Any

from .security import dual_checksum_file, sha256_bytes, sha512_bytes, validate_safe_path


def _utc_now() -> str:
    return datetime.now(tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")


class EvidenceManager:
    """Manages forensic evidence registration, dual SHA-256/SHA-512 integrity, chain of custody, and signed manifests."""

    def __init__(self) -> None:
        self._items: dict[str, dict[str, Any]] = {}
        self._chain_of_custody: list[dict[str, Any]] = []
        self._export_history: list[dict[str, Any]] = []

    def register_evidence(
        self,
        file_path: Path | str,
        category: str = "backup_artifact",
        operator: str = "local-investigator",
        notes: str = "",
    ) -> dict[str, Any]:
        """Register an accessible file as a tracked forensic evidence item with SHA-256 and SHA-512 digests."""
        safe_p = validate_safe_path(file_path, must_exist=True, allow_symlinks=False, reject_traversal_tokens=False)
        stat = safe_p.stat()
        checksums = dual_checksum_file(safe_p) if stat.st_size > 0 else {
            "sha256": hashlib.sha256(b"").hexdigest(),
            "sha512": hashlib.sha512(b"").hexdigest(),
        }
        stamp_day = datetime.now(tz=timezone.utc).strftime("%Y%m%d")
        evid_id = f"EVID-{stamp_day}-{uuid.uuid4().hex[:8].upper()}"
        acquired_at = _utc_now()

        record: dict[str, Any] = {
            "evidence_id": evid_id,
            "name": safe_p.name,
            "path": str(safe_p),
            "category": category,
            "size": stat.st_size,
            "modified_timestamp": int(stat.st_mtime),
            "acquired_at": acquired_at,
            "operator": operator,
            "sha256": checksums["sha256"],
            "sha512": checksums["sha512"],
            "notes": notes[:240],
            "integrity_status": "verified",
        }
        self._items[evid_id] = record
        self._chain_of_custody.append({
            "event_id": f"COC-{uuid.uuid4().hex[:8].upper()}",
            "evidence_id": evid_id,
            "timestamp": acquired_at,
            "action": "evidence_acquired_and_hashed",
            "operator": operator,
            "path": str(safe_p),
            "sha256": checksums["sha256"],
            "sha512": checksums["sha512"],
        })
        return record

    def verify_evidence_integrity(self, evidence_id: str) -> dict[str, Any]:
        """Re-calculate SHA-256 and SHA-512 of a registered evidence item and record a chain-of-custody event."""
        if evidence_id not in self._items:
            raise ValueError(f"Unknown evidence_id: {evidence_id}")
        item = self._items[evidence_id]
        p = Path(item["path"])
        now = _utc_now()
        if not p.exists() or not p.is_file() or p.is_symlink():
            item["integrity_status"] = "missing_or_unavailable"
            return {"evidence_id": evidence_id, "verified": False, "status": "missing_or_unavailable", "timestamp": now}

        current_hashes = dual_checksum_file(p)
        ok = (
            current_hashes["sha256"] == item["sha256"]
            and current_hashes["sha512"] == item["sha512"]
        )
        item["integrity_status"] = "verified" if ok else "mismatch_detected"
        self._chain_of_custody.append({
            "event_id": f"COC-{uuid.uuid4().hex[:8].upper()}",
            "evidence_id": evidence_id,
            "timestamp": now,
            "action": "integrity_reverified" if ok else "integrity_mismatch",
            "operator": item.get("operator", "local-investigator"),
            "path": item["path"],
            "sha256": current_hashes["sha256"],
            "sha512": current_hashes["sha512"],
        })
        return {
            "evidence_id": evidence_id,
            "verified": ok,
            "status": item["integrity_status"],
            "expected_sha256": item["sha256"],
            "actual_sha256": current_hashes["sha256"],
            "expected_sha512": item["sha512"],
            "actual_sha512": current_hashes["sha512"],
            "timestamp": now,
        }

    def record_export_event(self, export_result: dict[str, Any]) -> None:
        self._export_history.append({
            "timestamp": _utc_now(),
            "certificate_id": export_result.get("certificate_id", ""),
            "session_id": export_result.get("session_id", ""),
            "destination": export_result.get("destination", ""),
            "verified_count": export_result.get("verified_count", 0),
            "manifest_sha256": export_result.get("manifest_sha256", ""),
            "manifest_sha512": export_result.get("manifest_sha512", ""),
        })

    def generate_signed_manifest(self, signing_key: str | bytes | None = None) -> dict[str, Any]:
        """Generate an evidence manifest, clearly labeling whether it is cryptographically signed or checksum-verified."""
        items_list = list(self._items.values())
        canonical_bytes = json.dumps(items_list, sort_keys=True, ensure_ascii=False).encode("utf-8")
        manifest_sha256 = sha256_bytes(canonical_bytes)
        manifest_sha512 = sha512_bytes(canonical_bytes)

        if signing_key:
            key_bytes = signing_key.encode("utf-8") if isinstance(signing_key, str) else signing_key
            signature = hmac.new(key_bytes, canonical_bytes, hashlib.sha256).hexdigest()
            verification_mode = "cryptographically_signed_hmac_sha256"
            key_fingerprint = sha256_bytes(key_bytes)[:16]
        else:
            signature = None
            verification_mode = "checksum_verified_only"
            key_fingerprint = None

        return {
            "manifest_id": f"MAN-{uuid.uuid4().hex[:10].upper()}",
            "generated_at": _utc_now(),
            "verification_mode": verification_mode,
            "cryptographically_signed": signature is not None,
            "signing_algorithm": "HMAC-SHA256" if signature else "NONE (SHA-256 + SHA-512 Checksum Manifest)",
            "signing_key_fingerprint": key_fingerprint,
            "signature": signature,
            "manifest_sha256": manifest_sha256,
            "manifest_sha512": manifest_sha512,
            "evidence_count": len(items_list),
            "evidence_items": items_list,
            "chain_of_custody": self._chain_of_custody[-200:],
            "export_history": self._export_history[-100:],
        }

    def list_state(self) -> dict[str, Any]:
        return {
            "evidence_count": len(self._items),
            "evidence_items": list(self._items.values()),
            "chain_of_custody": list(reversed(self._chain_of_custody[-100:])),
            "export_history": list(reversed(self._export_history[-50:])),
        }


EVIDENCE_LEDGER = EvidenceManager()
