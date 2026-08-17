"""Canonical JSON hashing for generated datasets - intentionally the same
approach zeroshield.repositories.evidence_builder already uses for manifest
hashing (sorted keys, compact separators, sha256), so a generated dataset's
provenance hash is computed the same way evidence hashes are, without
importing that module's private helper across package boundaries.
"""

import hashlib
import json


def canonical_sha256(data: dict) -> str:
    canonical = json.dumps(data, sort_keys=True, separators=(",", ":"), default=str).encode("utf-8")
    return hashlib.sha256(canonical).hexdigest()
