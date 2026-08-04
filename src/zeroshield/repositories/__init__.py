from zeroshield.repositories.evidence_builder import (
    EvidenceBundle,
    build_run_evidence,
    verify_manifest_integrity,
)
from zeroshield.repositories.evidence_repository import EvidenceRepository, LocalEvidenceRepository

# MinioEvidenceRepository is deliberately NOT imported here: it requires the
# optional 'minio' package (the "storage" extra), and every existing consumer
# of this package (CLI, dashboard, API, worker) only installs "api"/
# "dashboard"/"queue"/"dev" - eagerly importing it here would make minio a
# hard dependency for all of them. Import it directly from
# zeroshield.repositories.minio_evidence_repository when the storage extra is
# installed and MinIO is actually wanted.

__all__ = [
    "EvidenceBundle",
    "EvidenceRepository",
    "LocalEvidenceRepository",
    "build_run_evidence",
    "verify_manifest_integrity",
]
