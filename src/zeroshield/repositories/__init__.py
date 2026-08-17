from zeroshield.repositories.evidence_builder import (
    EvidenceBundle,
    build_run_evidence,
    verify_manifest_integrity,
)
from zeroshield.repositories.evidence_repository import (
    EvidenceAlreadyExistsError,
    EvidenceRepository,
    LocalEvidenceRepository,
)
from zeroshield.repositories.run_repository import NullRunRepository, RunEvent, RunRepository

# MinioEvidenceRepository/PostgresRunRepository are deliberately NOT imported
# here: they require the optional 'minio'/'db' packages (the "storage"/"db"
# extras), and every existing consumer of this package (CLI, dashboard, API,
# worker) only installs "api"/"dashboard"/"queue"/"dev" - eagerly importing
# them here would make minio/sqlalchemy hard dependencies for all of them.
# Import zeroshield.repositories.minio_evidence_repository /
# zeroshield.repositories.postgres_run_repository directly when the
# storage/db extra is installed and actually wanted.

__all__ = [
    "EvidenceAlreadyExistsError",
    "EvidenceBundle",
    "EvidenceRepository",
    "LocalEvidenceRepository",
    "NullRunRepository",
    "RunEvent",
    "RunRepository",
    "build_run_evidence",
    "verify_manifest_integrity",
]
