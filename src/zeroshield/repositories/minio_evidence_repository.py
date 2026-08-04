"""S3-compatible (MinIO) evidence storage, per SRS S14: "MinIO - Optional evidence
storage - S3-compatible local object storage; repository abstraction allows
replacement."

Implements exactly the same EvidenceRepository interface as
LocalEvidenceRepository - orchestration/runner/policy/metrics code needs zero
changes to use this instead (see execute_and_generate_evidence, which already
only depends on the EvidenceRepository ABC, never a concrete class).

save_run_evidence/save_comparison must return a Path per the ABC. There is no
real filesystem path for an object-storage backend, so these return a
symbolic, informational Path built from bucket/experiment_id/run_id (never a
URI scheme, which pathlib parses inconsistently across platforms) - it is
useful as a location label but is never treated as an openable file, either
here or by any existing caller.
"""

import io
import json
import os
from pathlib import Path

from minio import Minio
from minio.error import S3Error

from zeroshield.models import ComparisonReport, EvidenceManifest
from zeroshield.repositories.evidence_builder import EvidenceBundle
from zeroshield.repositories.evidence_repository import EvidenceRepository

_NOT_FOUND_CODES = {"NoSuchKey", "NoSuchObject"}


class MinioEvidenceRepository(EvidenceRepository):
    def __init__(self, client: Minio, bucket: str) -> None:
        self._client = client
        self._bucket = bucket
        if not client.bucket_exists(bucket):
            client.make_bucket(bucket)

    def _object_key(self, experiment_id: str, run_id: str, filename: str) -> str:
        return f"{experiment_id}/{run_id}/{filename}"

    def _put(self, key: str, content: bytes) -> None:
        self._client.put_object(
            self._bucket,
            key,
            io.BytesIO(content),
            length=len(content),
            content_type="application/json",
        )

    def save_run_evidence(self, bundle: EvidenceBundle) -> Path:
        experiment_id = bundle.manifest.experiment_id
        run_id = bundle.manifest.run_id
        for name, content in bundle.artefacts.items():
            self._put(self._object_key(experiment_id, run_id, name), content)
        return Path(self._bucket) / experiment_id / run_id

    def load_manifest(self, experiment_id: str, run_id: str) -> EvidenceManifest:
        key = self._object_key(experiment_id, run_id, "manifest.json")
        try:
            response = self._client.get_object(self._bucket, key)
        except S3Error as exc:
            if exc.code in _NOT_FOUND_CODES:
                raise FileNotFoundError(
                    f"no manifest at bucket '{self._bucket}' key '{key}'"
                ) from exc
            raise
        try:
            data = json.loads(response.read())
        finally:
            response.close()
            response.release_conn()
        return EvidenceManifest.model_validate(data)

    def save_comparison(self, experiment_id: str, report: ComparisonReport) -> Path:
        key = f"{experiment_id}/comparison.json"
        self._put(key, report.model_dump_json(indent=2).encode("utf-8"))
        return Path(self._bucket) / experiment_id / "comparison.json"


def default_minio_client() -> Minio:
    """Builds a Minio client from environment variables, with local-dev defaults
    matching the credentials docker-compose.yml sets for the minio service.
    Not used by any existing CLI/API/dashboard/worker code path - MinIO remains
    an optional, available EvidenceRepository, not the default backend."""
    return Minio(
        os.environ.get("MINIO_ENDPOINT", "localhost:9000"),
        access_key=os.environ.get("MINIO_ACCESS_KEY", "zeroshield"),
        secret_key=os.environ.get("MINIO_SECRET_KEY", "zeroshield123"),
        secure=os.environ.get("MINIO_SECURE", "false").lower() == "true",
    )
