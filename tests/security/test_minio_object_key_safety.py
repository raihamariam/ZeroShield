"""MinIO object-key hardening (V2 Phase 6, Step 4). S3-compatible object
storage has a flat key namespace - there is no directory tree for "../" to
walk up out of the way there is on a real filesystem, so classic path
traversal does not apply to MinioEvidenceRepository the way it does to
LocalEvidenceRepository (see test_path_traversal_comprehensive.py). What
does still matter: a malicious experiment_id/run_id must never let one run's
evidence collide with or overwrite an unrelated object, and must never
reach this layer at all in the first place - the API only ever calls it
with a server-validated experiment_id (zeroshield.api.dependencies.
get_experiment) and a server-generated run_id (RUN-<uuid4 hex>), never raw
client input (see zeroshield.runners.experiment_runner).
"""

from pathlib import Path
from typing import Any
from unittest.mock import MagicMock

import pytest
from minio.error import S3Error

from zeroshield.models import ExperimentDefinition
from zeroshield.orchestration import execute_and_generate_evidence
from zeroshield.policies import ExecutionContext
from zeroshield.repositories.minio_evidence_repository import MinioEvidenceRepository
from zeroshield.strategies.registry import resolve_strategy

REPO_ROOT = Path(__file__).resolve().parents[2]
VPN_EXPERIMENT = REPO_ROOT / "experiments" / "ZC-VPN-EXP-001.json"
VPN_DATASET = REPO_ROOT / "test_data" / "vpn" / "vpn_pre_auth_request_dataset.json"


class _FakeMinioBackend:
    def __init__(self) -> None:
        self.buckets: set[str] = set()
        self.objects: dict[tuple[str, str], bytes] = {}

    def bucket_exists(self, bucket: str) -> bool:
        return bucket in self.buckets

    def make_bucket(self, bucket: str) -> None:
        self.buckets.add(bucket)

    def put_object(self, bucket: str, key: str, data: Any, length: int, **kwargs: Any) -> None:
        self.objects[(bucket, key)] = data.read()

    def list_objects(self, bucket: str, prefix: str = "", **kwargs: Any) -> list[str]:
        return [key for (b, key) in self.objects if b == bucket and key.startswith(prefix)]

    def get_object(self, bucket: str, key: str, **kwargs: Any) -> MagicMock:
        if (bucket, key) not in self.objects:
            raise S3Error(
                response=MagicMock(), code="NoSuchKey", message="not found", resource=key,
                request_id="x", host_id="x", bucket_name=bucket, object_name=key,
            )
        response = MagicMock()
        response.read.return_value = self.objects[(bucket, key)]
        return response


def test_object_key_is_a_literal_string_never_interpreted_as_a_path() -> None:
    """A malicious-looking experiment_id, if it ever reached this layer,
    becomes a literal S3 key - '..' is just two dots in a key string, not a
    directory-traversal operator, so it can never resolve to a different
    bucket or escape the key prefix it was given."""
    repo = MinioEvidenceRepository(_FakeMinioBackend(), "zeroshield-evidence")  # type: ignore[arg-type]
    key = repo._object_key("../../etc/passwd", "RUN-1", "manifest.json")
    assert key == "../../etc/passwd/RUN-1/manifest.json"
    # It is one single literal key - not multiple path segments interpreted
    # by any filesystem-style resolver (this repository never calls
    # os.path/pathlib on the key at all).
    assert isinstance(key, str)


def test_run_id_is_rejected_at_the_domain_model_before_ever_reaching_a_repository() -> None:
    """A stronger guarantee than the object-key test above: run_id is
    Pydantic-constrained (CaseResult.run_id: ^RUN-\\d{3,}$) at the domain
    model layer, so a traversal-shaped run_id can never even complete a run,
    let alone reach MinioEvidenceRepository/LocalEvidenceRepository. Not
    that this test needed to reach the repository to prove the point -
    that's exactly what makes it a stronger defense than a repository-level
    check alone would be."""
    experiment = ExperimentDefinition.model_validate_json(VPN_EXPERIMENT.read_text(encoding="utf-8"))
    baseline = resolve_strategy(experiment.baseline_strategy)
    mitigation = resolve_strategy(experiment.mitigation_strategy)
    repo = MinioEvidenceRepository(_FakeMinioBackend(), "zeroshield-evidence")  # type: ignore[arg-type]

    with pytest.raises(Exception, match="run_id"):
        execute_and_generate_evidence(
            experiment, VPN_DATASET, baseline=baseline, mitigation=mitigation,
            baseline_run_id="RUN-../../evil", mitigation_run_id="RUN-2", git_commit="0000000",
            evidence_repository=repo, execution_context=ExecutionContext.LOCAL_UNIT_TEST,
        )
