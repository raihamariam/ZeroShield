"""Evidence immutability (Milestone 26 fix, closing a real gap against the SRS's
own S10.3 threat model: "Path traversal or evidence overwrite - Canonical
paths, immutable run directories, generated IDs and repository boundary."
Before this milestone, LocalEvidenceRepository/MinioEvidenceRepository would
silently overwrite an existing run's evidence if called twice with the same
run_id - this proves that can no longer happen, in either backend, and that
the original evidence is provably untouched by a rejected attempt.
"""

from pathlib import Path
from typing import Any
from unittest.mock import MagicMock

import pytest
from minio.error import S3Error

from zeroshield.models import ExperimentDefinition
from zeroshield.orchestration import execute_and_generate_evidence
from zeroshield.policies import ExecutionContext
from zeroshield.repositories import EvidenceAlreadyExistsError, LocalEvidenceRepository
from zeroshield.repositories.evidence_repository import EvidenceRepository
from zeroshield.repositories.minio_evidence_repository import MinioEvidenceRepository
from zeroshield.strategies.registry import resolve_strategy

REPO_ROOT = Path(__file__).resolve().parents[2]
VPN_EXPERIMENT = REPO_ROOT / "experiments" / "ZC-VPN-EXP-001.json"
VPN_DATASET = REPO_ROOT / "test_data" / "vpn" / "vpn_pre_auth_request_dataset.json"


def _run(
    evidence_repository: EvidenceRepository, baseline_run_id: str, mitigation_run_id: str
) -> None:
    experiment = ExperimentDefinition.model_validate_json(VPN_EXPERIMENT.read_text(encoding="utf-8"))
    baseline = resolve_strategy(experiment.baseline_strategy)
    mitigation = resolve_strategy(experiment.mitigation_strategy)
    execute_and_generate_evidence(
        experiment,
        VPN_DATASET,
        baseline=baseline,
        mitigation=mitigation,
        baseline_run_id=baseline_run_id,
        mitigation_run_id=mitigation_run_id,
        git_commit="0000000",
        evidence_repository=evidence_repository,
        execution_context=ExecutionContext.LOCAL_UNIT_TEST,
    )


def test_local_repository_rejects_overwriting_baseline_evidence(tmp_path: Path) -> None:
    results_root = tmp_path / "results"
    repo = LocalEvidenceRepository(results_root)
    _run(repo, "RUN-001", "RUN-002")

    manifest_path = results_root / "ZC-VPN-EXP-001" / "RUN-001" / "manifest.json"
    original = manifest_path.read_text(encoding="utf-8")

    with pytest.raises(EvidenceAlreadyExistsError):
        _run(repo, "RUN-001", "RUN-003")

    # the colliding baseline attempt is rejected before mitigation is ever reached
    assert not (results_root / "ZC-VPN-EXP-001" / "RUN-003").exists()
    # and the original baseline evidence is provably untouched
    assert manifest_path.read_text(encoding="utf-8") == original


def test_local_repository_rejects_overwriting_mitigation_evidence(tmp_path: Path) -> None:
    results_root = tmp_path / "results"
    repo = LocalEvidenceRepository(results_root)
    _run(repo, "RUN-101", "RUN-102")

    manifest_path = results_root / "ZC-VPN-EXP-001" / "RUN-102" / "manifest.json"
    original = manifest_path.read_text(encoding="utf-8")

    with pytest.raises(EvidenceAlreadyExistsError):
        _run(repo, "RUN-201", "RUN-102")

    assert manifest_path.read_text(encoding="utf-8") == original


def test_local_repository_allows_a_genuinely_new_run_id(tmp_path: Path) -> None:
    results_root = tmp_path / "results"
    repo = LocalEvidenceRepository(results_root)
    _run(repo, "RUN-301", "RUN-302")
    _run(repo, "RUN-401", "RUN-402")  # no collision - must succeed

    assert (results_root / "ZC-VPN-EXP-001" / "RUN-301").is_dir()
    assert (results_root / "ZC-VPN-EXP-001" / "RUN-401").is_dir()


class _FakeMinioBackend:
    """Minimal in-memory MinIO stand-in, just enough for save_run_evidence's
    overwrite check (list_objects) and put_object/get_object/bucket_exists."""

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
                response=MagicMock(),
                code="NoSuchKey",
                message="not found",
                resource=key,
                request_id="x",
                host_id="x",
                bucket_name=bucket,
                object_name=key,
            )
        response = MagicMock()
        response.read.return_value = self.objects[(bucket, key)]
        return response


def test_minio_repository_rejects_overwriting_baseline_evidence(tmp_path: Path) -> None:
    repo = MinioEvidenceRepository(_FakeMinioBackend(), "zeroshield-evidence")  # type: ignore[arg-type]
    _run(repo, "RUN-501", "RUN-502")

    with pytest.raises(EvidenceAlreadyExistsError):
        _run(repo, "RUN-501", "RUN-503")
