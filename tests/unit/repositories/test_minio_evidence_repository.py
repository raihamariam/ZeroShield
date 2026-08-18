"""Tests MinioEvidenceRepository against an in-memory fake MinIO backend (not a
real broker), exercising the same put/get logic a real MinIO server would - just
without a live server. Genuine end-to-end verification against a real running
MinIO container was done manually via Docker; see the Milestone 22 report.
"""

from datetime import UTC, datetime
from typing import Any
from unittest.mock import MagicMock

import pytest
from minio.error import S3Error

from zeroshield.models import (
    ComparisonReport,
    ExperimentDefinition,
    ExperimentMetrics,
    PolicyDecision,
)
from zeroshield.repositories import build_run_evidence, verify_manifest_integrity
from zeroshield.repositories.minio_evidence_repository import (
    MinioEvidenceRepository,
    default_minio_client,
)
from zeroshield.runners import RunOutcome

STARTED = datetime(2026, 8, 4, 12, 0, 0, tzinfo=UTC)


class _FakeResponse:
    def __init__(self, data: bytes) -> None:
        self._data = data
        self.closed = False
        self.released = False

    def read(self) -> bytes:
        return self._data

    def close(self) -> None:
        self.closed = True

    def release_conn(self) -> None:
        self.released = True


class _FakeMinioBackend:
    """In-memory stand-in for a real MinIO server's relevant surface."""

    def __init__(self) -> None:
        self.buckets: set[str] = set()
        self.objects: dict[tuple[str, str], bytes] = {}
        self.last_response: _FakeResponse | None = None

    def bucket_exists(self, bucket: str) -> bool:
        return bucket in self.buckets

    def make_bucket(self, bucket: str) -> None:
        self.buckets.add(bucket)

    def put_object(self, bucket: str, key: str, data: Any, length: int, **kwargs: Any) -> None:
        content = data.read()
        assert len(content) == length
        self.objects[(bucket, key)] = content

    def get_object(self, bucket: str, key: str, **kwargs: Any) -> _FakeResponse:
        if (bucket, key) not in self.objects:
            raise S3Error(
                response=MagicMock(),
                code="NoSuchKey",
                message="The specified key does not exist.",
                resource=key,
                request_id="fake-request-id",
                host_id="fake-host-id",
                bucket_name=bucket,
                object_name=key,
            )
        self.last_response = _FakeResponse(self.objects[(bucket, key)])
        return self.last_response

    def list_objects(self, bucket: str, prefix: str = "", **kwargs: Any) -> list[str]:
        return [key for (b, key) in self.objects if b == bucket and key.startswith(prefix)]


@pytest.fixture
def fake_backend() -> _FakeMinioBackend:
    return _FakeMinioBackend()


def test_constructor_creates_bucket_if_missing(fake_backend: _FakeMinioBackend) -> None:
    MinioEvidenceRepository(fake_backend, "zeroshield-evidence")  # type: ignore[arg-type]
    assert "zeroshield-evidence" in fake_backend.buckets


def test_constructor_does_not_recreate_existing_bucket(fake_backend: _FakeMinioBackend) -> None:
    fake_backend.buckets.add("zeroshield-evidence")
    MinioEvidenceRepository(fake_backend, "zeroshield-evidence")  # type: ignore[arg-type]
    assert fake_backend.buckets == {"zeroshield-evidence"}


def test_save_and_load_run_evidence_round_trips(
    fake_backend: _FakeMinioBackend,
    valid_experiment_definition_data: dict,
    evidence_run_outcome: RunOutcome,
    evidence_metrics: ExperimentMetrics,
    evidence_policy_decision: PolicyDecision,
) -> None:
    experiment = ExperimentDefinition(**valid_experiment_definition_data)
    bundle = build_run_evidence(
        experiment, "vpn-pre-auth-request-v1", evidence_run_outcome, evidence_metrics, evidence_policy_decision
    )
    repo = MinioEvidenceRepository(fake_backend, "zeroshield-evidence")  # type: ignore[arg-type]

    location = repo.save_run_evidence(bundle)
    assert location.parts == ("zeroshield-evidence", "ZC-VPN-EXP-999", "RUN-001")
    for name in bundle.artefacts:
        assert ("zeroshield-evidence", f"ZC-VPN-EXP-999/RUN-001/{name}") in fake_backend.objects

    loaded = repo.load_manifest("ZC-VPN-EXP-999", "RUN-001")
    assert loaded == bundle.manifest
    assert verify_manifest_integrity(loaded) is True
    # the fake's response must have been drained and released, matching real MinIO usage
    assert fake_backend.last_response is not None
    assert fake_backend.last_response.closed is True
    assert fake_backend.last_response.released is True


def test_load_manifest_raises_file_not_found_for_missing_object(fake_backend: _FakeMinioBackend) -> None:
    repo = MinioEvidenceRepository(fake_backend, "zeroshield-evidence")  # type: ignore[arg-type]
    with pytest.raises(FileNotFoundError):
        repo.load_manifest("ZC-VPN-EXP-999", "RUN-999")


def test_load_manifest_reraises_non_not_found_s3_errors(fake_backend: _FakeMinioBackend) -> None:
    repo = MinioEvidenceRepository(fake_backend, "zeroshield-evidence")  # type: ignore[arg-type]

    def _raise_access_denied(bucket: str, key: str, **kwargs: object) -> None:
        raise S3Error(
            response=MagicMock(),
            code="AccessDenied",
            message="Access Denied.",
            resource=key,
            request_id="fake-request-id",
            host_id="fake-host-id",
            bucket_name=bucket,
            object_name=key,
        )

    fake_backend.get_object = _raise_access_denied  # type: ignore[method-assign]
    with pytest.raises(S3Error):
        repo.load_manifest("ZC-VPN-EXP-999", "RUN-001")


def test_saved_manifest_detects_tampering(
    fake_backend: _FakeMinioBackend,
    valid_experiment_definition_data: dict,
    evidence_run_outcome: RunOutcome,
    evidence_metrics: ExperimentMetrics,
    evidence_policy_decision: PolicyDecision,
) -> None:
    experiment = ExperimentDefinition(**valid_experiment_definition_data)
    bundle = build_run_evidence(
        experiment, "vpn-pre-auth-request-v1", evidence_run_outcome, evidence_metrics, evidence_policy_decision
    )
    repo = MinioEvidenceRepository(fake_backend, "zeroshield-evidence")  # type: ignore[arg-type]
    repo.save_run_evidence(bundle)

    key = ("zeroshield-evidence", "ZC-VPN-EXP-999/RUN-001/manifest.json")
    tampered = fake_backend.objects[key].replace(
        b"weak_schema_length_baseline", b"strict_schema_canonicalisation_mitigation"
    )
    fake_backend.objects[key] = tampered

    loaded = repo.load_manifest("ZC-VPN-EXP-999", "RUN-001")
    assert verify_manifest_integrity(loaded) is False


def test_save_comparison_round_trips(fake_backend: _FakeMinioBackend, evidence_metrics: ExperimentMetrics) -> None:
    mitigation_metrics = evidence_metrics.model_copy(update={"run_id": "RUN-002"})
    report = ComparisonReport(
        experiment_id="ZC-VPN-EXP-999",
        baseline_run_id="RUN-001",
        mitigation_run_id="RUN-002",
        total_cases=22,
        baseline_metrics=evidence_metrics,
        mitigation_metrics=mitigation_metrics,
        block_rate_improvement=1.0,
        latency_overhead_ms=0.5,
        limitations=["synthetic model only"],
        generated_at=STARTED,
    )
    repo = MinioEvidenceRepository(fake_backend, "zeroshield-evidence")  # type: ignore[arg-type]

    location = repo.save_comparison("ZC-VPN-EXP-999", report)
    assert location.parts == ("zeroshield-evidence", "ZC-VPN-EXP-999", "comparison.json")

    stored = fake_backend.objects[("zeroshield-evidence", "ZC-VPN-EXP-999/comparison.json")]
    loaded = ComparisonReport.model_validate_json(stored.decode("utf-8"))
    assert loaded == report


def test_load_comparison_round_trips(fake_backend: _FakeMinioBackend, evidence_metrics: ExperimentMetrics) -> None:
    """Final release gap-closure pass: completes the read side of this
    abstraction - previously only LocalEvidenceRepository could ever be
    read back from (zeroshield.services.experiment_service.
    load_latest_evidence was hardcoded to it), so a MinIO-backed write
    (this method's own save_comparison, confirmed working above) was
    genuinely unreadable through the API/dashboard despite succeeding."""
    mitigation_metrics = evidence_metrics.model_copy(update={"run_id": "RUN-002"})
    report = ComparisonReport(
        experiment_id="ZC-VPN-EXP-999", baseline_run_id="RUN-001", mitigation_run_id="RUN-002",
        total_cases=22, baseline_metrics=evidence_metrics, mitigation_metrics=mitigation_metrics,
        block_rate_improvement=1.0, latency_overhead_ms=0.5, limitations=["synthetic model only"],
        generated_at=STARTED,
    )
    repo = MinioEvidenceRepository(fake_backend, "zeroshield-evidence")  # type: ignore[arg-type]
    repo.save_comparison("ZC-VPN-EXP-999", report)

    loaded = repo.load_comparison("ZC-VPN-EXP-999")
    assert loaded == report


def test_load_comparison_returns_none_when_nothing_saved_yet(fake_backend: _FakeMinioBackend) -> None:
    repo = MinioEvidenceRepository(fake_backend, "zeroshield-evidence")  # type: ignore[arg-type]
    assert repo.load_comparison("ZC-VPN-EXP-999") is None


def test_load_artefact_round_trips_a_named_run_artefact(
    fake_backend: _FakeMinioBackend,
    valid_experiment_definition_data: dict,
    evidence_run_outcome: RunOutcome,
    evidence_metrics: ExperimentMetrics,
    evidence_policy_decision: PolicyDecision,
) -> None:
    experiment = ExperimentDefinition(**valid_experiment_definition_data)
    bundle = build_run_evidence(
        experiment, "vpn-pre-auth-request-v1", evidence_run_outcome, evidence_metrics, evidence_policy_decision
    )
    repo = MinioEvidenceRepository(fake_backend, "zeroshield-evidence")  # type: ignore[arg-type]
    repo.save_run_evidence(bundle)

    manifest = repo.load_manifest("ZC-VPN-EXP-999", "RUN-001")
    raw = repo.load_artefact("ZC-VPN-EXP-999", "RUN-001", str(manifest.artefact_paths["metrics"]))
    assert raw == bundle.artefacts["metrics.json"]


def test_load_artefact_raises_file_not_found_for_missing_object(fake_backend: _FakeMinioBackend) -> None:
    repo = MinioEvidenceRepository(fake_backend, "zeroshield-evidence")  # type: ignore[arg-type]
    with pytest.raises(FileNotFoundError):
        repo.load_artefact("ZC-VPN-EXP-999", "RUN-999", "results.json")


def test_default_minio_client_uses_local_dev_defaults(monkeypatch: pytest.MonkeyPatch) -> None:
    for key in ("MINIO_ENDPOINT", "MINIO_ACCESS_KEY", "MINIO_SECRET_KEY", "MINIO_SECURE"):
        monkeypatch.delenv(key, raising=False)
    client = default_minio_client()
    # constructing a Minio client does not connect to anything (lazy), so this is safe
    # to call without a live server; it only proves the client is wired up correctly.
    assert client._base_url.host == "localhost:9000"
    assert client._base_url.is_https is False


def test_default_minio_client_reads_environment_overrides(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("MINIO_ENDPOINT", "minio.example.com:9000")
    monkeypatch.setenv("MINIO_SECURE", "true")
    client = default_minio_client()
    assert client._base_url.host == "minio.example.com:9000"
    assert client._base_url.is_https is True
