import json
from pathlib import Path

import pytest

from zeroshield.models import ApprovalStatus, Decision, ExperimentDefinition, TestCaseCategory
from zeroshield.models.enums import RunEventType
from zeroshield.policies import ExecutionContext
from zeroshield.repositories import LocalEvidenceRepository
from zeroshield.runners import PolicyRefusalError
from zeroshield.services import experiment_service as services

REPO_ROOT = Path(__file__).resolve().parents[3]
EXPERIMENTS_DIR = REPO_ROOT / "experiments"
VPN_EXPERIMENT_PATH = EXPERIMENTS_DIR / "ZC-VPN-EXP-001.json"
TELECOM_EXPERIMENT_PATH = EXPERIMENTS_DIR / "ZC-TELECOM-EXP-001.json"


def _load(path: Path) -> ExperimentDefinition:
    return ExperimentDefinition.model_validate_json(path.read_text(encoding="utf-8"))


def test_list_experiments_discovers_real_experiments() -> None:
    result = services.list_experiments(EXPERIMENTS_DIR)
    ids = {e.experiment_id for e in result.experiments}
    assert "ZC-VPN-EXP-001" in ids
    assert "ZC-TELECOM-EXP-001" in ids


def test_check_safety_denies_draft_experiment_under_default_context() -> None:
    experiment = _load(VPN_EXPERIMENT_PATH)
    check = services.check_safety(experiment, execution_context=ExecutionContext.EXPERIMENT_RUN)
    assert check.decision.allowed is False
    assert any("SAFE-004" in reason for reason in check.decision.reasons)


def test_check_safety_passes_draft_experiment_under_local_unit_test() -> None:
    experiment = _load(VPN_EXPERIMENT_PATH)
    check = services.check_safety(experiment, execution_context=ExecutionContext.LOCAL_UNIT_TEST)
    assert check.decision.allowed is True


def test_run_experiment_denied_by_safety_policy_cannot_be_bypassed(tmp_path: Path) -> None:
    experiment = _load(VPN_EXPERIMENT_PATH)
    results_root = tmp_path / "results"
    with pytest.raises(PolicyRefusalError) as exc_info:
        services.run_experiment(
            experiment, execution_context=ExecutionContext.EXPERIMENT_RUN, results_root=results_root
        )
    assert any("SAFE-004" in reason for reason in exc_info.value.decision.reasons)
    # strongest proof: no evidence was ever written because the runner never executed a case
    assert not results_root.exists()


def test_run_experiment_denied_for_unsafe_configured_experiment(tmp_path: Path) -> None:
    data = json.loads(VPN_EXPERIMENT_PATH.read_text(encoding="utf-8"))
    data["weaponised_payloads"] = True
    data["approval_status"] = ApprovalStatus.APPROVED.value
    unsafe_experiment = ExperimentDefinition.model_validate(data)

    results_root = tmp_path / "results"
    with pytest.raises(PolicyRefusalError) as exc_info:
        services.run_experiment(
            unsafe_experiment,
            execution_context=ExecutionContext.EXPERIMENT_RUN,
            results_root=results_root,
        )
    assert any("SAFE-003" in reason for reason in exc_info.value.decision.reasons)
    assert not results_root.exists()


def test_run_vpn_experiment_end_to_end_through_real_orchestration(tmp_path: Path) -> None:
    """Integration-level: real orchestration/runner/strategies, no mocking."""
    experiment = _load(VPN_EXPERIMENT_PATH)
    results_root = tmp_path / "results"
    summary = services.run_experiment(
        experiment, execution_context=ExecutionContext.LOCAL_UNIT_TEST, results_root=results_root
    )
    assert summary.comparison_report.experiment_id == "ZC-VPN-EXP-001"
    assert summary.comparison_report.total_cases == 22
    assert summary.baseline_manifest_path.is_file()
    assert summary.mitigation_manifest_path.is_file()
    assert summary.results_dir == results_root / "ZC-VPN-EXP-001"


def test_run_experiment_defaults_to_local_evidence_backend(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """No ZEROSHIELD_EVIDENCE_BACKEND set -> local, per V1 compatibility - every
    existing bare-Python/CI/test invocation has no MinIO server running."""
    monkeypatch.delenv("ZEROSHIELD_EVIDENCE_BACKEND", raising=False)
    experiment = _load(VPN_EXPERIMENT_PATH)
    results_root = tmp_path / "results"
    summary = services.run_experiment(
        experiment, execution_context=ExecutionContext.LOCAL_UNIT_TEST, results_root=results_root
    )
    assert summary.baseline_manifest_path.is_relative_to(results_root)


def test_run_experiment_honours_explicit_evidence_repository_override(tmp_path: Path) -> None:
    experiment = _load(VPN_EXPERIMENT_PATH)
    custom_root = tmp_path / "custom_evidence_location"
    repo = LocalEvidenceRepository(custom_root)
    summary = services.run_experiment(
        experiment,
        execution_context=ExecutionContext.LOCAL_UNIT_TEST,
        results_root=tmp_path / "unused_results",
        evidence_repository=repo,
    )
    assert summary.baseline_manifest_path.is_relative_to(custom_root)
    assert not (tmp_path / "unused_results").exists()


def test_run_experiment_event_sink_receives_preparing_before_anything_else(tmp_path: Path) -> None:
    experiment = _load(VPN_EXPERIMENT_PATH)
    events: list[RunEventType] = []
    services.run_experiment(
        experiment,
        execution_context=ExecutionContext.LOCAL_UNIT_TEST,
        results_root=tmp_path / "results",
        event_sink=lambda event_type, detail: events.append(event_type),
    )
    assert events[0] == RunEventType.PREPARING
    assert events[-1] == RunEventType.GENERATING_EVIDENCE


def test_run_experiment_event_sink_receives_preparing_even_when_denied(tmp_path: Path) -> None:
    """PREPARING is emitted before the dataset/strategy checks and before the safety
    gate - proves it fires unconditionally, not only on a successful run."""
    experiment = _load(VPN_EXPERIMENT_PATH)
    events: list[RunEventType] = []
    with pytest.raises(PolicyRefusalError):
        services.run_experiment(
            experiment,
            execution_context=ExecutionContext.EXPERIMENT_RUN,
            results_root=tmp_path / "results",
            event_sink=lambda event_type, detail: events.append(event_type),
        )
    assert RunEventType.PREPARING in events
    assert RunEventType.RUNNING_BASELINE not in events


def test_resolve_evidence_repository_selects_minio_backend_when_configured(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """ZEROSHIELD_EVIDENCE_BACKEND=minio must select MinioEvidenceRepository - the
    intended default for the containerised platform (docker-compose.yml sets this
    for worker/dashboard). Fakes MinioEvidenceRepository/default_minio_client so
    this never needs a live MinIO server."""
    from zeroshield.repositories import minio_evidence_repository as minio_module

    created: dict[str, object] = {}

    class _FakeMinioRepo:
        def __init__(self, client: object, bucket: str) -> None:
            created["client"] = client
            created["bucket"] = bucket

    monkeypatch.setattr(minio_module, "MinioEvidenceRepository", _FakeMinioRepo)
    monkeypatch.setattr(minio_module, "default_minio_client", lambda: "fake-client")
    monkeypatch.setenv("ZEROSHIELD_EVIDENCE_BACKEND", "minio")
    monkeypatch.setenv("MINIO_EVIDENCE_BUCKET", "custom-bucket")

    repo = services.resolve_evidence_repository(tmp_path / "results")
    assert isinstance(repo, _FakeMinioRepo)
    assert created == {"client": "fake-client", "bucket": "custom-bucket"}


def test_resolve_evidence_repository_defaults_to_local_backend(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.delenv("MINIO_EVIDENCE_BUCKET", raising=False)
    monkeypatch.delenv("ZEROSHIELD_EVIDENCE_BACKEND", raising=False)
    repo = services.resolve_evidence_repository(tmp_path / "results")
    assert isinstance(repo, LocalEvidenceRepository)


def test_run_telecom_experiment_end_to_end_through_real_orchestration(tmp_path: Path) -> None:
    experiment = _load(TELECOM_EXPERIMENT_PATH)
    results_root = tmp_path / "results"
    summary = services.run_experiment(
        experiment, execution_context=ExecutionContext.LOCAL_UNIT_TEST, results_root=results_root
    )
    assert summary.comparison_report.experiment_id == "ZC-TELECOM-EXP-001"
    assert summary.comparison_report.total_cases == 25


def test_run_experiment_unknown_strategy_raises_dashboard_error(tmp_path: Path) -> None:
    data = json.loads(VPN_EXPERIMENT_PATH.read_text(encoding="utf-8"))
    data["baseline_strategy"] = "totally_unknown_strategy"
    experiment = ExperimentDefinition.model_validate(data)

    with pytest.raises(services.ExperimentServiceError):
        services.run_experiment(
            experiment,
            execution_context=ExecutionContext.LOCAL_UNIT_TEST,
            results_root=tmp_path / "results",
        )


def test_run_experiment_missing_dataset_raises_dashboard_error(tmp_path: Path) -> None:
    data = json.loads(VPN_EXPERIMENT_PATH.read_text(encoding="utf-8"))
    data["dataset_path"] = "test_data/vpn/does_not_exist.json"
    experiment = ExperimentDefinition.model_validate(data)

    with pytest.raises(services.ExperimentServiceError):
        services.run_experiment(
            experiment,
            execution_context=ExecutionContext.LOCAL_UNIT_TEST,
            results_root=tmp_path / "results",
        )


def test_load_latest_evidence_returns_none_when_no_results_exist(tmp_path: Path) -> None:
    assert services.load_latest_evidence("ZC-VPN-EXP-001", tmp_path / "results") is None


def test_load_latest_evidence_after_real_run_matches_generated_evidence(tmp_path: Path) -> None:
    experiment = _load(VPN_EXPERIMENT_PATH)
    results_root = tmp_path / "results"
    summary = services.run_experiment(
        experiment, execution_context=ExecutionContext.LOCAL_UNIT_TEST, results_root=results_root
    )

    view = services.load_latest_evidence("ZC-VPN-EXP-001", results_root)
    assert view is not None
    assert view.experiment_id == "ZC-VPN-EXP-001"
    assert view.comparison.generated_at == summary.comparison_report.generated_at
    assert view.baseline_manifest.run_id == summary.comparison_report.baseline_run_id
    assert view.mitigation_manifest.run_id == summary.comparison_report.mitigation_run_id
    assert len(view.case_comparisons) == 22
    assert view.dataset_note is None
    # every case comparison must be a genuine join: real TestCase + real baseline/mitigation CaseResult
    for case in view.case_comparisons:
        assert case.test_case is not None
        assert case.test_case.case_id == case.case_id
        assert case.baseline.case_id == case.case_id
        assert case.mitigation.case_id == case.case_id


def test_load_latest_evidence_skips_cases_missing_from_mitigation_results(tmp_path: Path) -> None:
    """Defends against a tampered/corrupted mitigation results.json missing a case_id."""
    experiment = _load(VPN_EXPERIMENT_PATH)
    results_root = tmp_path / "results"
    summary = services.run_experiment(
        experiment, execution_context=ExecutionContext.LOCAL_UNIT_TEST, results_root=results_root
    )

    mitigation_run_id = summary.comparison_report.mitigation_run_id
    results_path = results_root / "ZC-VPN-EXP-001" / mitigation_run_id / "results.json"
    rows = json.loads(results_path.read_text(encoding="utf-8"))
    del rows[0]
    results_path.write_text(json.dumps(rows), encoding="utf-8")

    view = services.load_latest_evidence("ZC-VPN-EXP-001", results_root)
    assert view is not None
    assert len(view.case_comparisons) == 21


def test_load_latest_evidence_degrades_gracefully_when_dataset_missing(tmp_path: Path) -> None:
    experiment = _load(VPN_EXPERIMENT_PATH)
    results_root = tmp_path / "results"
    services.run_experiment(
        experiment, execution_context=ExecutionContext.LOCAL_UNIT_TEST, results_root=results_root
    )

    # simulate the original dataset having moved/been deleted since the run
    manifest_path = next((results_root / "ZC-VPN-EXP-001").glob("*/dataset_manifest.json"))
    payload = json.loads(manifest_path.read_text(encoding="utf-8"))
    payload["dataset_path"] = "test_data/vpn/no_longer_exists.json"
    manifest_path.write_text(json.dumps(payload), encoding="utf-8")

    view = services.load_latest_evidence("ZC-VPN-EXP-001", results_root)
    assert view is not None
    assert view.dataset_note is not None
    assert all(c.test_case is None for c in view.case_comparisons)


def test_load_latest_evidence_reads_back_through_the_same_minio_backend_that_wrote_it(tmp_path: Path) -> None:
    """The actual final-release gap: run_experiment(evidence_repository=minio)
    followed by load_latest_evidence(evidence_repository=minio) must return
    the same evidence - not silently fall back to (and fail to find
    anything on) the local filesystem. Uses a fake, in-memory MinIO
    backend (same shape as tests/security/test_minio_object_key_safety.py's)
    so this needs no live MinIO server."""
    from unittest.mock import MagicMock

    from minio.error import S3Error

    from zeroshield.repositories.minio_evidence_repository import MinioEvidenceRepository

    class _FakeMinioBackend:
        def __init__(self) -> None:
            self.buckets: set[str] = set()
            self.objects: dict[tuple[str, str], bytes] = {}

        def bucket_exists(self, bucket: str) -> bool:
            return bucket in self.buckets

        def make_bucket(self, bucket: str) -> None:
            self.buckets.add(bucket)

        def put_object(self, bucket: str, key: str, data: object, length: int, **kwargs: object) -> None:
            self.objects[(bucket, key)] = data.read()  # type: ignore[attr-defined]

        def list_objects(self, bucket: str, prefix: str = "", **kwargs: object) -> list[str]:
            return [key for (b, key) in self.objects if b == bucket and key.startswith(prefix)]

        def get_object(self, bucket: str, key: str, **kwargs: object) -> MagicMock:
            if (bucket, key) not in self.objects:
                raise S3Error(
                    response=MagicMock(), code="NoSuchKey", message="not found", resource=key,
                    request_id="x", host_id="x", bucket_name=bucket, object_name=key,
                )
            response = MagicMock()
            response.read.return_value = self.objects[(bucket, key)]
            return response

    repo = MinioEvidenceRepository(_FakeMinioBackend(), "zeroshield-evidence")  # type: ignore[arg-type]
    experiment = _load(VPN_EXPERIMENT_PATH)
    summary = services.run_experiment(
        experiment, execution_context=ExecutionContext.LOCAL_UNIT_TEST,
        results_root=tmp_path / "unused_results", evidence_repository=repo,
    )
    assert not (tmp_path / "unused_results").exists()  # nothing touched the local filesystem

    view = services.load_latest_evidence("ZC-VPN-EXP-001", tmp_path / "unused_results", evidence_repository=repo)
    assert view is not None
    assert view.comparison.generated_at == summary.comparison_report.generated_at
    assert view.baseline_manifest.run_id == summary.comparison_report.baseline_run_id
    assert view.mitigation_manifest.run_id == summary.comparison_report.mitigation_run_id
    assert len(view.case_comparisons) == 22
    for case in view.case_comparisons:
        assert case.baseline.case_id == case.case_id
        assert case.mitigation.case_id == case.case_id


def test_summarise_case_categories_matches_real_vpn_dataset(tmp_path: Path) -> None:
    experiment = _load(VPN_EXPERIMENT_PATH)
    results_root = tmp_path / "results"
    services.run_experiment(
        experiment, execution_context=ExecutionContext.LOCAL_UNIT_TEST, results_root=results_root
    )
    view = services.load_latest_evidence("ZC-VPN-EXP-001", results_root)
    assert view is not None
    breakdown = services.summarise_case_categories(view.case_comparisons)

    assert breakdown.valid_count == 4
    assert breakdown.malformed_count == 15
    assert breakdown.boundary_count == 3
    # baseline is deliberately weak: it does not block malformed-only markers
    assert breakdown.baseline_malformed_block_rate == 0.0
    # mitigation is strict: it blocks every malformed case
    assert breakdown.mitigation_malformed_block_rate == 1.0


def test_summarise_case_categories_handles_empty_list() -> None:
    breakdown = services.summarise_case_categories([])
    assert breakdown.valid_count == 0
    assert breakdown.malformed_count == 0
    assert breakdown.boundary_count == 0
    assert breakdown.baseline_malformed_block_rate is None
    assert breakdown.mitigation_malformed_block_rate is None


def test_generate_overleaf_export_uses_existing_exporter(tmp_path: Path) -> None:
    experiment = _load(VPN_EXPERIMENT_PATH)
    results_root = tmp_path / "results"
    summary = services.run_experiment(
        experiment, execution_context=ExecutionContext.LOCAL_UNIT_TEST, results_root=results_root
    )

    export_root = tmp_path / "overleaf_exports"
    export_dir = services.generate_overleaf_export(experiment, summary.comparison_report, export_root)

    assert export_dir == export_root / "ZC-VPN-EXP-001"
    assert (export_dir / "comparison.csv").is_file()
    assert (export_dir / "metrics.tex").is_file()
    assert (export_dir / "factual_summary.tex").is_file()


def test_case_comparison_category_values_are_real_enum_members(tmp_path: Path) -> None:
    experiment = _load(VPN_EXPERIMENT_PATH)
    results_root = tmp_path / "results"
    services.run_experiment(
        experiment, execution_context=ExecutionContext.LOCAL_UNIT_TEST, results_root=results_root
    )
    view = services.load_latest_evidence("ZC-VPN-EXP-001", results_root)
    assert view is not None
    categories = {c.test_case.category for c in view.case_comparisons if c.test_case is not None}
    assert categories <= {TestCaseCategory.VALID, TestCaseCategory.MALFORMED, TestCaseCategory.BOUNDARY}
    decisions = {c.baseline.decision for c in view.case_comparisons} | {
        c.mitigation.decision for c in view.case_comparisons
    }
    assert decisions <= {Decision.ACCEPTED, Decision.BLOCKED}
