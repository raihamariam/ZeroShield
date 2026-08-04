"""Security tests (SRS §11.1): identifier/path handling must resist path-traversal input."""

from datetime import UTC, datetime

import pytest
from pydantic import ValidationError

from zeroshield.models import CaseResult, EvidenceManifest, ExperimentRun

MALICIOUS_IDS = [
    "../../etc/passwd",
    "..\\..\\windows\\system32",
    "ZC-VPN-EXP-001/../../../secret",
    "ZC-VPN-EXP-001; rm -rf /",
    "",
    "ZC-VPN-EXP-001\x00.json",
]


@pytest.mark.parametrize("bad_experiment_id", MALICIOUS_IDS)
def test_experiment_run_rejects_path_traversal_experiment_id(bad_experiment_id: str) -> None:
    with pytest.raises(ValidationError):
        ExperimentRun(
            run_id="RUN-001",
            experiment_id=bad_experiment_id,
            mode="baseline",
            dataset_hash="a" * 64,
            git_commit="abc1234",
            environment={"python_version": "3.12.10"},
            started_at=datetime(2026, 8, 4, 12, 0, 0, tzinfo=UTC),
        )


@pytest.mark.parametrize("bad_run_id", MALICIOUS_IDS)
def test_case_result_rejects_path_traversal_run_id(bad_run_id: str) -> None:
    with pytest.raises(ValidationError):
        CaseResult(
            run_id=bad_run_id,
            case_id="TC-001",
            decision="accepted",
            parser_reached=True,
            errored=False,
            logged=False,
            latency_ms=1.0,
        )


def test_evidence_manifest_artefact_paths_reject_traversal_sequences() -> None:
    with pytest.raises(ValidationError, match="relative"):
        EvidenceManifest(
            manifest_version="1.0.0",
            experiment_id="ZC-VPN-EXP-001",
            experiment_version="1.0.0",
            run_id="RUN-001",
            mode="baseline",
            test_set_id="vpn-pre-auth-request-v1",
            test_set_sha256="a" * 64,
            git_commit="abc1234",
            started_at=datetime(2026, 8, 4, 12, 0, 0, tzinfo=UTC),
            completed_at=datetime(2026, 8, 4, 12, 0, 5, tzinfo=UTC),
            strategy_id="weak_schema_length_baseline",
            metrics={
                "run_id": "RUN-001",
                "processing_success_rate": 1.0,
                "block_rate": 0.0,
                "valid_acceptance_rate": 1.0,
                "false_positive_rate": 0.0,
                "false_negative_rate": 0.0,
                "parser_reach_rate": 0.0,
                "mean_latency_ms": 1.0,
                "log_completeness_rate": 0.0,
                "calculated_at": datetime(2026, 8, 4, 12, 0, 5, tzinfo=UTC),
                "calculation_version": "1.0.0",
            },
            artefact_paths={"results": "../../etc/passwd"},
            safety_decision={
                "allowed": True,
                "evaluated_at": datetime(2026, 8, 4, 12, 0, 0, tzinfo=UTC),
                "rule_results": {"SAFE-001": True},
                "reasons": [],
                "policy_version": "1.0.0",
            },
            review_status="draft",
            manifest_sha256="b" * 64,
        )
