import json
from pathlib import Path
from typing import Any

import pytest

from zeroshield.models import ApprovalStatus, ExperimentDefinition
from zeroshield.orchestration import execute_and_generate_evidence
from zeroshield.policies import ExecutionContext
from zeroshield.repositories import LocalEvidenceRepository, verify_manifest_integrity
from zeroshield.runners import PolicyRefusalError
from zeroshield.strategies import ProcessingStrategy, StrategyOutcome


class _StubStrategy(ProcessingStrategy):
    def __init__(self, strategy_id: str, decision: str) -> None:
        self.strategy_id = strategy_id
        self._decision = decision

    def process(self, input_data: dict[str, Any]) -> StrategyOutcome:
        return StrategyOutcome(
            decision=self._decision,
            parser_reached=self._decision == "accepted",
            logged=self._decision == "blocked",
        )


def _telecom_cve() -> dict[str, Any]:
    return {
        "cve_id": "CVE-2023-23846",
        "domain": "TELECOM",
        "cvss_score": None,
        "cisa_kev": False,
        "epss_score": None,
        "trust_boundary": "GTP-U interface",
        "root_cause": "parser_message_handling_failure",
        "vendor_mitigation": "test",
        "mitigation_gap": "test",
        "source_urls": ["https://github.com/advisories/GHSA-3vj7-j945-rq57"],
        "retrieved_date": "2026-07-13",
    }


def _telecom_experiment(approved: bool) -> ExperimentDefinition:
    return ExperimentDefinition(
        experiment_id="ZC-TELECOM-EXP-999",
        title="Orchestrator reusability test experiment",
        domain="TELECOM",
        description="Synthetic experiment used only to prove the orchestrator has no VPN coupling.",
        related_cves=[_telecom_cve()],
        failure_pattern="test failure pattern",
        root_cause="parser_message_handling_failure",
        vendor_mitigation="test",
        mitigation_gap="test",
        research_question="test question?",
        hypothesis="test hypothesis",
        safety_level="SYNTHETIC_ONLY",
        baseline_strategy="telecom_stub_baseline",
        mitigation_strategy="telecom_stub_mitigation",
        dataset_path="test_data/telecom/orchestrator_test_dataset.json",
        metrics_to_collect=["block_rate"],
        approval_status=ApprovalStatus.APPROVED if approved else ApprovalStatus.DRAFT,
    )


def _write_dataset(path: Path) -> None:
    dataset = {
        "test_set_id": "orchestrator-test-v1",
        "version": "1.0.0",
        "domain": "TELECOM",
        "cases": [
            {
                "case_id": f"TC-{i:03d}",
                "category": "malformed",
                "input_data": {"seq": i},
                "expected_outcome": "blocked",
                "provenance": "synthetic",
                "version": "1.0.0",
            }
            for i in range(3)
        ],
    }
    path.write_text(json.dumps(dataset), encoding="utf-8")


def test_orchestrator_produces_evidence_for_a_non_vpn_experiment(tmp_path: Path) -> None:
    dataset_path = tmp_path / "dataset.json"
    _write_dataset(dataset_path)
    evidence_root = tmp_path / "evidence"
    repo = LocalEvidenceRepository(evidence_root)
    experiment = _telecom_experiment(approved=True)

    result = execute_and_generate_evidence(
        experiment,
        dataset_path,
        baseline=_StubStrategy("telecom_stub_baseline", "accepted"),
        mitigation=_StubStrategy("telecom_stub_mitigation", "blocked"),
        baseline_run_id="RUN-001",
        mitigation_run_id="RUN-002",
        git_commit="abc1234",
        evidence_repository=repo,
        execution_context=ExecutionContext.EXPERIMENT_RUN,
    )

    assert result.baseline_manifest_path.is_file()
    assert result.mitigation_manifest_path.is_file()
    assert result.comparison_path.is_file()
    assert result.comparison_report.mitigation_metrics.block_rate == 1.0
    assert result.comparison_report.baseline_metrics.block_rate == 0.0

    baseline_manifest = repo.load_manifest("ZC-TELECOM-EXP-999", "RUN-001")
    assert verify_manifest_integrity(baseline_manifest) is True


def test_orchestrator_refuses_unapproved_experiment(tmp_path: Path) -> None:
    dataset_path = tmp_path / "dataset.json"
    _write_dataset(dataset_path)
    repo = LocalEvidenceRepository(tmp_path / "evidence")
    experiment = _telecom_experiment(approved=False)

    with pytest.raises(PolicyRefusalError):
        execute_and_generate_evidence(
            experiment,
            dataset_path,
            baseline=_StubStrategy("telecom_stub_baseline", "accepted"),
            mitigation=_StubStrategy("telecom_stub_mitigation", "blocked"),
            baseline_run_id="RUN-001",
            mitigation_run_id="RUN-002",
            git_commit="abc1234",
            evidence_repository=repo,
            execution_context=ExecutionContext.EXPERIMENT_RUN,
        )
    assert not (tmp_path / "evidence").exists()
