"""Reproducibility tests (SRS §11.1 / NFR-004): independent re-runs must match exactly."""

import json
from pathlib import Path

import pytest

from zeroshield.models import ExperimentDefinition
from zeroshield.policies import ExecutionContext
from zeroshield.runners import ExperimentRunner
from zeroshield.strategies.telecom import (
    StrictGrammarStateMachineMitigation,
    WeakMandatoryFieldStateBaseline,
)
from zeroshield.strategies.vpn import (
    StrictSchemaCanonicalisationMitigation,
    WeakSchemaLengthBaseline,
)

REPO_ROOT = Path(__file__).resolve().parents[2]


def _load_experiment(name: str) -> ExperimentDefinition:
    data = json.loads((REPO_ROOT / "experiments" / name).read_text(encoding="utf-8"))
    return ExperimentDefinition(**data)


CASES = [
    pytest.param(
        "ZC-VPN-EXP-001.json",
        REPO_ROOT / "test_data" / "vpn" / "vpn_pre_auth_request_dataset.json",
        WeakSchemaLengthBaseline,
        StrictSchemaCanonicalisationMitigation,
        id="vpn",
    ),
    pytest.param(
        "ZC-TELECOM-EXP-001.json",
        REPO_ROOT / "test_data" / "telecom" / "telecom_sip_session_setup_dataset.json",
        WeakMandatoryFieldStateBaseline,
        StrictGrammarStateMachineMitigation,
        id="telecom",
    ),
]


@pytest.mark.parametrize("experiment_file,dataset_path,baseline_cls,mitigation_cls", CASES)
def test_independent_reruns_reproduce_identical_hashes_and_decisions(
    experiment_file: str, dataset_path: Path, baseline_cls: type, mitigation_cls: type
) -> None:
    experiment = _load_experiment(experiment_file)

    run_one = ExperimentRunner().run(
        experiment,
        dataset_path,
        baseline=baseline_cls(),
        mitigation=mitigation_cls(),
        baseline_run_id="RUN-001",
        mitigation_run_id="RUN-002",
        git_commit="0123456",
        execution_context=ExecutionContext.LOCAL_UNIT_TEST,
    )
    # A second, fully independent run: fresh runner, fresh strategy instances, same inputs.
    run_two = ExperimentRunner().run(
        experiment,
        dataset_path,
        baseline=baseline_cls(),
        mitigation=mitigation_cls(),
        baseline_run_id="RUN-001",
        mitigation_run_id="RUN-002",
        git_commit="0123456",
        execution_context=ExecutionContext.LOCAL_UNIT_TEST,
    )

    assert run_one.baseline.run.dataset_hash == run_two.baseline.run.dataset_hash
    assert run_one.mitigation.run.dataset_hash == run_two.mitigation.run.dataset_hash

    def decisions(results: list) -> list[tuple[str, str, bool, bool]]:
        return [(r.case_id, r.decision, r.parser_reached, r.logged) for r in results]

    assert decisions(run_one.baseline.case_results) == decisions(run_two.baseline.case_results)
    assert decisions(run_one.mitigation.case_results) == decisions(run_two.mitigation.case_results)
