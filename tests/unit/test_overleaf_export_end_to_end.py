import json
from pathlib import Path

import pytest

from zeroshield.datasets import load_test_set
from zeroshield.exports import save_overleaf_export
from zeroshield.metrics import calculate_metrics, compare
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


def _load_experiment(name: str) -> ExperimentDefinition:
    data = json.loads((REPO_ROOT / "experiments" / name).read_text(encoding="utf-8"))
    return ExperimentDefinition(**data)


@pytest.mark.parametrize("experiment_file,dataset_path,baseline_cls,mitigation_cls", CASES)
def test_real_experiment_exports_to_overleaf_format(
    tmp_path: Path,
    experiment_file: str,
    dataset_path: Path,
    baseline_cls: type,
    mitigation_cls: type,
) -> None:
    experiment = _load_experiment(experiment_file)
    test_set, _ = load_test_set(dataset_path)

    result = ExperimentRunner().run(
        experiment,
        dataset_path,
        baseline=baseline_cls(),
        mitigation=mitigation_cls(),
        baseline_run_id="RUN-001",
        mitigation_run_id="RUN-002",
        git_commit="0123456",
        execution_context=ExecutionContext.LOCAL_UNIT_TEST,
    )
    baseline_metrics = calculate_metrics("RUN-001", result.baseline.case_results, test_set.cases)
    mitigation_metrics = calculate_metrics("RUN-002", result.mitigation.case_results, test_set.cases)
    report = compare(experiment.experiment_id, len(test_set.cases), baseline_metrics, mitigation_metrics)

    export_dir = save_overleaf_export(tmp_path, report, experiment)

    assert export_dir == tmp_path / experiment.experiment_id
    csv_text = (export_dir / "comparison.csv").read_text(encoding="utf-8")
    assert f"{mitigation_metrics.block_rate:.6f}" in csv_text

    summary = (export_dir / "factual_summary.tex").read_text(encoding="utf-8")
    assert str(len(test_set.cases)) in summary
    for cve in experiment.related_cves:
        assert cve.cve_id in summary
