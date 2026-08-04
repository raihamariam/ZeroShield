import csv
import io
from datetime import UTC, datetime
from pathlib import Path

from zeroshield.exports import (
    export_comparison_csv,
    export_factual_summary_tex,
    export_metrics_tex,
    save_overleaf_export,
)
from zeroshield.models import ComparisonReport, ExperimentDefinition, ExperimentMetrics

FORBIDDEN_PHRASES = [
    "proves",
    "guarantees",
    "protects the real",
    "eliminates the vulnerability",
    "fully secure",
    "vendor product is safe",
]


def _metrics(run_id: str, block_rate: float, mean_latency_ms: float) -> ExperimentMetrics:
    return ExperimentMetrics(
        run_id=run_id,
        processing_success_rate=1.0,
        block_rate=block_rate,
        valid_acceptance_rate=1.0,
        false_positive_rate=0.0,
        false_negative_rate=1.0 - block_rate,
        parser_reach_rate=1.0 - block_rate,
        mean_latency_ms=mean_latency_ms,
        log_completeness_rate=block_rate,
        calculated_at=datetime(2026, 8, 4, 12, 0, 0, tzinfo=UTC),
        calculation_version="1.0.0",
    )


def _report() -> ComparisonReport:
    baseline = _metrics("RUN-001", block_rate=0.0, mean_latency_ms=1.0)
    mitigation = _metrics("RUN-002", block_rate=1.0, mean_latency_ms=1.5)
    return ComparisonReport(
        experiment_id="ZC-VPN-EXP-999",
        baseline_run_id="RUN-001",
        mitigation_run_id="RUN-002",
        total_cases=22,
        baseline_metrics=baseline,
        mitigation_metrics=mitigation,
        block_rate_improvement=1.0,
        latency_overhead_ms=0.5,
        limitations=["This is a test limitation statement with 50% coverage & special chars."],
        generated_at=datetime(2026, 8, 4, 12, 0, 5, tzinfo=UTC),
    )


def _experiment(valid_experiment_definition_data: dict) -> ExperimentDefinition:
    return ExperimentDefinition(**valid_experiment_definition_data)


def test_comparison_csv_has_correct_headers_and_values() -> None:
    report = _report()
    csv_text = export_comparison_csv(report)
    reader = csv.DictReader(io.StringIO(csv_text))
    rows = list(reader)

    assert reader.fieldnames == ["metric", "baseline", "mitigation", "difference"]
    assert len(rows) == 8

    block_row = next(r for r in rows if r["metric"] == "Block rate")
    assert float(block_row["baseline"]) == 0.0
    assert float(block_row["mitigation"]) == 1.0
    assert float(block_row["difference"]) == 1.0


def test_metrics_tex_is_well_formed_and_correct() -> None:
    report = _report()
    tex = export_metrics_tex(report)
    assert r"\begin{tabular}{lrrr}" in tex
    assert r"\end{tabular}" in tex
    assert "Block rate & 0.000 & 1.000 & 1.000" in tex


def test_metrics_tex_escapes_experiment_id() -> None:
    report = _report()
    tex = export_metrics_tex(report)
    assert "ZC-VPN-EXP-999" in tex  # hyphens need no escaping


def test_factual_summary_contains_only_measured_values(valid_experiment_definition_data: dict) -> None:
    report = _report()
    experiment = _experiment(valid_experiment_definition_data)
    summary = export_factual_summary_tex(report, experiment)

    assert "22 test cases" in summary
    assert "CVE-2024-21762" in summary
    assert "0.0\\%" in summary
    assert "100.0\\%" in summary


def test_factual_summary_reuses_limitations_verbatim(valid_experiment_definition_data: dict) -> None:
    report = _report()
    experiment = _experiment(valid_experiment_definition_data)
    summary = export_factual_summary_tex(report, experiment)
    # the literal limitation text (LaTeX-escaped) must appear, not a rewritten version
    assert "This is a test limitation statement with 50\\% coverage \\& special chars." in summary


def test_factual_summary_never_contains_overclaiming_language(
    valid_experiment_definition_data: dict,
) -> None:
    report = _report()
    experiment = _experiment(valid_experiment_definition_data)
    summary = export_factual_summary_tex(report, experiment).lower()
    for phrase in FORBIDDEN_PHRASES:
        assert phrase not in summary


def test_save_overleaf_export_writes_all_three_files(
    tmp_path: Path, valid_experiment_definition_data: dict
) -> None:
    report = _report()
    experiment = _experiment(valid_experiment_definition_data)
    export_dir = save_overleaf_export(tmp_path, report, experiment)

    assert export_dir == tmp_path / "ZC-VPN-EXP-999"
    assert (export_dir / "comparison.csv").is_file()
    assert (export_dir / "metrics.tex").is_file()
    assert (export_dir / "factual_summary.tex").is_file()

    csv_content = (export_dir / "comparison.csv").read_bytes().decode("utf-8")
    assert csv_content == export_comparison_csv(report)
