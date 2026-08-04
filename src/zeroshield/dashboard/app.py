"""ZeroShield Demo Dashboard (Milestone 18).

A Streamlit presentation/demonstration layer over the existing ZeroShield
Core. This module only renders UI and calls zeroshield.services.experiment_service,
which itself only calls existing core functionality (experiment discovery,
SafetyPolicy, orchestration, repositories, exporter). No safety, strategy,
or metric logic is implemented here - the existing core remains the source
of truth. Launch from the repository root:

    streamlit run src/zeroshield/dashboard/app.py
"""

from pathlib import Path

import streamlit as st

from zeroshield.models import ComparisonReport, Domain, ExperimentDefinition
from zeroshield.policies import ExecutionContext
from zeroshield.repositories import verify_manifest_integrity
from zeroshield.runners import PolicyRefusalError
from zeroshield.services import experiment_service as services

REPO_ROOT = Path.cwd()
EXPERIMENTS_DIR = REPO_ROOT / "experiments"
RESULTS_ROOT = REPO_ROOT / "results"
OVERLEAF_EXPORT_ROOT = REPO_ROOT / "overleaf_exports"

METRIC_LABELS: list[tuple[str, str]] = [
    ("processing_success_rate", "Processing success"),
    ("block_rate", "Block rate (cases expected to be blocked)"),
    ("valid_acceptance_rate", "Valid acceptance rate"),
    ("false_positive_rate", "False-positive rate"),
    ("false_negative_rate", "False-negative rate"),
    ("parser_reach_rate", "Parser exposure rate"),
    ("mean_latency_ms", "Mean latency (ms)"),
    ("log_completeness_rate", "Log completeness rate"),
]


def domain_badge(domain: Domain) -> None:
    if domain == Domain.VPN:
        st.badge("VPN", color="blue")
    else:
        st.badge("TELECOM", color="violet")


def render_overview() -> None:
    st.title("ZeroShield")
    st.subheader("A Sandbox-Based Validation Framework for Zero-Click Vulnerability Mitigations")
    st.markdown(
        "ZeroShield turns curated zero-click CVE research into controlled, reproducible, "
        "**synthetic** experiments that measure whether a candidate mitigation changes "
        "defensive behaviour compared to a deliberately weak baseline, over the same dataset."
    )
    st.markdown("#### Pipeline")
    st.markdown("Research &rarr; Experiment &rarr; Baseline &rarr; Mitigation &rarr; Comparison &rarr; Evidence")
    st.warning(
        "**Phase 1 uses synthetic experiments only.** ZeroShield does not reproduce real vendor "
        "exploits, does not target real systems or vendor products, and does not process real "
        "attacker traffic."
    )


def render_experiment_details(experiment: ExperimentDefinition) -> None:
    left, right = st.columns([3, 1])
    with left:
        st.subheader(f"{experiment.experiment_id} — {experiment.title}")
    with right:
        domain_badge(experiment.domain)

    st.caption(experiment.description)

    col1, col2 = st.columns(2)
    with col1:
        st.markdown(f"**Root cause:** {experiment.root_cause.value}")
        st.markdown(f"**Failure pattern:** {experiment.failure_pattern}")
        st.markdown(f"**Vendor mitigation:** {experiment.vendor_mitigation}")
        st.markdown(f"**Mitigation gap:** {experiment.mitigation_gap}")
    with col2:
        st.markdown(f"**Safety level:** {experiment.safety_level.value}")
        st.markdown(f"**Approval status:** `{experiment.approval_status.value}`")
        st.markdown(f"**Baseline strategy:** `{experiment.baseline_strategy}`")
        st.markdown(f"**Mitigation strategy:** `{experiment.mitigation_strategy}`")

    st.markdown("**Research question:** " + experiment.research_question)
    st.markdown("**Hypothesis:** " + experiment.hypothesis)

    st.markdown("**Related CVEs**")
    cve_rows = [
        {
            "CVE": cve.cve_id,
            "CVSS": cve.cvss_score,
            "CISA KEV": cve.cisa_kev,
            "EPSS": cve.epss_score,
            "Trust boundary": cve.trust_boundary,
        }
        for cve in experiment.related_cves
    ]
    st.dataframe(cve_rows, hide_index=True, width="stretch")


def render_safety_and_run(experiment: ExperimentDefinition) -> None:
    st.markdown("#### Safety status")
    context_label = st.radio(
        "Execution context",
        options=[ExecutionContext.EXPERIMENT_RUN, ExecutionContext.LOCAL_UNIT_TEST],
        format_func=lambda c: (
            "experiment_run (strict — the same gate a real run uses)"
            if c is ExecutionContext.EXPERIMENT_RUN
            else "local_unit_test (draft-only local demonstration carve-out)"
        ),
        key=f"context_{experiment.experiment_id}",
    )
    if context_label is ExecutionContext.LOCAL_UNIT_TEST:
        st.caption(
            "local_unit_test only relaxes the approval-status check (SAFE-004) for local "
            "demonstration of draft experiments. All other safety rules still apply and "
            "approval status is never changed automatically."
        )

    check = services.check_safety(experiment, execution_context=context_label)
    if check.decision.allowed:
        st.success("Safety Policy: PASSED")
    else:
        st.error("Safety Policy: DENIED")
        for reason in check.decision.reasons:
            st.markdown(f"- {reason}")

    st.markdown("#### Run experiment")
    run_clicked = st.button(
        "Run Experiment", disabled=not check.decision.allowed, key=f"run_{experiment.experiment_id}"
    )
    if run_clicked:
        with st.status("Running experiment pipeline...", expanded=True) as status:
            st.write("1. Loading experiment")
            st.write("2. Safety validation")
            st.write("3. Loading synthetic dataset")
            st.write("4. Running baseline")
            st.write("5. Running mitigation")
            st.write("6. Calculating metrics")
            st.write("7. Generating evidence")
            try:
                summary = services.run_experiment(
                    experiment, execution_context=context_label, results_root=RESULTS_ROOT
                )
            except PolicyRefusalError as exc:
                status.update(label="Refused by safety policy", state="error")
                st.error("Execution was refused before any case was processed:")
                for reason in exc.decision.reasons:
                    st.markdown(f"- {reason}")
            except services.ExperimentServiceError as exc:
                status.update(label="Failed", state="error")
                st.error(str(exc))
            else:
                status.update(label="Complete", state="complete")
                st.success(
                    f"Run complete: {summary.comparison_report.total_cases} cases. "
                    f"Evidence written to `{summary.results_dir}`."
                )


def render_results(comparison: ComparisonReport, case_comparisons: list[services.CaseComparison]) -> None:
    st.markdown(f"**Total test cases:** {comparison.total_cases}")

    breakdown = services.summarise_case_categories(case_comparisons)
    c1, c2, c3 = st.columns(3)
    c1.metric("Valid cases", breakdown.valid_count)
    c2.metric("Malformed cases", breakdown.malformed_count)
    c3.metric("Boundary cases", breakdown.boundary_count)
    if breakdown.malformed_count:
        c1, c2 = st.columns(2)
        c1.metric(
            "Malformed block rate — baseline",
            f"{breakdown.baseline_malformed_block_rate:.0%}"
            if breakdown.baseline_malformed_block_rate is not None
            else "n/a",
        )
        c2.metric(
            "Malformed block rate — mitigation",
            f"{breakdown.mitigation_malformed_block_rate:.0%}"
            if breakdown.mitigation_malformed_block_rate is not None
            else "n/a",
        )

    st.markdown("#### Baseline vs. mitigation")
    table_rows = []
    chart_data: dict[str, dict[str, float]] = {}
    for field, label in METRIC_LABELS:
        baseline_value = getattr(comparison.baseline_metrics, field)
        mitigation_value = getattr(comparison.mitigation_metrics, field)
        table_rows.append(
            {
                "Metric": label,
                "Baseline": baseline_value,
                "Mitigation": mitigation_value,
                "Difference": mitigation_value - baseline_value,
            }
        )
        if field != "mean_latency_ms":
            chart_data[label] = {"Baseline": baseline_value, "Mitigation": mitigation_value}
    st.dataframe(table_rows, hide_index=True, width="stretch")

    st.markdown("#### Rate metrics (baseline vs. mitigation)")
    st.bar_chart(chart_data)

    st.markdown(
        f"**Block-rate improvement:** {comparison.block_rate_improvement:+.1%}  \n"
        f"**Mitigation overhead (mean latency):** {comparison.latency_overhead_ms:+.4f} ms"
    )

    st.markdown("#### Limitations")
    for item in comparison.limitations:
        st.markdown(f"- {item}")


def render_test_cases(case_comparisons: list[services.CaseComparison]) -> None:
    if not case_comparisons:
        st.info("No test cases available.")
        return

    case_ids = sorted(c.case_id for c in case_comparisons)
    selected_id = st.selectbox("Select a test case", case_ids)
    case = next(c for c in case_comparisons if c.case_id == selected_id)

    if case.test_case is not None:
        st.markdown(f"**Input classification:** `{case.test_case.category.value}`")
        st.markdown(f"**Expected outcome:** `{case.test_case.expected_outcome.value}`")
        with st.expander("Raw input data"):
            st.json(case.test_case.input_data)
    else:
        st.info("Original dataset could not be re-located; showing recorded results only.")

    col1, col2 = st.columns(2)
    for col, side_label, result in (
        (col1, "BASELINE", case.baseline),
        (col2, "MITIGATION", case.mitigation),
    ):
        with col:
            st.markdown(f"**{side_label}**")
            st.markdown("Accepted" if result.decision.value == "accepted" else "Rejected/blocked")
            st.markdown(f"Parser reached: `{result.parser_reached}`")
            reason = result.error_message if result.errored else "No processing error was recorded."
            st.markdown(f"Reason: {reason}")
            st.markdown("Processing result:")
            st.json(result.model_dump(mode="json"))


def render_evidence(view: services.EvidenceView) -> None:
    st.markdown(f"**Experiment ID:** {view.experiment_id}")
    st.markdown(f"**Evidence location:** `{view.results_dir}`")
    if view.dataset_note:
        st.info(view.dataset_note)

    for label, manifest in (
        ("Baseline", view.baseline_manifest),
        ("Mitigation", view.mitigation_manifest),
    ):
        st.markdown(f"#### {label} run — `{manifest.run_id}`")
        integrity_ok = verify_manifest_integrity(manifest)
        st.markdown(
            f"Manifest status: {'✅ integrity verified' if integrity_ok else '❌ integrity check FAILED'}"
        )
        col1, col2 = st.columns(2)
        with col1:
            st.markdown(f"Strategy: `{manifest.strategy_id}`")
            st.markdown(f"Started: {manifest.started_at}")
            st.markdown(f"Completed: {manifest.completed_at}")
            st.markdown(f"Review status at run time: `{manifest.review_status.value}`")
        with col2:
            st.markdown(f"Dataset ID: `{manifest.test_set_id}`")
            st.markdown(f"Dataset SHA-256: `{manifest.test_set_sha256}`")
            st.markdown(f"Git commit: `{manifest.git_commit}`")
            st.markdown(f"Manifest SHA-256: `{manifest.manifest_sha256}`")

        run_dir = view.results_dir / manifest.run_id
        artefact_name = st.selectbox(
            f"Inspect a {label.lower()} evidence file",
            sorted(manifest.artefact_paths),
            key=f"artefact_{manifest.run_id}",
        )
        artefact_path = run_dir / manifest.artefact_paths[artefact_name]
        if artefact_path.is_file():
            st.json(artefact_path.read_text(encoding="utf-8"))


def render_overleaf_export(experiment: ExperimentDefinition, comparison: ComparisonReport) -> None:
    st.markdown(
        "Generates a factual, auto-generated CSV/LaTeX export of this run's comparison for "
        "manual researcher review. ZeroShield never writes to or modifies the shared "
        "collaborative Overleaf document directly."
    )
    st.code("ZeroShield → overleaf_exports → researcher review → manual inclusion in VPN/Telecom sections")

    if st.button("Generate Overleaf Export", key=f"export_{experiment.experiment_id}"):
        export_dir = services.generate_overleaf_export(experiment, comparison, OVERLEAF_EXPORT_ROOT)
        st.success(f"Export written to `{export_dir}`")
        for filename in ("comparison.csv", "metrics.tex", "factual_summary.tex"):
            path = export_dir / filename
            if path.is_file():
                with st.expander(filename):
                    st.code(path.read_text(encoding="utf-8"))


def render_research_pipeline() -> None:
    st.markdown(
        """
- **Excel CVE workbook** — a broad, structured research/intelligence registry of candidate
  zero-click CVEs across VPN and Telecom. Not all rows become experiments.
- **ExperimentDefinition** — a manually reviewed bridge between one CVE-backed research finding
  and a runnable, safety-checked ZeroShield experiment.
- **ZeroShield** — the controlled mitigation-validation engine: it runs the baseline and
  mitigation strategies over the same synthetic dataset and measures the difference.
- **Results / Evidence** — the demonstrated findings of one synthetic experiment run, with a
  reproducible, hashed evidence package.
- **Overleaf** — where results are interpreted and written up as research, by a person, from
  the factual export ZeroShield produces.
        """
    )
    st.info(
        "The Excel workbook is a research registry, not a runtime database: ZeroShield never "
        "automatically executes experiments from arbitrary Excel rows."
    )


def main() -> None:
    st.set_page_config(page_title="ZeroShield Dashboard", page_icon="🛡️", layout="wide")

    st.sidebar.title("🛡️ ZeroShield")
    discovery = services.list_experiments(EXPERIMENTS_DIR)
    if discovery.skipped:
        with st.sidebar.expander(f"{len(discovery.skipped)} file(s) skipped"):
            for item in discovery.skipped:
                st.markdown(f"- `{item.path.name}`: {item.reason}")

    if not discovery.experiments:
        st.error(f"No valid ExperimentDefinition files were found under `{EXPERIMENTS_DIR}`.")
        return

    labels = [f"{e.experiment_id} — {e.title}" for e in discovery.experiments]
    selected_index = st.sidebar.selectbox(
        "Experiment", options=range(len(labels)), format_func=lambda i: labels[i]
    )
    experiment = discovery.experiments[selected_index]

    tabs = st.tabs(
        [
            "Overview",
            "Experiment & Safety",
            "Results",
            "Test Cases",
            "Evidence",
            "Overleaf Export",
            "Research Pipeline",
        ]
    )

    with tabs[0]:
        render_overview()
    with tabs[1]:
        render_experiment_details(experiment)
        st.divider()
        render_safety_and_run(experiment)

    view = services.load_latest_evidence(experiment.experiment_id, RESULTS_ROOT)

    with tabs[2]:
        if view is None:
            st.info("No evidence yet for this experiment. Run it from the Experiment & Safety tab.")
        else:
            render_results(view.comparison, view.case_comparisons)
    with tabs[3]:
        if view is None:
            st.info("No evidence yet for this experiment. Run it from the Experiment & Safety tab.")
        else:
            render_test_cases(view.case_comparisons)
    with tabs[4]:
        if view is None:
            st.info("No evidence yet for this experiment. Run it from the Experiment & Safety tab.")
        else:
            render_evidence(view)
    with tabs[5]:
        if view is None:
            st.info("No evidence yet for this experiment. Run it from the Experiment & Safety tab.")
        else:
            render_overleaf_export(experiment, view.comparison)
    with tabs[6]:
        render_research_pipeline()


main()
