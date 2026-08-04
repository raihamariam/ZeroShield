"""End-to-end dashboard workflow via Streamlit's real AppTest rendering: select
experiment -> check safety -> run -> Results -> Test Cases -> Evidence ->
Overleaf Export. Extends the lighter smoke test in tests/unit/dashboard/
test_app_smoke.py (which only confirms a run completes) to touch every tab
with real, persisted evidence - proving the full user-facing workflow works,
not just that individual pieces are wired correctly.

Happy path only: denial/failure-path scenarios are Milestone 26's scope.
"""

from pathlib import Path

from streamlit.testing.v1 import AppTest

REPO_ROOT = Path(__file__).resolve().parents[2]
APP_PATH = REPO_ROOT / "src" / "zeroshield" / "dashboard" / "app.py"

# app.py resolves results/experiments from Path.cwd() (the documented "launch from
# the repository root" convention); pytest is always run from the repository root
# in this project. Like the existing smoke test, this writes real evidence to the
# real results/ directory - it is gitignored, regenerable output, same as every
# other real dashboard/CLI/API run performed throughout this project's milestones.


def test_full_dashboard_workflow_vpn() -> None:
    at = AppTest.from_file(str(APP_PATH))
    at.run(timeout=30)

    labels = at.sidebar.selectbox[0].options
    vpn_index = next(i for i, label in enumerate(labels) if label.startswith("ZC-VPN-EXP-001"))
    at.sidebar.selectbox[0].set_value(vpn_index).run(timeout=30)

    radio = at.tabs[1].radio[0]
    at.tabs[1].radio[0].set_value(radio.options[1]).run(timeout=30)  # local_unit_test

    at.button(key="run_ZC-VPN-EXP-001").click().run(timeout=30)
    assert not at.exception
    success_messages = " ".join(m.value for m in at.tabs[1].success)
    assert "Run complete: 22 cases" in success_messages

    # Results tab
    results_markdown = " ".join(m.value for m in at.tabs[2].markdown)
    assert "Total test cases:" in results_markdown
    assert "Limitations" in results_markdown
    assert len(at.tabs[2].dataframe) >= 1
    metric_labels = [m.label for m in at.tabs[2].metric]
    assert "Valid cases" in metric_labels
    assert "Malformed cases" in metric_labels
    assert "Boundary cases" in metric_labels

    # Test Cases tab
    assert len(at.tabs[3].selectbox) == 1
    case_ids = at.tabs[3].selectbox[0].options
    assert len(case_ids) == 22
    test_case_markdown = " ".join(m.value for m in at.tabs[3].markdown)
    assert "Input classification" in test_case_markdown
    assert "BASELINE" in test_case_markdown
    assert "MITIGATION" in test_case_markdown

    # Evidence tab
    evidence_markdown = " ".join(m.value for m in at.tabs[4].markdown)
    assert "Experiment ID:" in evidence_markdown
    assert "Evidence location:" in evidence_markdown
    assert "integrity verified" in evidence_markdown
    assert len(at.tabs[4].selectbox) == 2  # baseline + mitigation artefact inspectors

    # Overleaf Export tab: a separate widget interaction (Streamlit processes one
    # click per run), the run/context selections above persist via their widget keys
    at.button(key="export_ZC-VPN-EXP-001").click().run(timeout=30)
    assert not at.exception
    export_success = " ".join(m.value for m in at.tabs[5].success)
    assert "Export written to" in export_success

    export_dir = REPO_ROOT / "overleaf_exports" / "ZC-VPN-EXP-001"
    assert (export_dir / "comparison.csv").is_file()
    assert (export_dir / "metrics.tex").is_file()
    assert (export_dir / "factual_summary.tex").is_file()


def test_full_dashboard_workflow_telecom() -> None:
    at = AppTest.from_file(str(APP_PATH))
    at.run(timeout=30)

    labels = at.sidebar.selectbox[0].options
    telecom_index = next(i for i, label in enumerate(labels) if label.startswith("ZC-TELECOM-EXP-001"))
    at.sidebar.selectbox[0].set_value(telecom_index).run(timeout=30)

    radio = at.tabs[1].radio[0]
    at.tabs[1].radio[0].set_value(radio.options[1]).run(timeout=30)  # local_unit_test

    at.button(key="run_ZC-TELECOM-EXP-001").click().run(timeout=30)
    assert not at.exception
    success_messages = " ".join(m.value for m in at.tabs[1].success)
    assert "Run complete: 25 cases" in success_messages

    assert len(at.tabs[3].selectbox[0].options) == 25

    at.button(key="export_ZC-TELECOM-EXP-001").click().run(timeout=30)
    assert not at.exception
    export_dir = REPO_ROOT / "overleaf_exports" / "ZC-TELECOM-EXP-001"
    assert (export_dir / "comparison.csv").is_file()
