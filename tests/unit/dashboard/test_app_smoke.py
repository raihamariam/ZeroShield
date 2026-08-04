"""Light smoke tests for the Streamlit app's wiring, using Streamlit's own headless
AppTest framework. Deliberately not exhaustive - the real logic is tested against
zeroshield.dashboard.services directly in test_services.py; these tests only guard
against UI-wiring mistakes (wrong widget key, wrong field name, etc.)."""

from pathlib import Path

from streamlit.testing.v1 import AppTest

REPO_ROOT = Path(__file__).resolve().parents[3]
APP_PATH = REPO_ROOT / "src" / "zeroshield" / "dashboard" / "app.py"

# app.py resolves its data directories from Path.cwd(), matching the documented
# "launch from the repository root" convention; pytest is likewise always run from
# the repository root in this project, so no chdir is needed here.


def test_app_boots_with_no_exceptions() -> None:
    at = AppTest.from_file(str(APP_PATH))
    at.run(timeout=30)
    assert not at.exception


def test_vpn_run_through_dashboard_completes_with_no_exceptions() -> None:
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
