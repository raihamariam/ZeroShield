"""Genuine end-to-end proof that the installed entry points work from a real shell,
not just via in-process calls to main()."""

import os
import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[3]


def test_python_dash_m_zeroshield_help_works() -> None:
    result = subprocess.run(
        [sys.executable, "-m", "zeroshield", "--help"],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
    )
    assert result.returncode == 0
    assert "validate-experiment" in result.stdout


def test_installed_zeroshield_console_script_help_works() -> None:
    scripts_dir = Path(sys.executable).parent
    script = scripts_dir / ("zeroshield.exe" if os.name == "nt" else "zeroshield")
    assert script.is_file(), f"console script not found at {script}; run `pip install -e .` first"

    result = subprocess.run(
        [str(script), "--help"], cwd=REPO_ROOT, capture_output=True, text=True, timeout=30, check=False
    )
    assert result.returncode == 0
    assert "validate-experiment" in result.stdout
