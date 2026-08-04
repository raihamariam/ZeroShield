"""Dependency vulnerability scan (Milestone 26; SRS S11.1 "Security" test
level: "... dependency scan and egress control"). Runs the real `pip-audit`
CLI against this project's installed environment and fails if it reports any
known vulnerability for a dependency actually in use.

pip-audit queries an online advisory database (OSV/PyPI), so unlike every
other test in this project it depends on outbound network access. If it
cannot complete a real scan (network unavailable, registry unreachable), the
test is skipped rather than failed - the absence of a network is not
evidence of a vulnerability, and this must never be silently treated as "no
vulnerabilities found".
"""

import json
import subprocess
import sys

import pytest

_TIMEOUT_SECONDS = 120


def _run_pip_audit() -> dict:
    result = subprocess.run(
        [sys.executable, "-m", "pip_audit", "--format", "json", "--progress-spinner", "off"],
        capture_output=True,
        text=True,
        timeout=_TIMEOUT_SECONDS,
        check=False,
    )
    try:
        return json.loads(result.stdout)
    except json.JSONDecodeError:
        pytest.skip(
            "pip-audit did not return valid JSON (likely no network access to the "
            f"advisory database); stderr: {result.stderr.strip()[:500]}"
        )


def test_installed_dependencies_have_no_known_vulnerabilities() -> None:
    try:
        report = _run_pip_audit()
    except FileNotFoundError:
        pytest.skip("pip-audit is not installed (install the 'dev' extra)")
    except subprocess.TimeoutExpired:
        pytest.skip(f"pip-audit did not complete within {_TIMEOUT_SECONDS}s (likely no network)")

    vulnerable = [
        {"name": dep["name"], "version": dep.get("version"), "vulns": dep["vulns"]}
        for dep in report["dependencies"]
        if dep.get("vulns")
    ]
    assert vulnerable == [], f"pip-audit found known vulnerabilities: {vulnerable}"
