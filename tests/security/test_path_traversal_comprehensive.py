"""Comprehensive path-traversal sweep (Milestone 26; SRS S10.3 threat model:
"Path traversal or evidence overwrite - Canonical paths, immutable run
directories, generated IDs and repository boundary"; SRS S11.1 "Security"
test level: "Input validation, path handling").

tests/unit/api/test_experiments.py and tests/unit/api/test_jobs.py already
each check one or two representative traversal attempts against their own
route. This file turns that into an explicit, exhaustive matrix: every
malicious ID in MALICIOUS_IDS, against every id-accepting API route, plus a
canary-file check proving that no matter which malicious ID is sent, nothing
outside the sanctioned results_root/jobs_dir/experiments_dir is ever read
back into a response body.

Not swept here: zeroshield.cli.commands.verify_evidence's run_dir argument.
It is a local operator pointing the CLI at their own filesystem path (like
`cat` or `ls`) - the "attacker" already has the OS-user-level filesystem
access this sweep is trying to rule out, so it is not a trust-boundary
crossing the way an HTTP path parameter is.
"""

from collections.abc import Iterator
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

MALICIOUS_IDS = [
    "../../etc/passwd",
    "..\\..\\windows\\system32",
    "ZC-VPN-EXP-001/../../../secret",
    "ZC-VPN-EXP-001; rm -rf /",
    "....//....//etc/passwd",
    "%2e%2e%2fetc%2fpasswd",
    "..",
    "ZC-VPN-EXP-999999",  # not path traversal, just unknown - must still 404 cleanly
]

# (method, path_template) for every route whose id path parameter is
# resolved against the filesystem - see zeroshield.api.dependencies.get_experiment
# and zeroshield.api.routes.jobs.get_job.
EXPERIMENT_ID_ROUTES: list[tuple[str, str]] = [
    ("GET", "/experiments/{id}"),
    ("GET", "/experiments/{id}/results"),
    ("GET", "/experiments/{id}/evidence"),
]


@pytest.fixture
def canary_file(tmp_path: Path) -> Iterator[str]:
    """A secret marker placed outside every sanctioned directory this API is
    allowed to read from (results_root/jobs_dir are subdirectories of
    tmp_path; this file is a sibling, one level up). If any response body
    ever contains this marker, a traversal attempt escaped its boundary."""
    marker = "ZEROSHIELD-CANARY-3f9c2a7b-do-not-leak"
    secret = tmp_path.parent / f"path-traversal-canary-{tmp_path.name}.txt"
    secret.write_text(marker, encoding="utf-8")
    try:
        yield marker
    finally:
        secret.unlink(missing_ok=True)


@pytest.mark.parametrize("malicious_id", MALICIOUS_IDS)
@pytest.mark.parametrize("method,path_template", EXPERIMENT_ID_ROUTES)
def test_experiment_id_routes_reject_malicious_ids_without_leaking(
    method: str,
    path_template: str,
    malicious_id: str,
    client: TestClient,
    canary_file: str,
) -> None:
    path = path_template.format(id=malicious_id)
    response = client.request(method, path)

    # never a server crash: either routed-and-rejected (404) or not routed at
    # all (also 404, since these are single-segment path params with no
    # matching alternate route) - never a 500, never a 200 for a nonexistent
    # or out-of-bounds resource.
    assert response.status_code == 404
    assert canary_file not in response.text
    assert "root:" not in response.text


@pytest.mark.parametrize("malicious_id", MALICIOUS_IDS)
def test_validate_route_rejects_malicious_experiment_id_without_leaking(
    malicious_id: str, client: TestClient, canary_file: str
) -> None:
    response = client.post(
        f"/experiments/{malicious_id}/validate", json={"execution_context": "local_unit_test"}
    )
    assert response.status_code == 404
    assert canary_file not in response.text


@pytest.mark.parametrize("malicious_id", MALICIOUS_IDS)
def test_runs_route_rejects_malicious_experiment_id_without_leaking(
    malicious_id: str, client: TestClient, canary_file: str
) -> None:
    response = client.post(
        f"/experiments/{malicious_id}/runs", json={"execution_context": "local_unit_test"}
    )
    assert response.status_code == 404
    assert canary_file not in response.text


@pytest.mark.parametrize("malicious_id", MALICIOUS_IDS)
def test_jobs_route_rejects_malicious_job_id_without_leaking(
    malicious_id: str, client: TestClient, canary_file: str
) -> None:
    response = client.get(f"/jobs/{malicious_id}")
    # job_id is constrained by a regex Path(pattern=...) (422) as well as by
    # JobStore simply having no matching file (404 if it somehow slipped
    # through) - either is an acceptable rejection, a 200/500 is not.
    assert response.status_code in (404, 422)
    assert canary_file not in response.text


def test_malicious_ids_never_appear_in_any_directory_created_under_results_root(
    client: TestClient, results_root: Path, canary_file: str
) -> None:
    """Belt-and-braces: after the whole sweep above, results_root must contain
    no directory or file whose name reflects an attacker-controlled id - every
    write, if any ever happened, would have to be under a real, discovered
    experiment_id."""
    for malicious_id in MALICIOUS_IDS:
        client.get(f"/experiments/{malicious_id}/results")
        client.post(
            f"/experiments/{malicious_id}/runs", json={"execution_context": "local_unit_test"}
        )
    if results_root.exists():
        written = {p.name for p in results_root.iterdir()}
        assert written <= {"ZC-VPN-EXP-001", "ZC-TELECOM-EXP-001"}
