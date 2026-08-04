"""Queue message robustness (Milestone 26 fix, SRS S10.3 threat model: "Queue
job tampering - Signed/validated payloads, least-privilege broker permissions
and idempotency"). Before this milestone, a single malformed message would
crash worker.main's consume loop entirely and, since it would remain unacked,
be redelivered - crashing the worker again forever on reconnect. This proves
handle_message_body() never raises, for a range of malformed/adversarial
message bodies, and that a genuinely valid message still processes correctly.
"""

import json
from pathlib import Path

import pytest

from zeroshield.policies import ExecutionContext
from zeroshield.services.job_store import JobStatus, JobStore
from zeroshield.worker.main import handle_message_body

REPO_ROOT = Path(__file__).resolve().parents[2]
EXPERIMENTS_DIR = REPO_ROOT / "experiments"

MALFORMED_BODIES: list[bytes] = [
    b"",
    b"not json at all",
    b"{",
    b"null",
    b"[]",
    b'{"job_id": "JOB-1"}',  # missing required fields
    b'{"job_id": "JOB-1", "experiment_id": "ZC-VPN-EXP-001", "execution_context": "not_a_real_context"}',
    b'{"job_id": "JOB-1", "experiment_id": "ZC-VPN-EXP-001", "execution_context": "local_unit_test", "extra": "field"}',
    b'{"job_id": "JOB-\x00injected", "experiment_id": "ZC-VPN-EXP-001", "execution_context": "local_unit_test"}',
    b"\xff\xfe\x00\x00garbage-binary-not-utf8",
    (b'{"job_id": "JOB-huge", "experiment_id": "' + b"A" * 100_000 + b'", "execution_context": "local_unit_test"}'),
]

MALFORMED_BODY_IDS = [
    "empty",
    "not-json",
    "truncated-json",
    "json-null",
    "json-empty-list",
    "missing-required-fields",
    "invalid-execution-context",
    "extra-field",
    "embedded-nul-byte",
    "binary-garbage",
    "oversized-payload",
]


@pytest.mark.parametrize("body", MALFORMED_BODIES, ids=MALFORMED_BODY_IDS)
def test_handle_message_body_never_raises_for_malformed_input(body: bytes, tmp_path: Path) -> None:
    job_store = JobStore(tmp_path / "jobs")
    # the only assertion that matters: this must not raise - a real caller (the
    # pika consume loop) always acks right after this call precisely because it
    # is guaranteed not to throw
    handle_message_body(
        body,
        experiments_dir=EXPERIMENTS_DIR,
        results_root=tmp_path / "results",
        job_store=job_store,
    )


def test_handle_message_body_does_not_write_a_job_record_for_a_malformed_message(
    tmp_path: Path,
) -> None:
    """A message that never parses into a RunJobMessage has no job_id to record
    against - it is dropped, not silently turned into a phantom job."""
    jobs_dir = tmp_path / "jobs"
    job_store = JobStore(jobs_dir)
    handle_message_body(
        b"not json", experiments_dir=EXPERIMENTS_DIR, results_root=tmp_path / "results", job_store=job_store
    )
    assert list(jobs_dir.glob("*.json")) == [] if jobs_dir.exists() else True


def test_handle_message_body_processes_a_genuinely_valid_message(tmp_path: Path) -> None:
    """Confirms the robustness change didn't break the real, happy-path message flow."""
    job_store = JobStore(tmp_path / "jobs")
    results_root = tmp_path / "results"
    body = json.dumps(
        {
            "job_id": "JOB-robustness-check",
            "experiment_id": "ZC-VPN-EXP-001",
            "execution_context": ExecutionContext.LOCAL_UNIT_TEST.value,
        }
    ).encode("utf-8")

    handle_message_body(
        body, experiments_dir=EXPERIMENTS_DIR, results_root=results_root, job_store=job_store
    )

    record = job_store.load("JOB-robustness-check")
    assert record is not None
    assert record.status == JobStatus.COMPLETED
    assert record.result is not None
    assert record.result.total_cases == 22
