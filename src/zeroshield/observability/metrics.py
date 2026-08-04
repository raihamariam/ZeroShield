"""Operational Prometheus metrics for the API and worker: request counts,
job outcomes, processing durations.

Per SRS S14: "Prometheus - Optional metrics - Time-series operational and
experiment counters; raw scientific evidence remains separately stored" and
"Grafana ... must not replace raw data and reports." These counters are
NEVER a substitute for the scientific research metrics in zeroshield.metrics
(block_rate, valid_acceptance_rate, etc.) or for the evidence manifests -
they describe how the *system* is behaving (request volume, job success/
failure/denial counts, latency), not the experiment's findings. Nothing
here is read by, or written into, an EvidenceManifest or ComparisonReport.

Uses prometheus_client's default global registry (the standard, idiomatic
usage pattern) - not injected/isolated, since these are simple, low-risk,
side-effect-free counters, not something callers need to swap out.
"""

from prometheus_client import Counter, Histogram

API_REQUESTS_TOTAL = Counter(
    "zeroshield_api_requests_total",
    "Total HTTP requests handled by the ZeroShield API",
    ["method", "path", "status_code"],
)

API_REQUEST_DURATION_SECONDS = Histogram(
    "zeroshield_api_request_duration_seconds",
    "ZeroShield API HTTP request duration in seconds",
    ["method", "path"],
)

EXPERIMENT_RUNS_SUBMITTED_TOTAL = Counter(
    "zeroshield_experiment_runs_submitted_total",
    "Total experiment run jobs submitted via POST /experiments/{id}/runs",
    ["experiment_id", "execution_context"],
)

WORKER_JOBS_PROCESSED_TOTAL = Counter(
    "zeroshield_worker_jobs_processed_total",
    "Total run jobs processed by the worker, by terminal status",
    ["status"],
)

WORKER_JOB_DURATION_SECONDS = Histogram(
    "zeroshield_worker_job_duration_seconds",
    "Time from a job being picked up by the worker to reaching a terminal state",
)
