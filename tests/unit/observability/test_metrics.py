from zeroshield.observability import metrics


def _sample_names(metric: object) -> set[str]:
    names: set[str] = set()
    for family in metric.collect():  # type: ignore[attr-defined]
        for sample in family.samples:
            names.add(sample.name)
    return names


def test_api_requests_total_has_expected_labels() -> None:
    metrics.API_REQUESTS_TOTAL.labels(method="GET", path="/health", status_code="200")


def test_api_request_duration_seconds_has_expected_labels() -> None:
    metrics.API_REQUEST_DURATION_SECONDS.labels(method="GET", path="/health")


def test_experiment_runs_submitted_total_has_expected_labels() -> None:
    metrics.EXPERIMENT_RUNS_SUBMITTED_TOTAL.labels(
        experiment_id="ZC-VPN-EXP-001", execution_context="local_unit_test"
    )


def test_worker_jobs_processed_total_has_expected_labels() -> None:
    metrics.WORKER_JOBS_PROCESSED_TOTAL.labels(status="completed")


def test_worker_job_duration_seconds_observable_without_labels() -> None:
    metrics.WORKER_JOB_DURATION_SECONDS.observe(0.001)


def test_metric_names_are_all_zeroshield_prefixed_and_distinct() -> None:
    all_metrics = [
        metrics.API_REQUESTS_TOTAL,
        metrics.API_REQUEST_DURATION_SECONDS,
        metrics.EXPERIMENT_RUNS_SUBMITTED_TOTAL,
        metrics.WORKER_JOBS_PROCESSED_TOTAL,
        metrics.WORKER_JOB_DURATION_SECONDS,
    ]
    base_names = {m._name for m in all_metrics}  # type: ignore[attr-defined]
    assert len(base_names) == len(all_metrics)
    assert all(name.startswith("zeroshield_") for name in base_names)
