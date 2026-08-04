"""GET /metrics and the PrometheusMiddleware. Uses relative before/after counter
comparisons rather than absolute values, since prometheus_client's default
registry is process-global and shared across the whole test session.
"""

from fastapi.testclient import TestClient

from zeroshield.observability.metrics import API_REQUESTS_TOTAL, EXPERIMENT_RUNS_SUBMITTED_TOTAL


def _counter_value(counter: object, **labels: str) -> float:
    """Reads one label combination's current value via the public collect() API.

    A labelled child's own collect() returns its samples with an EMPTY labels
    dict (the label values aren't echoed back onto the child's samples) - only
    its value is meaningful, so this takes the "_total" sample by name, not by
    matching labels.
    """
    labelled = counter.labels(**labels)  # type: ignore[attr-defined]
    for family in labelled.collect():
        for sample in family.samples:
            if sample.name.endswith("_total"):
                return sample.value
    return 0.0


def test_metrics_endpoint_returns_prometheus_text_format(client: TestClient) -> None:
    response = client.get("/metrics")
    assert response.status_code == 200
    assert "text/plain" in response.headers["content-type"]
    assert "zeroshield_api_requests_total" in response.text
    assert "zeroshield_worker_jobs_processed_total" in response.text


def test_health_request_increments_requests_total_for_its_own_route(client: TestClient) -> None:
    before = _counter_value(API_REQUESTS_TOTAL, method="GET", path="/health", status_code="200")
    client.get("/health")
    after = _counter_value(API_REQUESTS_TOTAL, method="GET", path="/health", status_code="200")
    assert after == before + 1


def test_parameterised_route_is_labelled_by_template_not_raw_path(client: TestClient) -> None:
    """Two different experiment_id values must aggregate under the SAME label -
    using the raw resolved path instead would cause unbounded label cardinality."""
    label = {"method": "GET", "path": "/experiments/{experiment_id}", "status_code": "200"}
    before = _counter_value(API_REQUESTS_TOTAL, **label)

    client.get("/experiments/ZC-VPN-EXP-001")
    client.get("/experiments/ZC-TELECOM-EXP-001")

    after = _counter_value(API_REQUESTS_TOTAL, **label)
    assert after == before + 2


def test_unmatched_path_is_grouped_under_a_fixed_label(client: TestClient) -> None:
    label = {"method": "GET", "path": "unmatched", "status_code": "404"}
    before = _counter_value(API_REQUESTS_TOTAL, **label)

    client.get("/this/path/does/not/exist/at/all")
    client.get("/another/nonexistent/path")

    after = _counter_value(API_REQUESTS_TOTAL, **label)
    assert after == before + 2


def test_submit_run_increments_experiment_runs_submitted_total(client: TestClient) -> None:
    label = {"experiment_id": "ZC-VPN-EXP-001", "execution_context": "local_unit_test"}
    before = _counter_value(EXPERIMENT_RUNS_SUBMITTED_TOTAL, **label)

    response = client.post(
        "/experiments/ZC-VPN-EXP-001/runs", json={"execution_context": "local_unit_test"}
    )
    assert response.status_code == 202

    after = _counter_value(EXPERIMENT_RUNS_SUBMITTED_TOTAL, **label)
    assert after == before + 1


def test_unknown_experiment_run_does_not_increment_submitted_total(client: TestClient) -> None:
    label = {"experiment_id": "ZC-VPN-EXP-999999", "execution_context": "local_unit_test"}
    before = _counter_value(EXPERIMENT_RUNS_SUBMITTED_TOTAL, **label)

    response = client.post(
        "/experiments/ZC-VPN-EXP-999999/runs", json={"execution_context": "local_unit_test"}
    )
    assert response.status_code == 404

    after = _counter_value(EXPERIMENT_RUNS_SUBMITTED_TOTAL, **label)
    assert after == before
