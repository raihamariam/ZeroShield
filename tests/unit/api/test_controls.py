"""Tests /controls routes (V2 Phase 5, Steps 8/9/10) against a real
in-memory-SQLite-backed AssuranceRepository - no live Postgres. Closes the
HTTP-level test gap flagged in the Phase 5 audit, and specifically
regression-tests the version-comparability fix: regression detection must
never compare two ControlValidations from different control versions
(Step 9's "never blend incompatible validations" applies to Step 10 too).
"""

from collections.abc import Iterator
from datetime import UTC, datetime, timedelta

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool
from tests.unit.api.conftest import fake_user

from zeroshield.ai.null_provider import NullAIProvider
from zeroshield.ai.provider import AIGenerationRequest, AIGenerationResult, AIProvider
from zeroshield.ai.research_analyst_service import ResearchAnalystService
from zeroshield.api import dependencies
from zeroshield.api.app import app
from zeroshield.assurance.models import ControlValidation
from zeroshield.assurance.repository import AssuranceRepository
from zeroshield.db.base import Base

NOW = datetime.now(UTC)


class FakeAIProvider(AIProvider):
    def __init__(self, data: dict | None = None) -> None:
        self._data = data

    def is_configured(self) -> bool:
        return True

    def generate_structured(self, request: AIGenerationRequest) -> AIGenerationResult:
        assert self._data is not None
        return AIGenerationResult(data=self._data, provider="fake", model="fake-model-1")


@pytest.fixture
def assurance_repo() -> AssuranceRepository:
    engine = create_engine(
        "sqlite:///:memory:", connect_args={"check_same_thread": False}, poolclass=StaticPool, future=True
    )
    Base.metadata.create_all(engine)
    return AssuranceRepository(sessionmaker(bind=engine, expire_on_commit=False, future=True))


@pytest.fixture
def client(assurance_repo: AssuranceRepository) -> Iterator[TestClient]:
    app.dependency_overrides[dependencies.get_assurance_repository] = lambda: assurance_repo
    app.dependency_overrides[dependencies.get_research_analyst_service] = lambda: ResearchAnalystService(
        NullAIProvider()
    )
    app.dependency_overrides[dependencies.get_current_user] = lambda: fake_user()
    with TestClient(app, raise_server_exceptions=False) as test_client:
        yield test_client
    app.dependency_overrides.clear()


def _validation(control_id: str, version_id: str, **overrides: object) -> ControlValidation:
    base = {
        "validation_id": f"VAL-{overrides.get('validation_id', 'x')}", "control_id": control_id,
        "version_id": version_id, "experiment_id": "ZC-VPN-EXP-001", "baseline_run_id": "RUN-1",
        "mitigation_run_id": "RUN-2", "total_cases": 10, "block_rate_improvement": 0.6,
        "false_positive_rate": 0.01, "false_negative_rate": 0.01, "valid_acceptance_rate": 0.99,
        "parser_reach_rate": 0.05, "latency_overhead_ms": 1.0, "verdict_label": "effective", "validated_at": NOW,
    }
    base.update(overrides)
    return ControlValidation(**base)


def test_get_unknown_control_is_404(client: TestClient) -> None:
    assert client.get("/controls/does-not-exist").status_code == 404


def test_effectiveness_with_no_validations_is_404(client: TestClient, assurance_repo: AssuranceRepository) -> None:
    control = assurance_repo.get_or_create_control(domain="VPN", mitigation_strategy_id="m", name="X")
    response = client.get(f"/controls/{control.control_id}/effectiveness")
    assert response.status_code == 404


def test_effectiveness_reports_comparability_note_and_trend(
    client: TestClient, assurance_repo: AssuranceRepository
) -> None:
    control = assurance_repo.get_or_create_control(domain="VPN", mitigation_strategy_id="m", name="X")
    version = assurance_repo.get_or_create_control_version(
        control_id=control.control_id, version_label="1.0.0", domain_pack_id="vpn",
        template_id="t", template_version="1.0.0",
    )
    assurance_repo.record_validation(_validation(control.control_id, version.version_id, validation_id="1", validated_at=NOW - timedelta(days=1)))
    assurance_repo.record_validation(_validation(control.control_id, version.version_id, validation_id="2", validated_at=NOW))

    response = client.get(f"/controls/{control.control_id}/effectiveness")
    assert response.status_code == 200
    body = response.json()
    assert body["validation_count_current_version"] == 2
    assert "never" in body["comparability_note"].lower()
    assert len(body["trend"]) == 2


def test_regression_never_compares_across_control_versions(
    client: TestClient, assurance_repo: AssuranceRepository
) -> None:
    """Regression test for the version-comparability bug: a control-version
    bump combined with a worse verdict on the new version must NOT be
    reported as a regression, because the two validations measure different
    things (different template/domain_pack/version), not the same control
    degrading over time."""
    control = assurance_repo.get_or_create_control(domain="VPN", mitigation_strategy_id="m", name="X")
    v1 = assurance_repo.get_or_create_control_version(
        control_id=control.control_id, version_label="1.0.0", domain_pack_id="vpn",
        template_id="t", template_version="1.0.0",
    )
    v2 = assurance_repo.get_or_create_control_version(
        control_id=control.control_id, version_label="2.0.0", domain_pack_id="vpn",
        template_id="t", template_version="2.0.0",
    )
    assurance_repo.record_validation(
        _validation(control.control_id, v1.version_id, validation_id="1", verdict_label="effective", validated_at=NOW - timedelta(days=10))
    )
    # v2 is a brand-new version's *first* validation, with a worse verdict than v1's -
    # this must never be flagged as a regression of v1.
    assurance_repo.record_validation(
        _validation(control.control_id, v2.version_id, validation_id="2", verdict_label="ineffective", validated_at=NOW)
    )

    response = client.get(f"/controls/{control.control_id}/effectiveness")
    assert response.status_code == 200
    assert response.json()["regression"] is None


def test_regression_detected_within_the_same_control_version(
    client: TestClient, assurance_repo: AssuranceRepository
) -> None:
    control = assurance_repo.get_or_create_control(domain="VPN", mitigation_strategy_id="m", name="X")
    version = assurance_repo.get_or_create_control_version(
        control_id=control.control_id, version_label="1.0.0", domain_pack_id="vpn",
        template_id="t", template_version="1.0.0",
    )
    assurance_repo.record_validation(
        _validation(control.control_id, version.version_id, validation_id="1", verdict_label="effective", validated_at=NOW - timedelta(days=1))
    )
    assurance_repo.record_validation(
        _validation(control.control_id, version.version_id, validation_id="2", verdict_label="ineffective", validated_at=NOW)
    )

    response = client.get(f"/controls/{control.control_id}/effectiveness")
    assert response.status_code == 200
    regression = response.json()["regression"]
    assert regression is not None
    assert regression["is_regression"] is True
    assert any("Verdict deteriorated" in r for r in regression["reasons"])


def test_explain_regression_is_404_when_not_regressed(client: TestClient, assurance_repo: AssuranceRepository) -> None:
    control = assurance_repo.get_or_create_control(domain="VPN", mitigation_strategy_id="m", name="X")
    version = assurance_repo.get_or_create_control_version(
        control_id=control.control_id, version_label="1.0.0", domain_pack_id="vpn", template_id="t", template_version="1.0.0"
    )
    assurance_repo.record_validation(_validation(control.control_id, version.version_id, validation_id="1"))
    response = client.post(f"/controls/{control.control_id}/regression/explain")
    assert response.status_code == 404
    assert response.json()["detail"]["error"] == "no_regression"


def test_explain_regression_calls_ai_only_after_a_real_regression_is_detected(
    assurance_repo: AssuranceRepository,
) -> None:
    """The AI is never asked to decide whether a regression occurred - it is only
    invoked once detect_regressions() has already found one, and only narrates the
    deterministic reasons it is handed (Step 10)."""
    control = assurance_repo.get_or_create_control(domain="VPN", mitigation_strategy_id="m", name="X")
    version = assurance_repo.get_or_create_control_version(
        control_id=control.control_id, version_label="1.0.0", domain_pack_id="vpn", template_id="t", template_version="1.0.0"
    )
    assurance_repo.record_validation(
        _validation(control.control_id, version.version_id, validation_id="1", verdict_label="effective", validated_at=NOW - timedelta(days=1))
    )
    assurance_repo.record_validation(
        _validation(control.control_id, version.version_id, validation_id="2", verdict_label="ineffective", validated_at=NOW)
    )

    provider = FakeAIProvider(
        data={"confidence": 0.7, "rationale": "verdict worsened", "source_ids": [], "control_id": control.control_id, "explanation": "The control's verdict got worse."}
    )
    app.dependency_overrides[dependencies.get_assurance_repository] = lambda: assurance_repo
    app.dependency_overrides[dependencies.get_research_analyst_service] = lambda: ResearchAnalystService(provider)
    app.dependency_overrides[dependencies.get_current_user] = lambda: fake_user()
    try:
        with TestClient(app, raise_server_exceptions=False) as test_client:
            response = test_client.post(f"/controls/{control.control_id}/regression/explain")
    finally:
        app.dependency_overrides.clear()

    assert response.status_code == 201
    body = response.json()
    assert body["assessment_type"] == "regression_explanation"
    assert body["subject_type"] == "control"
    assert body["subject_id"] == control.control_id
    assert body["reviewed"] is False


def test_explain_regression_is_503_when_ai_disabled(client: TestClient, assurance_repo: AssuranceRepository) -> None:
    control = assurance_repo.get_or_create_control(domain="VPN", mitigation_strategy_id="m", name="X")
    version = assurance_repo.get_or_create_control_version(
        control_id=control.control_id, version_label="1.0.0", domain_pack_id="vpn", template_id="t", template_version="1.0.0"
    )
    assurance_repo.record_validation(
        _validation(control.control_id, version.version_id, validation_id="1", verdict_label="effective", validated_at=NOW - timedelta(days=1))
    )
    assurance_repo.record_validation(
        _validation(control.control_id, version.version_id, validation_id="2", verdict_label="ineffective", validated_at=NOW)
    )
    response = client.post(f"/controls/{control.control_id}/regression/explain")
    assert response.status_code == 503
    assert response.json()["detail"]["error"] == "ai_unavailable"


def test_list_control_versions(client: TestClient, assurance_repo: AssuranceRepository) -> None:
    control = assurance_repo.get_or_create_control(domain="VPN", mitigation_strategy_id="m", name="X")
    assurance_repo.get_or_create_control_version(
        control_id=control.control_id, version_label="1.0.0", domain_pack_id="vpn", template_id="t", template_version="1.0.0"
    )
    response = client.get(f"/controls/{control.control_id}/versions")
    assert response.status_code == 200
    assert len(response.json()["versions"]) == 1
