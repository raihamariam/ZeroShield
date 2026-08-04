from pathlib import Path

from zeroshield.datasets import load_test_set
from zeroshield.models import Decision, TestCaseCategory
from zeroshield.strategies.vpn import WeakSchemaLengthBaseline

REPO_ROOT = Path(__file__).resolve().parents[4]
DATASET_PATH = REPO_ROOT / "test_data" / "vpn" / "vpn_pre_auth_request_dataset.json"


def test_strategy_id_matches_experiment_declaration() -> None:
    assert WeakSchemaLengthBaseline.strategy_id == "weak_schema_length_baseline"


def test_accepts_well_formed_request() -> None:
    strategy = WeakSchemaLengthBaseline()
    outcome = strategy.process({"method": "GET", "path": "/remote/login"})
    assert outcome.decision == Decision.ACCEPTED
    assert outcome.parser_reached is True


def test_blocks_missing_method() -> None:
    strategy = WeakSchemaLengthBaseline()
    outcome = strategy.process({"path": "/remote/login"})
    assert outcome.decision == Decision.BLOCKED
    assert outcome.parser_reached is False


def test_blocks_missing_path() -> None:
    strategy = WeakSchemaLengthBaseline()
    outcome = strategy.process({"method": "GET"})
    assert outcome.decision == Decision.BLOCKED
    assert outcome.parser_reached is False


def test_blocks_non_string_method() -> None:
    strategy = WeakSchemaLengthBaseline()
    outcome = strategy.process({"method": 123, "path": "/remote/login"})
    assert outcome.decision == Decision.BLOCKED


def test_blocks_empty_string_path() -> None:
    strategy = WeakSchemaLengthBaseline()
    outcome = strategy.process({"method": "GET", "path": ""})
    assert outcome.decision == Decision.BLOCKED


def test_accepts_oversized_declared_content_length() -> None:
    strategy = WeakSchemaLengthBaseline()
    outcome = strategy.process(
        {"method": "POST", "path": "/remote/login", "declared_content_length": 5000000}
    )
    assert outcome.decision == Decision.ACCEPTED


def test_accepts_mismatched_declared_and_actual_length() -> None:
    strategy = WeakSchemaLengthBaseline()
    outcome = strategy.process(
        {
            "method": "POST",
            "path": "/remote/login",
            "declared_content_length": 42,
            "actual_body_length": 4096,
        }
    )
    assert outcome.decision == Decision.ACCEPTED


def test_accepts_path_traversal_sequence() -> None:
    strategy = WeakSchemaLengthBaseline()
    outcome = strategy.process({"method": "GET", "path": "/remote/../../internal/x"})
    assert outcome.decision == Decision.ACCEPTED


def test_weak_baseline_accepts_all_valid_cases_in_real_dataset() -> None:
    test_set, _ = load_test_set(DATASET_PATH)
    strategy = WeakSchemaLengthBaseline()
    valid_cases = [c for c in test_set.cases if c.category == TestCaseCategory.VALID]
    outcomes = [strategy.process(c.input_data) for c in valid_cases]
    assert all(o.decision == Decision.ACCEPTED for o in outcomes)


def test_weak_baseline_fails_to_block_any_malformed_case_in_real_dataset() -> None:
    test_set, _ = load_test_set(DATASET_PATH)
    strategy = WeakSchemaLengthBaseline()
    malformed_cases = [c for c in test_set.cases if c.category == TestCaseCategory.MALFORMED]
    outcomes = [strategy.process(c.input_data) for c in malformed_cases]

    block_rate = sum(o.decision == Decision.BLOCKED for o in outcomes) / len(outcomes)
    assert block_rate == 0.0
    assert all(o.parser_reached for o in outcomes)
