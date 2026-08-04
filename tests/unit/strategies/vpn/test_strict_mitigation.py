from pathlib import Path

from zeroshield.datasets import load_test_set
from zeroshield.models import Decision, TestCaseCategory
from zeroshield.strategies.vpn import (
    StrictSchemaCanonicalisationMitigation,
    WeakSchemaLengthBaseline,
)

REPO_ROOT = Path(__file__).resolve().parents[4]
DATASET_PATH = REPO_ROOT / "test_data" / "vpn" / "vpn_pre_auth_request_dataset.json"

VALID_REQUEST = {
    "method": "GET",
    "path": "/remote/login",
    "headers": [["Host", "vpn.example.local"]],
    "declared_content_length": 0,
    "actual_body_length": 0,
    "encoding": "utf-8",
}


def test_strategy_id_matches_experiment_declaration() -> None:
    assert (
        StrictSchemaCanonicalisationMitigation.strategy_id
        == "strict_schema_canonicalisation_mitigation"
    )


def test_accepts_well_formed_request() -> None:
    strategy = StrictSchemaCanonicalisationMitigation()
    outcome = strategy.process(VALID_REQUEST)
    assert outcome.decision == Decision.ACCEPTED
    assert outcome.parser_reached is True
    assert outcome.logged is False


def test_blocks_missing_method() -> None:
    strategy = StrictSchemaCanonicalisationMitigation()
    outcome = strategy.process({**VALID_REQUEST, "method": None})
    assert outcome.decision == Decision.BLOCKED
    assert outcome.parser_reached is False
    assert outcome.logged is True


def test_blocks_oversized_declared_content_length() -> None:
    strategy = StrictSchemaCanonicalisationMitigation()
    outcome = strategy.process(
        {**VALID_REQUEST, "declared_content_length": 5000000, "actual_body_length": 5000000}
    )
    assert outcome.decision == Decision.BLOCKED


def test_blocks_mismatched_declared_and_actual_length() -> None:
    strategy = StrictSchemaCanonicalisationMitigation()
    outcome = strategy.process(
        {**VALID_REQUEST, "declared_content_length": 42, "actual_body_length": 4096}
    )
    assert outcome.decision == Decision.BLOCKED


def test_blocks_duplicate_header_keys() -> None:
    strategy = StrictSchemaCanonicalisationMitigation()
    outcome = strategy.process(
        {
            **VALID_REQUEST,
            "headers": [["Host", "vpn.example.local"], ["Host", "other.local"]],
        }
    )
    assert outcome.decision == Decision.BLOCKED


def test_blocks_unsupported_encoding() -> None:
    strategy = StrictSchemaCanonicalisationMitigation()
    outcome = strategy.process({**VALID_REQUEST, "encoding": "utf-7"})
    assert outcome.decision == Decision.BLOCKED


def test_blocks_path_traversal_sequence() -> None:
    strategy = StrictSchemaCanonicalisationMitigation()
    outcome = strategy.process({**VALID_REQUEST, "path": "/remote/../../internal/x"})
    assert outcome.decision == Decision.BLOCKED


def test_blocks_oversized_header_value() -> None:
    strategy = StrictSchemaCanonicalisationMitigation()
    outcome = strategy.process({**VALID_REQUEST, "headers": [["Host", "x" * 2000]]})
    assert outcome.decision == Decision.BLOCKED


def test_accepts_non_dict_query_params_as_no_params_to_check() -> None:
    strategy = StrictSchemaCanonicalisationMitigation()
    outcome = strategy.process({**VALID_REQUEST, "query_params": ["not", "a", "dict"]})
    assert outcome.decision == Decision.ACCEPTED


def test_mitigation_matches_expected_outcome_for_every_case_in_real_dataset() -> None:
    test_set, _ = load_test_set(DATASET_PATH)
    strategy = StrictSchemaCanonicalisationMitigation()
    mismatches = []
    for case in test_set.cases:
        outcome = strategy.process(case.input_data)
        if outcome.decision != case.expected_outcome:
            mismatches.append((case.case_id, case.expected_outcome, outcome.decision))
    assert mismatches == []


def test_mitigation_blocks_all_malformed_cases_in_real_dataset() -> None:
    test_set, _ = load_test_set(DATASET_PATH)
    strategy = StrictSchemaCanonicalisationMitigation()
    malformed_cases = [c for c in test_set.cases if c.category == TestCaseCategory.MALFORMED]
    outcomes = [strategy.process(c.input_data) for c in malformed_cases]

    block_rate = sum(o.decision == Decision.BLOCKED for o in outcomes) / len(outcomes)
    assert block_rate == 1.0
    assert all(not o.parser_reached for o in outcomes)
    assert all(o.logged for o in outcomes)


def test_mitigation_accepts_all_valid_cases_in_real_dataset() -> None:
    test_set, _ = load_test_set(DATASET_PATH)
    strategy = StrictSchemaCanonicalisationMitigation()
    valid_cases = [c for c in test_set.cases if c.category == TestCaseCategory.VALID]
    outcomes = [strategy.process(c.input_data) for c in valid_cases]
    assert all(o.decision == Decision.ACCEPTED for o in outcomes)
    assert all(not o.logged for o in outcomes)


def test_mitigation_blocks_materially_more_malformed_cases_than_baseline() -> None:
    test_set, _ = load_test_set(DATASET_PATH)
    malformed_cases = [c for c in test_set.cases if c.category == TestCaseCategory.MALFORMED]

    baseline = WeakSchemaLengthBaseline()
    mitigation = StrictSchemaCanonicalisationMitigation()

    baseline_block_rate = sum(
        baseline.process(c.input_data).decision == Decision.BLOCKED for c in malformed_cases
    ) / len(malformed_cases)
    mitigation_block_rate = sum(
        mitigation.process(c.input_data).decision == Decision.BLOCKED for c in malformed_cases
    ) / len(malformed_cases)

    assert mitigation_block_rate > baseline_block_rate
    assert baseline_block_rate == 0.0
    assert mitigation_block_rate == 1.0
