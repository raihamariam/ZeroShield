from pathlib import Path

from zeroshield.datasets import load_test_set
from zeroshield.models import Decision, TestCaseCategory
from zeroshield.strategies.telecom import WeakMandatoryFieldStateBaseline

REPO_ROOT = Path(__file__).resolve().parents[4]
DATASET_PATH = REPO_ROOT / "test_data" / "telecom" / "telecom_sip_session_setup_dataset.json"

VALID_MESSAGE = {
    "method": "INVITE",
    "session_state": "INIT",
    "headers": [
        ["Call-ID", "call-0001"],
        ["From", "sip:alice@ims.example.local"],
        ["To", "sip:bob@ims.example.local"],
    ],
    "sequence_number": 1,
    "expected_sequence_number": 1,
    "sdp_attributes": [["accept-type", "audio/AMR"]],
    "declared_body_length": 32,
    "actual_body_length": 32,
}


def test_strategy_id_matches_experiment_declaration() -> None:
    assert (
        WeakMandatoryFieldStateBaseline.strategy_id == "weak_mandatory_field_state_baseline"
    )


def test_accepts_well_formed_message() -> None:
    strategy = WeakMandatoryFieldStateBaseline()
    outcome = strategy.process(VALID_MESSAGE)
    assert outcome.decision == Decision.ACCEPTED
    assert outcome.parser_reached is True


def test_blocks_unknown_method() -> None:
    strategy = WeakMandatoryFieldStateBaseline()
    outcome = strategy.process({**VALID_MESSAGE, "method": "CANCEL"})
    assert outcome.decision == Decision.BLOCKED
    assert outcome.parser_reached is False


def test_blocks_empty_headers() -> None:
    strategy = WeakMandatoryFieldStateBaseline()
    outcome = strategy.process({**VALID_MESSAGE, "headers": []})
    assert outcome.decision == Decision.BLOCKED


def test_blocks_unknown_session_state() -> None:
    strategy = WeakMandatoryFieldStateBaseline()
    outcome = strategy.process({**VALID_MESSAGE, "session_state": "BOGUS"})
    assert outcome.decision == Decision.BLOCKED


def test_accepts_missing_mandatory_header() -> None:
    strategy = WeakMandatoryFieldStateBaseline()
    outcome = strategy.process(
        {**VALID_MESSAGE, "headers": [["From", "sip:alice@ims.example.local"]]}
    )
    assert outcome.decision == Decision.ACCEPTED


def test_accepts_oversized_sdp_attribute() -> None:
    strategy = WeakMandatoryFieldStateBaseline()
    outcome = strategy.process({**VALID_MESSAGE, "sdp_attributes": [["fmtp", "x" * 2000]]})
    assert outcome.decision == Decision.ACCEPTED


def test_accepts_invalid_state_transition() -> None:
    strategy = WeakMandatoryFieldStateBaseline()
    outcome = strategy.process({**VALID_MESSAGE, "method": "ACK", "session_state": "INIT"})
    assert outcome.decision == Decision.ACCEPTED


def test_weak_baseline_accepts_all_valid_and_accepted_boundary_cases_in_real_dataset() -> None:
    test_set, _ = load_test_set(DATASET_PATH)
    strategy = WeakMandatoryFieldStateBaseline()
    non_malformed = [c for c in test_set.cases if c.category != TestCaseCategory.MALFORMED]
    outcomes = [strategy.process(c.input_data) for c in non_malformed]
    assert all(o.decision == Decision.ACCEPTED for o in outcomes)


def test_weak_baseline_fails_to_block_any_malformed_case_in_real_dataset() -> None:
    test_set, _ = load_test_set(DATASET_PATH)
    strategy = WeakMandatoryFieldStateBaseline()
    malformed_cases = [c for c in test_set.cases if c.category == TestCaseCategory.MALFORMED]
    outcomes = [strategy.process(c.input_data) for c in malformed_cases]

    block_rate = sum(o.decision == Decision.BLOCKED for o in outcomes) / len(outcomes)
    assert block_rate == 0.0
    assert all(o.parser_reached for o in outcomes)
