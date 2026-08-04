from pathlib import Path

from zeroshield.datasets import load_test_set
from zeroshield.models import Decision, TestCaseCategory
from zeroshield.strategies.telecom import (
    StrictGrammarStateMachineMitigation,
    WeakMandatoryFieldStateBaseline,
)

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
        StrictGrammarStateMachineMitigation.strategy_id
        == "strict_grammar_state_machine_mitigation"
    )


def test_accepts_well_formed_message() -> None:
    strategy = StrictGrammarStateMachineMitigation()
    outcome = strategy.process(VALID_MESSAGE)
    assert outcome.decision == Decision.ACCEPTED
    assert outcome.parser_reached is True
    assert outcome.logged is False


def test_blocks_missing_mandatory_header() -> None:
    strategy = StrictGrammarStateMachineMitigation()
    outcome = strategy.process(
        {**VALID_MESSAGE, "headers": [["From", "sip:alice@ims.example.local"]]}
    )
    assert outcome.decision == Decision.BLOCKED
    assert outcome.parser_reached is False
    assert outcome.logged is True


def test_blocks_duplicate_header_key() -> None:
    strategy = StrictGrammarStateMachineMitigation()
    outcome = strategy.process(
        {
            **VALID_MESSAGE,
            "headers": [
                ["Call-ID", "call-0001"],
                ["Call-ID", "call-9999"],
                ["From", "sip:alice@ims.example.local"],
                ["To", "sip:bob@ims.example.local"],
            ],
        }
    )
    assert outcome.decision == Decision.BLOCKED


def test_blocks_oversized_sdp_attribute() -> None:
    strategy = StrictGrammarStateMachineMitigation()
    outcome = strategy.process({**VALID_MESSAGE, "sdp_attributes": [["fmtp", "x" * 2000]]})
    assert outcome.decision == Decision.BLOCKED


def test_blocks_mismatched_declared_and_actual_length() -> None:
    strategy = StrictGrammarStateMachineMitigation()
    outcome = strategy.process(
        {**VALID_MESSAGE, "declared_body_length": 32, "actual_body_length": 4096}
    )
    assert outcome.decision == Decision.BLOCKED


def test_blocks_invalid_sequence_number() -> None:
    strategy = StrictGrammarStateMachineMitigation()
    outcome = strategy.process(
        {**VALID_MESSAGE, "sequence_number": 99, "expected_sequence_number": 1}
    )
    assert outcome.decision == Decision.BLOCKED


def test_blocks_invalid_state_transition() -> None:
    strategy = StrictGrammarStateMachineMitigation()
    outcome = strategy.process({**VALID_MESSAGE, "method": "ACK", "session_state": "INIT"})
    assert outcome.decision == Decision.BLOCKED


def test_mitigation_matches_expected_outcome_for_every_case_in_real_dataset() -> None:
    test_set, _ = load_test_set(DATASET_PATH)
    strategy = StrictGrammarStateMachineMitigation()
    mismatches = []
    for case in test_set.cases:
        outcome = strategy.process(case.input_data)
        if outcome.decision != case.expected_outcome:
            mismatches.append((case.case_id, case.expected_outcome, outcome.decision))
    assert mismatches == []


def test_mitigation_blocks_all_malformed_cases_in_real_dataset() -> None:
    test_set, _ = load_test_set(DATASET_PATH)
    strategy = StrictGrammarStateMachineMitigation()
    malformed_cases = [c for c in test_set.cases if c.category == TestCaseCategory.MALFORMED]
    outcomes = [strategy.process(c.input_data) for c in malformed_cases]

    block_rate = sum(o.decision == Decision.BLOCKED for o in outcomes) / len(outcomes)
    assert block_rate == 1.0
    assert all(not o.parser_reached for o in outcomes)
    assert all(o.logged for o in outcomes)


def test_mitigation_accepts_all_valid_cases_in_real_dataset() -> None:
    test_set, _ = load_test_set(DATASET_PATH)
    strategy = StrictGrammarStateMachineMitigation()
    valid_cases = [c for c in test_set.cases if c.category == TestCaseCategory.VALID]
    outcomes = [strategy.process(c.input_data) for c in valid_cases]
    assert all(o.decision == Decision.ACCEPTED for o in outcomes)
    assert all(not o.logged for o in outcomes)


def test_mitigation_blocks_materially_more_malformed_cases_than_baseline() -> None:
    test_set, _ = load_test_set(DATASET_PATH)
    malformed_cases = [c for c in test_set.cases if c.category == TestCaseCategory.MALFORMED]

    baseline = WeakMandatoryFieldStateBaseline()
    mitigation = StrictGrammarStateMachineMitigation()

    baseline_block_rate = sum(
        baseline.process(c.input_data).decision == Decision.BLOCKED for c in malformed_cases
    ) / len(malformed_cases)
    mitigation_block_rate = sum(
        mitigation.process(c.input_data).decision == Decision.BLOCKED for c in malformed_cases
    ) / len(malformed_cases)

    assert mitigation_block_rate > baseline_block_rate
    assert baseline_block_rate == 0.0
    assert mitigation_block_rate == 1.0
