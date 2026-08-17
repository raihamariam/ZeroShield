import pytest
from pydantic import ValidationError

from zeroshield.generators import TelecomDatasetGenerator, TelecomGeneratorConfig
from zeroshield.models.enums import Decision, TestCaseCategory
from zeroshield.strategies.telecom.strict_mitigation import StrictGrammarStateMachineMitigation
from zeroshield.strategies.telecom.weak_baseline import WeakMandatoryFieldStateBaseline


def test_same_seed_and_config_reproduce_byte_identical_dataset() -> None:
    gen = TelecomDatasetGenerator()
    config = TelecomGeneratorConfig(oversized_field_count=2, invalid_sequence_count=2)
    d1 = gen.generate(seed=42, config=config)
    d2 = gen.generate(seed=42, config=config)
    assert d1.provenance.sha256 == d2.provenance.sha256


def test_different_seed_produces_different_hash() -> None:
    gen = TelecomDatasetGenerator()
    config = TelecomGeneratorConfig()
    assert gen.generate(seed=1, config=config).provenance.sha256 != gen.generate(seed=2, config=config).provenance.sha256


def test_invalid_config_raises_validation_error() -> None:
    with pytest.raises(ValidationError):
        TelecomGeneratorConfig(valid_count=-1)


def test_expected_outcome_matches_real_mitigation_strategy_for_every_category() -> None:
    gen = TelecomDatasetGenerator()
    config = TelecomGeneratorConfig(
        boundary_count=3, oversized_field_count=3, missing_header_count=3, duplicate_identity_count=3,
        mismatched_length_count=3, invalid_sequence_count=3, invalid_transition_count=3,
    )
    generated = gen.generate(seed=13, config=config)
    mitigation = StrictGrammarStateMachineMitigation()
    for case in generated.test_set.cases:
        outcome = mitigation.process(case.input_data)
        assert outcome.decision == case.expected_outcome, (
            f"{case.case_id}: mitigation said {outcome.decision}, expected {case.expected_outcome}"
        )


def test_weak_baseline_accepts_more_than_strict_mitigation() -> None:
    gen = TelecomDatasetGenerator()
    config = TelecomGeneratorConfig(
        oversized_field_count=3, missing_header_count=3, mismatched_length_count=3, invalid_sequence_count=3
    )
    generated = gen.generate(seed=23, config=config)
    baseline = WeakMandatoryFieldStateBaseline()
    mitigation = StrictGrammarStateMachineMitigation()
    baseline_blocked = sum(
        1 for c in generated.test_set.cases if baseline.process(c.input_data).decision == Decision.BLOCKED
    )
    mitigation_blocked = sum(
        1 for c in generated.test_set.cases if mitigation.process(c.input_data).decision == Decision.BLOCKED
    )
    assert mitigation_blocked > baseline_blocked


def test_valid_cases_use_only_legal_state_transitions() -> None:
    gen = TelecomDatasetGenerator()
    generated = gen.generate(seed=9, config=TelecomGeneratorConfig(valid_count=6))
    legal = {("INIT", "INVITE"), ("RINGING", "ACK"), ("ESTABLISHED", "BYE")}
    for case in generated.test_set.cases:
        if case.category is TestCaseCategory.VALID:
            pair = (case.input_data["session_state"], case.input_data["method"])
            assert pair in legal


def test_case_ids_unique() -> None:
    gen = TelecomDatasetGenerator()
    generated = gen.generate(seed=5, config=TelecomGeneratorConfig())
    case_ids = [c.case_id for c in generated.test_set.cases]
    assert len(set(case_ids)) == len(case_ids)
