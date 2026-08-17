import pytest
from pydantic import ValidationError

from zeroshield.generators import VPNDatasetGenerator, VPNGeneratorConfig
from zeroshield.models.enums import Decision, TestCaseCategory
from zeroshield.strategies.vpn.strict_mitigation import StrictSchemaCanonicalisationMitigation
from zeroshield.strategies.vpn.weak_baseline import WeakSchemaLengthBaseline


def test_same_seed_and_config_reproduce_byte_identical_dataset() -> None:
    gen = VPNDatasetGenerator()
    config = VPNGeneratorConfig(oversized_count=3, duplicate_field_count=2)
    d1 = gen.generate(seed=42, config=config)
    d2 = gen.generate(seed=42, config=config)
    assert d1.provenance.sha256 == d2.provenance.sha256
    assert d1.test_set.model_dump_json() == d2.test_set.model_dump_json()


def test_different_seed_produces_different_hash() -> None:
    gen = VPNDatasetGenerator()
    config = VPNGeneratorConfig()
    d1 = gen.generate(seed=1, config=config)
    d2 = gen.generate(seed=2, config=config)
    assert d1.provenance.sha256 != d2.provenance.sha256


def test_different_config_produces_different_hash_same_seed() -> None:
    gen = VPNDatasetGenerator()
    d1 = gen.generate(seed=1, config=VPNGeneratorConfig(valid_count=2))
    d2 = gen.generate(seed=1, config=VPNGeneratorConfig(valid_count=4))
    assert d1.provenance.sha256 != d2.provenance.sha256
    assert len(d1.test_set.cases) != len(d2.test_set.cases)


def test_provenance_fields_are_recorded() -> None:
    gen = VPNDatasetGenerator()
    generated = gen.generate(seed=7, config=VPNGeneratorConfig())
    assert generated.provenance.generator_id == "vpn_pre_auth_request_generator"
    assert generated.provenance.generator_version == "1.0.0"
    assert generated.provenance.seed == 7
    assert generated.provenance.config["valid_count"] == 4  # default


def test_invalid_config_raises_validation_error() -> None:
    with pytest.raises(ValidationError):
        VPNGeneratorConfig(valid_count=-1)
    with pytest.raises(ValidationError):
        VPNGeneratorConfig(unexpected_field=True)  # type: ignore[call-arg]


_ALLOWED_PATH_TRAVERSAL_PATTERNS = frozenset(
    {
        "/remote/../../internal/synthetic-config",
        "/remote/%2e%2e/%2e%2e/internal/synthetic-config",
        "/remote/login%00.synthetic",
    }
)


def test_generated_cases_never_contain_real_exploit_payloads() -> None:
    """The oversized-*string* boundary path must be built only from a
    repeated safe character ('a'), matching the existing hand-authored
    dataset's own precedent - never real shellcode/exploit byte sequences.
    (VPN-GEN-OVERSIZED-* cases are oversized only in a numeric declared
    length, not in string content, so they have no "body" to check here.)
    Path-traversal cases are limited to the documented, fictitious-target
    synthetic patterns."""
    gen = VPNDatasetGenerator()
    generated = gen.generate(
        seed=3, config=VPNGeneratorConfig(oversized_count=2, invalid_path_count=2, boundary_count=1)
    )
    for case in generated.test_set.cases:
        path = case.input_data.get("path", "")
        if case.case_id.startswith("VPN-GEN-INVALID-PATH"):
            assert path in _ALLOWED_PATH_TRAVERSAL_PATTERNS
        elif case.case_id.startswith("VPN-GEN-BOUNDARY"):
            body = path.removeprefix("/remote/")
            assert set(body) <= {"a"}, f"unexpected characters in generated path body: {body!r}"


def test_expected_outcome_matches_real_mitigation_strategy_for_every_category() -> None:
    """The generator's ground-truth `expected_outcome` must always match what
    StrictSchemaCanonicalisationMitigation actually decides - the strongest
    proof the generator is grounded in real strategy semantics, not guessed."""
    gen = VPNDatasetGenerator()
    config = VPNGeneratorConfig(
        boundary_count=3, oversized_count=3, duplicate_field_count=3, mismatched_length_count=3,
        unsupported_encoding_count=3, invalid_path_count=3,
    )
    generated = gen.generate(seed=11, config=config)
    mitigation = StrictSchemaCanonicalisationMitigation()
    for case in generated.test_set.cases:
        outcome = mitigation.process(case.input_data)
        assert outcome.decision == case.expected_outcome, (
            f"{case.case_id}: mitigation said {outcome.decision}, expected {case.expected_outcome}"
        )


def test_weak_baseline_accepts_more_than_strict_mitigation() -> None:
    """Demonstrates the generator actually produces a meaningful comparison -
    the weak baseline should block strictly fewer cases than the mitigation."""
    gen = VPNDatasetGenerator()
    config = VPNGeneratorConfig(oversized_count=3, duplicate_field_count=3, invalid_path_count=3)
    generated = gen.generate(seed=21, config=config)
    baseline = WeakSchemaLengthBaseline()
    mitigation = StrictSchemaCanonicalisationMitigation()
    baseline_blocked = sum(
        1 for c in generated.test_set.cases if baseline.process(c.input_data).decision == Decision.BLOCKED
    )
    mitigation_blocked = sum(
        1 for c in generated.test_set.cases if mitigation.process(c.input_data).decision == Decision.BLOCKED
    )
    assert mitigation_blocked > baseline_blocked


def test_case_ids_are_unique_and_categories_present() -> None:
    gen = VPNDatasetGenerator()
    generated = gen.generate(seed=5, config=VPNGeneratorConfig())
    case_ids = [c.case_id for c in generated.test_set.cases]
    assert len(set(case_ids)) == len(case_ids)
    categories = {c.category for c in generated.test_set.cases}
    assert TestCaseCategory.VALID in categories
    assert TestCaseCategory.MALFORMED in categories
