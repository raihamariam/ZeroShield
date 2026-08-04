import json
from collections import Counter
from pathlib import Path

from zeroshield.datasets import load_test_set
from zeroshield.models import Decision, Domain, ExperimentDefinition, TestCaseCategory

REPO_ROOT = Path(__file__).resolve().parents[2]
DATASET_PATH = REPO_ROOT / "test_data" / "telecom" / "telecom_sip_session_setup_dataset.json"
EXPERIMENT_PATH = REPO_ROOT / "experiments" / "ZC-TELECOM-EXP-001.json"

EXPECTED_CASE_ID_PREFIXES = (
    "TEL-VALID-",
    "TEL-BOUNDARY-",
    "TEL-MISSING-HEADER-",
    "TEL-OVERSIZED-FIELD-",
    "TEL-MALFORMED-LENGTH-",
    "TEL-DUPLICATE-IDENTITY-",
    "TEL-INVALID-SEQUENCE-",
    "TEL-INVALID-TRANSITION-",
)


def test_telecom_dataset_matches_experiment_declared_path() -> None:
    experiment_data = json.loads(EXPERIMENT_PATH.read_text(encoding="utf-8"))
    experiment = ExperimentDefinition(**experiment_data)
    expected = "test_data/telecom/telecom_sip_session_setup_dataset.json"
    assert str(experiment.dataset_path).replace("\\", "/") == expected
    assert DATASET_PATH.is_file()


def test_telecom_dataset_loads_and_hashes() -> None:
    test_set, sha256_hex = load_test_set(DATASET_PATH)
    assert test_set.domain == Domain.TELECOM
    assert len(sha256_hex) == 64
    assert len(test_set.cases) == 25


def test_telecom_dataset_covers_all_srs_input_categories() -> None:
    test_set, _ = load_test_set(DATASET_PATH)
    case_ids = [c.case_id for c in test_set.cases]
    for prefix in EXPECTED_CASE_ID_PREFIXES:
        matching = [cid for cid in case_ids if cid.startswith(prefix)]
        assert len(matching) == 3 or (prefix == "TEL-VALID-" and len(matching) == 4), (
            f"unexpected case count for prefix {prefix}: {len(matching)}"
        )


def test_telecom_dataset_category_distribution() -> None:
    test_set, _ = load_test_set(DATASET_PATH)
    counts = Counter(c.category for c in test_set.cases)
    assert counts[TestCaseCategory.VALID] == 4
    assert counts[TestCaseCategory.BOUNDARY] == 3
    assert counts[TestCaseCategory.MALFORMED] == 18


def test_valid_cases_all_expect_acceptance() -> None:
    test_set, _ = load_test_set(DATASET_PATH)
    valid_cases = [c for c in test_set.cases if c.category == TestCaseCategory.VALID]
    assert all(c.expected_outcome == Decision.ACCEPTED for c in valid_cases)


def test_malformed_cases_all_expect_blocking() -> None:
    test_set, _ = load_test_set(DATASET_PATH)
    malformed_cases = [c for c in test_set.cases if c.category == TestCaseCategory.MALFORMED]
    assert all(c.expected_outcome == Decision.BLOCKED for c in malformed_cases)


def test_boundary_cases_include_both_outcomes() -> None:
    test_set, _ = load_test_set(DATASET_PATH)
    boundary_cases = [c for c in test_set.cases if c.category == TestCaseCategory.BOUNDARY]
    outcomes = {c.expected_outcome for c in boundary_cases}
    assert outcomes == {Decision.ACCEPTED, Decision.BLOCKED}


def test_every_case_has_non_trivial_provenance() -> None:
    test_set, _ = load_test_set(DATASET_PATH)
    for c in test_set.cases:
        assert c.provenance.startswith("synthetic")


def test_no_case_contains_credential_like_fields() -> None:
    test_set, _ = load_test_set(DATASET_PATH)
    suspicious_keys = {"password", "passwd", "secret", "api_key", "apikey", "token", "private_key"}
    for c in test_set.cases:
        keys_lower = {str(k).lower() for k in c.input_data}
        assert not keys_lower & suspicious_keys, f"{c.case_id} contains a credential-like field"


def test_all_four_related_cves_referenced_in_dataset_provenance() -> None:
    test_set, _ = load_test_set(DATASET_PATH)
    provenance_text = " ".join(c.provenance for c in test_set.cases)
    for cve_id in ("CVE-2023-24033", "CVE-2023-26496", "CVE-2023-26497", "CVE-2023-26498"):
        assert cve_id in provenance_text
