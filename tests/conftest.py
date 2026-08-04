import pytest


@pytest.fixture
def valid_cve_reference_data() -> dict:
    return {
        "cve_id": "CVE-2024-21762",
        "domain": "VPN",
        "cvss_score": 9.8,
        "cisa_kev": True,
        "epss_score": 0.8343,
        "trust_boundary": "Internet to pre-auth SSL VPN service",
        "root_cause": "memory_safety_failure",
        "vendor_mitigation": "Upgrade to a fixed FortiOS release per FG-IR-24-015.",
        "mitigation_gap": "Session/credential rotation guidance after exposure is limited.",
        "source_urls": ["https://www.fortiguard.com/psirt/FG-IR-24-015"],
        "retrieved_date": "2026-07-13",
    }


@pytest.fixture
def valid_experiment_definition_data(valid_cve_reference_data: dict) -> dict:
    return {
        # 999 is a reserved test-fixture ID, distinct from the real experiment sequence
        "experiment_id": "ZC-VPN-EXP-999",
        "title": "Pre-Authentication SSL VPN Request Validation",
        "domain": "VPN",
        "description": "Synthetic pre-auth VPN request validation experiment.",
        "related_cves": [valid_cve_reference_data],
        "failure_pattern": "Unauthenticated request reaches memory-unsafe parsing code.",
        "root_cause": "memory_safety_failure",
        "vendor_mitigation": "Vendor firmware upgrade.",
        "mitigation_gap": "Session hygiene guidance limited.",
        "research_question": "Can pre-parser validation reject malformed requests?",
        "hypothesis": "Strict validation blocks more malformed requests than a weak baseline.",
        "safety_level": "SYNTHETIC_ONLY",
        "baseline_strategy": "weak_schema_length_baseline",
        "mitigation_strategy": "strict_schema_canonicalisation_mitigation",
        "dataset_path": "test_data/vpn/vpn_pre_auth_request_dataset.json",
        "metrics_to_collect": ["block_rate", "valid_acceptance_rate"],
    }
