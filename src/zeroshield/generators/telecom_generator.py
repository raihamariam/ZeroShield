"""Deterministic Telecom SIP-like session-setup dataset generator.

Grounded in zeroshield.strategies.telecom.weak_baseline/strict_mitigation the
same way vpn_generator.py is grounded in the VPN strategies - `expected_outcome`
always reflects StrictGrammarStateMachineMitigation's correct behaviour.
"""

import random

from pydantic import BaseModel, ConfigDict, Field

from zeroshield.generators.base import DatasetGenerator
from zeroshield.models import TestCase, TestSet
from zeroshield.models.enums import Decision, Domain, TestCaseCategory

_LEGAL_TRANSITIONS = (("INIT", "INVITE"), ("RINGING", "ACK"), ("ESTABLISHED", "BYE"))
_MANDATORY_HEADERS = ("Call-ID", "From", "To")


class TelecomGeneratorConfig(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    valid_count: int = Field(ge=0, le=50, default=4)
    boundary_count: int = Field(ge=0, le=10, default=1)
    oversized_field_count: int = Field(ge=0, le=20, default=2)
    missing_header_count: int = Field(ge=0, le=20, default=2)
    duplicate_identity_count: int = Field(ge=0, le=20, default=2)
    mismatched_length_count: int = Field(ge=0, le=20, default=2)
    invalid_sequence_count: int = Field(ge=0, le=20, default=2)
    invalid_transition_count: int = Field(ge=0, le=20, default=2)
    max_sdp_attr_value_length: int = Field(gt=0, default=256)
    max_body_length: int = Field(gt=0, default=4096)


def _headers(call_id: str = "call-0001") -> list[list[str]]:
    return [
        ["Call-ID", call_id],
        ["From", "sip:alice@ims.example.local"],
        ["To", "sip:bob@ims.example.local"],
    ]


class TelecomDatasetGenerator(DatasetGenerator):
    generator_id = "telecom_sip_session_setup_generator"
    version = "1.0.0"
    domain = Domain.TELECOM

    def _build_test_set(self, *, seed: int, config: BaseModel) -> TestSet:
        assert isinstance(config, TelecomGeneratorConfig)
        rng = random.Random(seed)
        cases: list[TestCase] = []

        for i in range(config.valid_count):
            state, method = _LEGAL_TRANSITIONS[i % len(_LEGAL_TRANSITIONS)]
            seq = i + 1
            req = self._base_request(state, method, seq, seq)
            cases.append(
                self._case(
                    f"TEL-GEN-VALID-{i + 1:03d}", TestCaseCategory.VALID, req, Decision.ACCEPTED,
                    "deterministic synthetic valid session-setup message",
                )
            )

        for i in range(config.boundary_count):
            at_limit = "a" * config.max_sdp_attr_value_length
            over_limit = "a" * (config.max_sdp_attr_value_length + 1)
            base = self._base_request("INIT", "INVITE", 1, 1)
            at_req = {**base, "sdp_attributes": [["video-configuration", at_limit]]}
            over_req = {**base, "sdp_attributes": [["video-configuration", over_limit]]}
            cases.append(
                self._case(
                    f"TEL-GEN-BOUNDARY-AT-{i + 1:03d}", TestCaseCategory.BOUNDARY, at_req, Decision.ACCEPTED,
                    f"SDP attribute value exactly at the configured maximum ({config.max_sdp_attr_value_length})",
                )
            )
            cases.append(
                self._case(
                    f"TEL-GEN-BOUNDARY-OVER-{i + 1:03d}", TestCaseCategory.BOUNDARY, over_req, Decision.BLOCKED,
                    f"SDP attribute value one over the configured maximum ({config.max_sdp_attr_value_length})",
                )
            )

        for i in range(config.oversized_field_count):
            oversized_length = config.max_sdp_attr_value_length + 1 + rng.randint(0, 500)
            req = self._base_request("INIT", "INVITE", 1, 1)
            req["sdp_attributes"] = [["accept-type", "a" * oversized_length]]
            cases.append(
                self._case(
                    f"TEL-GEN-OVERSIZED-{i + 1:03d}", TestCaseCategory.MALFORMED, req, Decision.BLOCKED,
                    "SDP attribute value over the configured maximum",
                )
            )

        for i in range(config.missing_header_count):
            missing = _MANDATORY_HEADERS[i % len(_MANDATORY_HEADERS)]
            req = self._base_request("INIT", "INVITE", 1, 1)
            req["headers"] = [h for h in req["headers"] if h[0] != missing]
            cases.append(
                self._case(
                    f"TEL-GEN-MISSING-HEADER-{i + 1:03d}", TestCaseCategory.MALFORMED, req, Decision.BLOCKED,
                    f"mandatory header '{missing}' absent",
                )
            )

        for i in range(config.duplicate_identity_count):
            field = _MANDATORY_HEADERS[i % len(_MANDATORY_HEADERS)]
            req = self._base_request("INIT", "INVITE", 1, 1)
            req["headers"] = [*req["headers"], [field, f"synthetic-conflicting-{field.lower()}"]]
            cases.append(
                self._case(
                    f"TEL-GEN-DUPLICATE-IDENTITY-{i + 1:03d}", TestCaseCategory.MALFORMED, req, Decision.BLOCKED,
                    f"duplicate '{field}' header with conflicting value",
                )
            )

        for i in range(config.mismatched_length_count):
            declared = 32
            actual = declared + 200 + rng.randint(0, 500)
            req = self._base_request("INIT", "INVITE", 1, 1)
            req.update(declared_body_length=declared, actual_body_length=actual)
            cases.append(
                self._case(
                    f"TEL-GEN-MISMATCHED-LENGTH-{i + 1:03d}", TestCaseCategory.MALFORMED, req, Decision.BLOCKED,
                    "declared/actual body length mismatch",
                )
            )

        for i in range(config.invalid_sequence_count):
            req = self._base_request("INIT", "INVITE", 0, 5 + i)
            cases.append(
                self._case(
                    f"TEL-GEN-INVALID-SEQUENCE-{i + 1:03d}", TestCaseCategory.MALFORMED, req, Decision.BLOCKED,
                    "sequence_number does not match expected_sequence_number",
                )
            )

        for i in range(config.invalid_transition_count):
            illegal_pairs = [("INIT", "ACK"), ("INIT", "BYE"), ("ESTABLISHED", "INVITE")]
            state, method = illegal_pairs[i % len(illegal_pairs)]
            req = self._base_request(state, method, 1, 1)
            cases.append(
                self._case(
                    f"TEL-GEN-INVALID-TRANSITION-{i + 1:03d}", TestCaseCategory.MALFORMED, req, Decision.BLOCKED,
                    f"illegal state transition: {method} received in state {state}",
                )
            )

        return TestSet(
            test_set_id=f"telecom-generated-{seed}",
            version="1.0.0",
            domain=Domain.TELECOM,
            cases=cases,
        )

    @staticmethod
    def _base_request(state: str, method: str, sequence: int, expected_sequence: int) -> dict:
        return {
            "method": method,
            "session_state": state,
            "headers": _headers(),
            "sequence_number": sequence,
            "expected_sequence_number": expected_sequence,
            "sdp_attributes": [["accept-type", "audio/AMR"]],
            "declared_body_length": 32,
            "actual_body_length": 32,
        }

    @staticmethod
    def _case(
        case_id: str, category: TestCaseCategory, input_data: dict, expected: Decision, provenance: str
    ) -> TestCase:
        return TestCase(
            case_id=case_id,
            category=category,
            input_data=input_data,
            expected_outcome=expected,
            provenance=provenance,
            version="1.0.0",
        )
