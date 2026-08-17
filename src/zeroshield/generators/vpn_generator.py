"""Deterministic VPN pre-auth request dataset generator.

Case semantics are deliberately grounded in the real strategies
(zeroshield.strategies.vpn.weak_baseline/strict_mitigation) so generated
`expected_outcome` values are actually correct, not guessed: `expected_outcome`
always reflects what StrictSchemaCanonicalisationMitigation (the "should
behave this way" reference) does with the generated input - never real
exploit payloads, only synthetic length/shape patterns, matching the existing
hand-authored dataset's own precedent (e.g. repeated "a" characters for
oversized fields).
"""

import random

from pydantic import BaseModel, ConfigDict, Field

from zeroshield.generators.base import DatasetGenerator
from zeroshield.models import TestCase, TestSet
from zeroshield.models.enums import Decision, Domain, TestCaseCategory


class VPNGeneratorConfig(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    valid_count: int = Field(ge=0, le=50, default=4)
    boundary_count: int = Field(ge=0, le=10, default=1)
    oversized_count: int = Field(ge=0, le=20, default=2)
    duplicate_field_count: int = Field(ge=0, le=20, default=2)
    mismatched_length_count: int = Field(ge=0, le=20, default=2)
    unsupported_encoding_count: int = Field(ge=0, le=20, default=2)
    invalid_path_count: int = Field(ge=0, le=20, default=2)
    max_path_length: int = Field(gt=0, default=256)
    max_body_length: int = Field(gt=0, default=8192)
    max_header_value_length: int = Field(gt=0, default=512)


_VALID_PATHS = ("/remote/login", "/remote/logincheck", "/remote/fgt_lang", "/remote/index")
_UNSUPPORTED_ENCODINGS = ("utf-7", "cesu-8", "unspecified-binary")
_PATH_TRAVERSAL_PATTERNS = (
    "/remote/../../internal/synthetic-config",
    "/remote/%2e%2e/%2e%2e/internal/synthetic-config",
    "/remote/login%00.synthetic",
)


class VPNDatasetGenerator(DatasetGenerator):
    generator_id = "vpn_pre_auth_request_generator"
    version = "1.0.0"
    domain = Domain.VPN

    def _build_test_set(self, *, seed: int, config: BaseModel) -> TestSet:
        assert isinstance(config, VPNGeneratorConfig)
        rng = random.Random(seed)
        cases: list[TestCase] = []

        for i in range(config.valid_count):
            path = _VALID_PATHS[i % len(_VALID_PATHS)]
            cases.append(
                self._case(
                    f"VPN-GEN-VALID-{i + 1:03d}",
                    TestCaseCategory.VALID,
                    {
                        "method": "GET" if rng.random() < 0.5 else "POST",
                        "path": path,
                        "headers": [["Host", "vpn.example.local"]],
                        "declared_content_length": 0,
                        "actual_body_length": 0,
                        "encoding": "utf-8",
                    },
                    Decision.ACCEPTED,
                    "deterministic synthetic valid pre-auth request",
                )
            )

        for i in range(config.boundary_count):
            prefix = "/remote/"
            at_limit_path = prefix + "a" * (config.max_path_length - len(prefix))
            over_limit_path = prefix + "a" * (config.max_path_length - len(prefix) + 1)
            cases.append(
                self._case(
                    f"VPN-GEN-BOUNDARY-AT-{i + 1:03d}",
                    TestCaseCategory.BOUNDARY,
                    self._base_request(at_limit_path),
                    Decision.ACCEPTED,
                    f"total path length exactly at the configured maximum ({config.max_path_length})",
                )
            )
            cases.append(
                self._case(
                    f"VPN-GEN-BOUNDARY-OVER-{i + 1:03d}",
                    TestCaseCategory.BOUNDARY,
                    self._base_request(over_limit_path),
                    Decision.BLOCKED,
                    f"total path length one over the configured maximum ({config.max_path_length})",
                )
            )

        for i in range(config.oversized_count):
            oversized_length = config.max_body_length + 1 + rng.randint(0, 1000)
            req = self._base_request("/remote/login")
            req.update(declared_content_length=oversized_length, actual_body_length=oversized_length)
            cases.append(
                self._case(
                    f"VPN-GEN-OVERSIZED-{i + 1:03d}",
                    TestCaseCategory.MALFORMED,
                    req,
                    Decision.BLOCKED,
                    "declared/actual body length over the configured maximum",
                )
            )

        for i in range(config.duplicate_field_count):
            req = self._base_request("/remote/login")
            req["headers"] = [["Host", "vpn.example.local"], ["Host", "internal.synthetic.local"]]
            cases.append(
                self._case(
                    f"VPN-GEN-DUPLICATE-{i + 1:03d}",
                    TestCaseCategory.MALFORMED,
                    req,
                    Decision.BLOCKED,
                    "duplicate header field with conflicting values",
                )
            )

        for i in range(config.mismatched_length_count):
            req = self._base_request("/remote/login")
            declared = 42
            actual = declared + 100 + rng.randint(0, 500)
            req.update(declared_content_length=declared, actual_body_length=actual)
            cases.append(
                self._case(
                    f"VPN-GEN-MISMATCHED-LENGTH-{i + 1:03d}",
                    TestCaseCategory.MALFORMED,
                    req,
                    Decision.BLOCKED,
                    "declared/actual body length mismatch",
                )
            )

        for i in range(config.unsupported_encoding_count):
            req = self._base_request("/remote/login")
            req["encoding"] = _UNSUPPORTED_ENCODINGS[i % len(_UNSUPPORTED_ENCODINGS)]
            cases.append(
                self._case(
                    f"VPN-GEN-UNSUPPORTED-ENCODING-{i + 1:03d}",
                    TestCaseCategory.MALFORMED,
                    req,
                    Decision.BLOCKED,
                    f"unsupported declared encoding ({req['encoding']})",
                )
            )

        for i in range(config.invalid_path_count):
            req = self._base_request(_PATH_TRAVERSAL_PATTERNS[i % len(_PATH_TRAVERSAL_PATTERNS)])
            cases.append(
                self._case(
                    f"VPN-GEN-INVALID-PATH-{i + 1:03d}",
                    TestCaseCategory.MALFORMED,
                    req,
                    Decision.BLOCKED,
                    "synthetic path-traversal-shaped pattern, no real filesystem target",
                )
            )

        return TestSet(
            test_set_id=f"vpn-generated-{seed}",
            version="1.0.0",
            domain=Domain.VPN,
            cases=cases,
        )

    @staticmethod
    def _base_request(path: str) -> dict:
        return {
            "method": "GET",
            "path": path,
            "headers": [["Host", "vpn.example.local"]],
            "declared_content_length": 0,
            "actual_body_length": 0,
            "encoding": "utf-8",
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
