from pydantic import BaseModel, ConfigDict, Field, model_validator

from zeroshield.models.enums import Domain
from zeroshield.models.test_case import TestCase


class TestSet(BaseModel):
    """A versioned, immutable collection of test cases, per SRS §7.1 (Test Set) / FR-005."""

    __test__ = False  # not a pytest test class despite the name
    model_config = ConfigDict(frozen=True, extra="forbid")

    test_set_id: str = Field(min_length=1)
    version: str = Field(min_length=1)
    domain: Domain
    cases: list[TestCase] = Field(min_length=1)

    @model_validator(mode="after")
    def check_case_ids_unique(self) -> "TestSet":
        case_ids = [c.case_id for c in self.cases]
        if len(set(case_ids)) != len(case_ids):
            raise ValueError("cases must not contain duplicate case_id values")
        return self
