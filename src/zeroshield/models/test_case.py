from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from zeroshield.models.enums import Decision, TestCaseCategory


class TestCase(BaseModel):
    """Synthetic test case, per SRS FR-005 and §7.1 (Test Case entity)."""

    __test__ = False  # not a pytest test class despite the name
    model_config = ConfigDict(frozen=True, extra="forbid")

    case_id: str = Field(min_length=1)
    category: TestCaseCategory
    input_data: dict[str, Any]
    expected_outcome: Decision
    provenance: str = Field(min_length=1)
    version: str = Field(min_length=1)
