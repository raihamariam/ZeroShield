from datetime import date

from pydantic import BaseModel, ConfigDict, Field, HttpUrl

from zeroshield.models._shared import CveId
from zeroshield.models.enums import Domain, RootCauseCategory


class CVEReference(BaseModel):
    """CVE evidence citation, per SRS §7.1 (CVE Evidence entity) and §7.2 (provenance rules)."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    cve_id: CveId
    domain: Domain
    cvss_score: float | None = Field(default=None, ge=0.0, le=10.0)
    cisa_kev: bool
    epss_score: float | None = Field(default=None, ge=0.0, le=1.0)
    trust_boundary: str = Field(min_length=1)
    root_cause: RootCauseCategory
    vendor_mitigation: str = Field(min_length=1)
    mitigation_gap: str = Field(min_length=1)
    source_urls: list[HttpUrl] = Field(min_length=1)
    retrieved_date: date
