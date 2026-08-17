"""DomainPack contract (V2 Phase 3, Step 1): what a domain needs to declare to
plug into the platform - identity/version, which failure patterns and
templates it supports, which strategies it allow-lists (a domain-scoped
narrowing of zeroshield.strategies.registry's global set - a VPN pack must
never allow-list a Telecom strategy even though both are registered
globally), which dataset generator it uses, and which metrics it expects.

Future domain packs (Identity/SSO, Messaging, ...) only need a new module
implementing this same contract plus a registry.register_domain_pack() call -
the core (runner/orchestration/policy/API) never special-cases a domain by
name. Not implemented in Phase 3, per the phase's own scope boundary.
"""

from pydantic import BaseModel, ConfigDict, Field

from zeroshield.models.enums import Domain, MetricName


class DomainPack(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    pack_id: str = Field(min_length=1)
    name: str = Field(min_length=1)
    version: str = Field(min_length=1)
    domain: Domain
    supported_failure_patterns: list[str] = Field(min_length=1)
    template_ids: list[str] = Field(min_length=1)
    allowed_strategy_ids: frozenset[str] = Field(min_length=1)
    dataset_generator_id: str = Field(min_length=1)
    domain_metrics: list[MetricName] = Field(min_length=1)
    compatibility: dict[str, str] = Field(default_factory=dict)
