"""Deterministic synthetic dataset generator contract (V2 Phase 3, Step 3).

Same generator_id + version + config + seed must always reproduce the same
TestSet (byte-identical when canonically serialised) - every concrete
generator must use only a locally-seeded `random.Random(seed)` instance,
never the global `random` module or any wall-clock/OS-entropy source, for
anything that affects case content or ordering.
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

from pydantic import BaseModel

from zeroshield.generators.hashing import canonical_sha256
from zeroshield.models import TestSet
from zeroshield.models.enums import Domain


@dataclass(frozen=True)
class DatasetProvenance:
    generator_id: str
    generator_version: str
    seed: int
    config: dict[str, Any]
    generated_at: datetime
    sha256: str


@dataclass(frozen=True)
class GeneratedDataset:
    test_set: TestSet
    provenance: DatasetProvenance


class DatasetGenerator(ABC):
    generator_id: str
    version: str
    domain: Domain

    @abstractmethod
    def _build_test_set(self, *, seed: int, config: BaseModel) -> TestSet:
        """Deterministic case construction - the only method a concrete
        generator implements. generate() wraps this with hashing/provenance
        so every generator gets identical, correct provenance handling."""

    def generate(self, *, seed: int, config: BaseModel, clock: Any = None) -> GeneratedDataset:
        test_set = self._build_test_set(seed=seed, config=config)
        sha256 = canonical_sha256(test_set.model_dump(mode="json"))
        generated_at = clock() if callable(clock) else datetime.now(UTC)
        provenance = DatasetProvenance(
            generator_id=self.generator_id,
            generator_version=self.version,
            seed=seed,
            config=config.model_dump(mode="json"),
            generated_at=generated_at,
            sha256=sha256,
        )
        return GeneratedDataset(test_set=test_set, provenance=provenance)
