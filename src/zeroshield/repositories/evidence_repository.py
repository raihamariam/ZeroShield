import json
from abc import ABC, abstractmethod
from pathlib import Path

from zeroshield.models import ComparisonReport, EvidenceManifest
from zeroshield.repositories.evidence_builder import EvidenceBundle


class EvidenceRepository(ABC):
    """Abstracts evidence persistence, per SRS §4.2 Repository pattern (local now, MinIO later)."""

    @abstractmethod
    def save_run_evidence(self, bundle: EvidenceBundle) -> Path: ...

    @abstractmethod
    def load_manifest(self, experiment_id: str, run_id: str) -> EvidenceManifest: ...

    @abstractmethod
    def save_comparison(self, experiment_id: str, report: ComparisonReport) -> Path: ...


class LocalEvidenceRepository(EvidenceRepository):
    def __init__(self, root: Path) -> None:
        self._root = root

    def save_run_evidence(self, bundle: EvidenceBundle) -> Path:
        run_dir = self._root / bundle.manifest.experiment_id / bundle.manifest.run_id
        run_dir.mkdir(parents=True, exist_ok=True)
        for name, content in bundle.artefacts.items():
            (run_dir / name).write_bytes(content)
        return run_dir

    def load_manifest(self, experiment_id: str, run_id: str) -> EvidenceManifest:
        path = self._root / experiment_id / run_id / "manifest.json"
        data = json.loads(path.read_text(encoding="utf-8"))
        return EvidenceManifest.model_validate(data)

    def save_comparison(self, experiment_id: str, report: ComparisonReport) -> Path:
        experiment_dir = self._root / experiment_id
        experiment_dir.mkdir(parents=True, exist_ok=True)
        path = experiment_dir / "comparison.json"
        path.write_bytes(report.model_dump_json(indent=2).encode("utf-8"))
        return path
