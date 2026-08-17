"""Experiment Studio backend workflow (V2 Phase 3, Step 4):

    Vulnerability/CVE cluster -> Domain Pack -> Validation Template ->
    Dataset configuration -> Baseline -> Mitigation -> Metrics ->
    Safety settings -> Draft ExperimentVersion

`build_experiment_draft` is the one function that replaces hand-authoring an
experiment JSON file: every field it needs is already-validated structured
data (a DomainPack, a ValidationTemplate, a generator config), and its output
is a real ExperimentDefinition, so nothing downstream (ExperimentRunner,
SafetyPolicy, orchestration) needs to know Experiment Studio exists.

Editing is only ever allowed while a version is still DRAFT - Step 4:
"Approved versions become immutable; editing creates a new version" is
enforced here as "anything past DRAFT is immutable"; see edit_draft's
ImmutableVersionError.
"""

from datetime import UTC, datetime
from pathlib import Path

from pydantic import BaseModel

from zeroshield.domain_packs import resolve_domain_pack
from zeroshield.generators import GeneratedDataset, resolve_generator
from zeroshield.models import ApprovalStatus, CVEReference, ExperimentDefinition, ExperimentVersion
from zeroshield.models.enums import ExperimentVersionStatus, MetricName, RootCauseCategory
from zeroshield.templates import resolve_template


class ExperimentBuilderError(Exception):
    pass


class ImmutableVersionError(Exception):
    """Raised when attempting to edit a version that has left DRAFT - per
    Step 4, only a brand-new version may change its content past that point."""


def _utc_now() -> datetime:
    return datetime.now(UTC)


def _materialise_dataset(generated: GeneratedDataset, dataset_root: Path) -> Path:
    """Writes a generated TestSet to a content-addressed path under
    dataset_root (test_data/generated/<generator_id>/<sha256[:16]>.json) - the
    same seed+config always reuses the same file rather than duplicating it,
    and the resulting relative path is exactly what ExperimentDefinition.
    dataset_path already expects (zeroshield.datasets.loader.load_test_set
    needs no changes)."""
    subdir = dataset_root / generated.provenance.generator_id
    subdir.mkdir(parents=True, exist_ok=True)
    path = subdir / f"{generated.provenance.sha256[:16]}.json"
    if not path.is_file():
        path.write_text(generated.test_set.model_dump_json(indent=2), encoding="utf-8")
    return path


def build_experiment_draft(
    *,
    experiment_id: str,
    version_number: int,
    title: str,
    description: str,
    related_cves: list[CVEReference],
    domain_pack_id: str,
    template_id: str,
    template_version: str,
    dataset_config: BaseModel,
    seed: int,
    failure_pattern: str,
    root_cause: RootCauseCategory,
    vendor_mitigation: str,
    mitigation_gap: str,
    research_question: str,
    hypothesis: str,
    created_by: str,
    metrics_to_collect: list[MetricName] | None = None,
    dataset_root: Path = Path("test_data/generated"),
    clock: object = None,
) -> ExperimentVersion:
    domain_pack = resolve_domain_pack(domain_pack_id)
    template = resolve_template(template_id, template_version)
    if template.domain_pack_id != domain_pack.pack_id:
        raise ExperimentBuilderError(
            f"template '{template_id}' belongs to domain pack '{template.domain_pack_id}', "
            f"not '{domain_pack_id}'"
        )
    if template_id not in domain_pack.template_ids:
        raise ExperimentBuilderError(
            f"domain pack '{domain_pack_id}' does not list template '{template_id}' as supported"
        )

    generator = resolve_generator(domain_pack.dataset_generator_id)
    generated = generator.generate(seed=seed, config=dataset_config)
    dataset_path = _materialise_dataset(generated, dataset_root)

    baseline_strategy = template.allowed_baseline_strategies[0]
    mitigation_strategy = template.allowed_mitigation_strategies[0]
    for strategy_id in (baseline_strategy, mitigation_strategy):
        if strategy_id not in domain_pack.allowed_strategy_ids:
            raise ExperimentBuilderError(
                f"template '{template_id}' strategy '{strategy_id}' is not in domain pack "
                f"'{domain_pack_id}''s allow-list {sorted(domain_pack.allowed_strategy_ids)}"
            )

    now = clock() if callable(clock) else _utc_now()

    definition = ExperimentDefinition(
        experiment_id=experiment_id,
        title=title,
        domain=domain_pack.domain,
        description=description,
        related_cves=related_cves,
        failure_pattern=failure_pattern,
        root_cause=root_cause,
        vendor_mitigation=vendor_mitigation,
        mitigation_gap=mitigation_gap,
        research_question=research_question,
        hypothesis=hypothesis,
        safety_level=template.safety_level,
        baseline_strategy=baseline_strategy,
        mitigation_strategy=mitigation_strategy,
        dataset_path=dataset_path,
        metrics_to_collect=metrics_to_collect or template.metrics_to_collect,
        approval_status=ApprovalStatus.DRAFT,
        version=f"{version_number}.0.0",
    )

    return ExperimentVersion(
        version_id=f"{experiment_id}@v{version_number}",
        experiment_id=experiment_id,
        version_number=version_number,
        status=ExperimentVersionStatus.DRAFT,
        domain_pack_id=domain_pack_id,
        template_id=template_id,
        template_version=template_version,
        definition=definition,
        dataset_provenance={
            "generator_id": generated.provenance.generator_id,
            "generator_version": generated.provenance.generator_version,
            "seed": generated.provenance.seed,
            "config": generated.provenance.config,
            "sha256": generated.provenance.sha256,
        },
        created_by=created_by,
        created_at=now,
        updated_at=now,
    )


def edit_draft(version: ExperimentVersion, **updates: object) -> ExperimentVersion:
    """Applies field updates to `definition` - only while status is DRAFT.
    Past DRAFT, call build_experiment_draft() again with an incremented
    version_number instead (Step 4's "editing creates a new version")."""
    if version.status is not ExperimentVersionStatus.DRAFT:
        raise ImmutableVersionError(
            f"version '{version.version_id}' is '{version.status.value}', not 'draft' - "
            "create a new version to change its content"
        )
    new_definition = version.definition.model_copy(update=updates)
    return version.model_copy(update={"definition": new_definition, "updated_at": _utc_now()})


def materialise_to_experiments_dir(version: ExperimentVersion, experiments_dir: Path) -> Path:
    """Writes an APPROVED version's ExperimentDefinition to experiments/ so
    the existing, unchanged discovery/run infrastructure
    (zeroshield.experiments.discovery, the CLI/dashboard/API) picks it up -
    Step 4's "generated experiments must still map into the trusted execution
    core," made literal. Only ever called for APPROVED versions (enforced by
    the caller - zeroshield.studio.service - not re-checked here, since this
    function's only job is the file write)."""
    experiments_dir.mkdir(parents=True, exist_ok=True)
    path = experiments_dir / f"{version.experiment_id}.json"
    path.write_text(version.definition.model_dump_json(indent=2), encoding="utf-8")
    return path
