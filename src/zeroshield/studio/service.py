"""Thin application-service layer over builder/approval/repository - the one
place the API/CLI actually calls, matching zeroshield.services.
experiment_service's role for the trusted core. No workflow rule is
duplicated here; this only sequences builder -> repository and
approval.transition() -> repository -> (on APPROVED) materialisation.
"""

from pathlib import Path

from zeroshield.models import ExperimentVersion
from zeroshield.models.enums import ExperimentVersionStatus
from zeroshield.studio.approval import transition
from zeroshield.studio.builder import (
    build_experiment_draft,
    edit_draft,
    materialise_to_experiments_dir,
)
from zeroshield.studio.repository import ExperimentVersionRepository


class ExperimentVersionNotFoundError(Exception):
    pass


def _get_or_raise(repository: ExperimentVersionRepository, version_id: str) -> ExperimentVersion:
    version = repository.get_version(version_id)
    if version is None:
        raise ExperimentVersionNotFoundError(f"no experiment version with id '{version_id}'")
    return version


def create_draft(repository: ExperimentVersionRepository, **builder_kwargs: object) -> ExperimentVersion:
    version = build_experiment_draft(**builder_kwargs)  # type: ignore[arg-type]
    repository.save_version(version)
    return version


def edit(repository: ExperimentVersionRepository, version_id: str, **updates: object) -> ExperimentVersion:
    version = _get_or_raise(repository, version_id)
    updated = edit_draft(version, **updates)
    repository.save_version(updated)
    return updated


def apply_transition(
    repository: ExperimentVersionRepository,
    version_id: str,
    target: ExperimentVersionStatus,
    *,
    actor: str,
    reason: str | None = None,
    experiments_dir: Path | None = None,
) -> ExperimentVersion:
    version = _get_or_raise(repository, version_id)
    new_version, decision = transition(version, target, actor=actor, reason=reason)
    repository.save_version(new_version)
    repository.append_approval_decision(decision)
    if target is ExperimentVersionStatus.APPROVED and experiments_dir is not None:
        materialise_to_experiments_dir(new_version, experiments_dir)
    return new_version


def submit_for_review(
    repository: ExperimentVersionRepository, version_id: str, *, actor: str, reason: str | None = None
) -> ExperimentVersion:
    return apply_transition(repository, version_id, ExperimentVersionStatus.READY_FOR_REVIEW, actor=actor, reason=reason)


def start_review(
    repository: ExperimentVersionRepository, version_id: str, *, actor: str, reason: str | None = None
) -> ExperimentVersion:
    return apply_transition(repository, version_id, ExperimentVersionStatus.UNDER_REVIEW, actor=actor, reason=reason)


def approve(
    repository: ExperimentVersionRepository,
    version_id: str,
    *,
    actor: str,
    reason: str | None = None,
    experiments_dir: Path = Path("experiments"),
) -> ExperimentVersion:
    return apply_transition(
        repository, version_id, ExperimentVersionStatus.APPROVED, actor=actor, reason=reason,
        experiments_dir=experiments_dir,
    )


def reject(
    repository: ExperimentVersionRepository, version_id: str, *, actor: str, reason: str
) -> ExperimentVersion:
    return apply_transition(repository, version_id, ExperimentVersionStatus.REJECTED, actor=actor, reason=reason)


def retire(
    repository: ExperimentVersionRepository, version_id: str, *, actor: str, reason: str | None = None
) -> ExperimentVersion:
    return apply_transition(repository, version_id, ExperimentVersionStatus.RETIRED, actor=actor, reason=reason)


def next_version_number(repository: ExperimentVersionRepository, experiment_id: str) -> int:
    return repository.latest_version_number(experiment_id) + 1
