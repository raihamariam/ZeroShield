"""Shared FastAPI dependencies: data-directory resolution and experiment lookup.

get_experiment resolves a path parameter against the set of already-discovered,
already-validated experiment IDs (from experiment_service.list_experiments) and
returns the validated ExperimentDefinition, never the raw client-supplied
string. Every route uses the returned experiment.experiment_id for any
filesystem access - the raw path parameter is only ever compared for
equality against known-good IDs, never used to build a path. This is what
prevents path traversal via the experiment_id path parameter, without
needing a duplicated ID-pattern check here.
"""

import os
from collections.abc import Callable
from pathlib import Path
from typing import Annotated

from fastapi import Depends, HTTPException

from zeroshield.api.messaging import publish_run_job
from zeroshield.experiments import find_experiment
from zeroshield.models import ExperimentDefinition
from zeroshield.services.job_store import JobStore, RunJobMessage


def get_experiments_dir() -> Path:
    return Path.cwd() / "experiments"


def get_results_root() -> Path:
    return Path.cwd() / "results"


def get_jobs_dir() -> Path:
    return Path.cwd() / "jobs"


def get_job_store(jobs_dir: Annotated[Path, Depends(get_jobs_dir)]) -> JobStore:
    return JobStore(jobs_dir)


def get_rabbitmq_url() -> str:
    return os.environ.get("RABBITMQ_URL", "amqp://guest:guest@localhost:5672/")


def get_publisher(
    rabbitmq_url: Annotated[str, Depends(get_rabbitmq_url)],
) -> Callable[[RunJobMessage], None]:
    def publish(message: RunJobMessage) -> None:
        publish_run_job(message, rabbitmq_url=rabbitmq_url)

    return publish


def get_experiment(
    experiment_id: str,
    experiments_dir: Annotated[Path, Depends(get_experiments_dir)],
) -> ExperimentDefinition:
    experiment = find_experiment(experiments_dir, experiment_id)
    if experiment is None:
        raise HTTPException(
            status_code=404,
            detail={
                "error": "experiment_not_found",
                "detail": f"no experiment with id '{experiment_id}'",
            },
        )
    return experiment
