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

from pathlib import Path
from typing import Annotated

from fastapi import Depends, HTTPException

from zeroshield.models import ExperimentDefinition
from zeroshield.services import experiment_service


def get_experiments_dir() -> Path:
    return Path.cwd() / "experiments"


def get_results_root() -> Path:
    return Path.cwd() / "results"


def get_experiment(
    experiment_id: str,
    experiments_dir: Annotated[Path, Depends(get_experiments_dir)],
) -> ExperimentDefinition:
    discovery = experiment_service.list_experiments(experiments_dir)
    for candidate in discovery.experiments:
        if candidate.experiment_id == experiment_id:
            return candidate
    raise HTTPException(
        status_code=404,
        detail={
            "error": "experiment_not_found",
            "detail": f"no experiment with id '{experiment_id}'",
        },
    )
