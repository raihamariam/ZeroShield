from enum import Enum


class ExecutionContext(str, Enum):
    LOCAL_UNIT_TEST = "local_unit_test"
    EXPERIMENT_RUN = "experiment_run"
