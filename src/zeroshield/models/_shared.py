import re
from pathlib import Path
from typing import Annotated

from pydantic import Field

_DRIVE_LETTER_RE = re.compile(r"^[A-Za-z]:[\\/]")


def is_unsafe_relative_path(path: Path) -> bool:
    if path.is_absolute() or _DRIVE_LETTER_RE.match(str(path)) or str(path).startswith(("/", "\\")):
        return True
    return ".." in path.parts

EXPERIMENT_ID_PATTERN = r"^ZC-(VPN|TELECOM)-EXP-\d{3,}$"
RUN_ID_PATTERN = r"^RUN-\d{3,}$"
CVE_ID_PATTERN = r"^CVE-\d{4}-\d{4,7}$"
STRATEGY_ID_PATTERN = r"^[a-z][a-z0-9_]*$"
SHA256_PATTERN = r"^[0-9a-f]{64}$"
GIT_COMMIT_PATTERN = r"^[0-9a-f]{7,40}$"
SAFETY_RULE_ID_PATTERN = r"^SAFE-\d{3}$"

ExperimentId = Annotated[str, Field(pattern=EXPERIMENT_ID_PATTERN)]
RunId = Annotated[str, Field(pattern=RUN_ID_PATTERN)]
CveId = Annotated[str, Field(pattern=CVE_ID_PATTERN)]
StrategyId = Annotated[str, Field(pattern=STRATEGY_ID_PATTERN, min_length=1)]
Sha256Hex = Annotated[str, Field(pattern=SHA256_PATTERN)]
GitCommitHex = Annotated[str, Field(pattern=GIT_COMMIT_PATTERN)]
SafetyRuleId = Annotated[str, Field(pattern=SAFETY_RULE_ID_PATTERN)]
Rate = Annotated[float, Field(ge=0.0, le=1.0)]
