from collections.abc import Callable
from datetime import UTC, datetime

from zeroshield.models import ExperimentDefinition, PolicyDecision
from zeroshield.policies import rules
from zeroshield.policies.execution_context import ExecutionContext

RuleCheck = Callable[[ExperimentDefinition, ExecutionContext], tuple[bool, str | None]]

_RULES: list[tuple[str, RuleCheck]] = [
    ("SAFE-001", rules.check_safe_001_external_targeting),
    ("SAFE-002", rules.check_safe_002_input_classification),
    ("SAFE-003", rules.check_safe_003_weaponised_payloads),
    ("SAFE-004", rules.check_safe_004_approval_status),
]


def _utc_now() -> datetime:
    return datetime.now(UTC)


class SafetyPolicy:
    """Policy Object per SRS §4.2: evaluates SAFE-001..004 before an experiment may run."""

    POLICY_VERSION = "1.0.0"

    def evaluate(
        self,
        experiment: ExperimentDefinition,
        *,
        execution_context: ExecutionContext = ExecutionContext.EXPERIMENT_RUN,
        clock: Callable[[], datetime] = _utc_now,
    ) -> PolicyDecision:
        rule_results: dict[str, bool] = {}
        reasons: list[str] = []
        for rule_id, check in _RULES:
            passed, reason = check(experiment, execution_context)
            rule_results[rule_id] = passed
            if not passed and reason is not None:
                reasons.append(reason)

        return PolicyDecision(
            allowed=all(rule_results.values()),
            evaluated_at=clock(),
            rule_results=rule_results,
            reasons=reasons,
            policy_version=self.POLICY_VERSION,
        )
