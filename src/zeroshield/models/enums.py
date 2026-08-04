from enum import Enum


class Domain(str, Enum):
    VPN = "VPN"
    TELECOM = "TELECOM"


class SafetyLevel(str, Enum):
    SYNTHETIC_ONLY = "SYNTHETIC_ONLY"


class ApprovalStatus(str, Enum):
    DRAFT = "draft"
    PENDING_REVIEW = "pending_review"
    APPROVED = "approved"
    REVISION_REQUIRED = "revision_required"
    REJECTED = "rejected"
    CLOSED = "closed"


class InputClassification(str, Enum):
    SYNTHETIC = "synthetic"
    BENIGN = "benign"
    EXPLICITLY_AUTHORIZED = "explicitly_authorized"


class RootCauseCategory(str, Enum):
    MEMORY_SAFETY_FAILURE = "memory_safety_failure"
    PARSER_MESSAGE_HANDLING_FAILURE = "parser_message_handling_failure"
    INPUT_VALIDATION_FAILURE = "input_validation_failure"
    AUTHENTICATION_LOGIC_ERROR = "authentication_logic_error"
    AUTHENTICATION_LOGIC_FLAW = "authentication_logic_flaw"
    AUTHORIZATION_ACCESS_CONTROL_FAILURE = "authorization_access_control_failure"
    INJECTION_FLAW = "injection_flaw"
    UNSAFE_COMMAND_OR_CODE_EXECUTION = "unsafe_command_or_code_execution"


class ZeroClickRelevance(str, Enum):
    HIGH = "High"
    MEDIUM = "Medium"
    LOW = "Low"


class TestCaseCategory(str, Enum):
    __test__ = False  # not a pytest test class despite the name
    VALID = "valid"
    MALFORMED = "malformed"
    BOUNDARY = "boundary"


class Decision(str, Enum):
    ACCEPTED = "accepted"
    BLOCKED = "blocked"


class RunMode(str, Enum):
    BASELINE = "baseline"
    MITIGATED = "mitigated"


class RunStatus(str, Enum):
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"


class MetricName(str, Enum):
    BLOCK_RATE = "block_rate"
    VALID_ACCEPTANCE_RATE = "valid_acceptance_rate"
    FALSE_POSITIVE_RATE = "false_positive_rate"
    FALSE_NEGATIVE_RATE = "false_negative_rate"
    PARSER_REACH_RATE = "parser_reach_rate"
    MEAN_LATENCY_MS = "mean_latency_ms"
    LOG_COMPLETENESS_RATE = "log_completeness_rate"
