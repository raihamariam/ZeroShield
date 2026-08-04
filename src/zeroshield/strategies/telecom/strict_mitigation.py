from typing import Any

from zeroshield.models.enums import Decision
from zeroshield.strategies.base import ProcessingStrategy
from zeroshield.strategies.outcome import StrategyOutcome

# Synthetic test-harness thresholds (this experiment's own assumptions), not vendor-sourced limits
MAX_SDP_ATTR_VALUE_LENGTH = 256
MAX_BODY_LENGTH = 4096
MANDATORY_HEADERS = ("Call-ID", "From", "To")
LEGAL_TRANSITIONS = {("INIT", "INVITE"), ("RINGING", "ACK"), ("ESTABLISHED", "BYE")}


def _as_list(value: Any) -> list[Any]:
    return value if isinstance(value, list) else []


class StrictGrammarStateMachineMitigation(ProcessingStrategy):
    """Strict Telecom session-setup validation (fields/size/duplicate/sequence/state), per SRS §6.2."""

    strategy_id = "strict_grammar_state_machine_mitigation"

    def process(self, input_data: dict[str, Any]) -> StrategyOutcome:
        if self._is_malformed(input_data):
            return StrategyOutcome(decision=Decision.BLOCKED, parser_reached=False, logged=True)
        return StrategyOutcome(decision=Decision.ACCEPTED, parser_reached=True, logged=False)

    def _is_malformed(self, input_data: dict[str, Any]) -> bool:
        return (
            self._fails_mandatory_field_check(input_data)
            or self._fails_duplicate_header_check(input_data)
            or self._fails_size_limit_checks(input_data)
            or self._fails_sequence_validation(input_data)
            or self._fails_state_machine_check(input_data)
        )

    @staticmethod
    def _fails_mandatory_field_check(input_data: dict[str, Any]) -> bool:
        headers = _as_list(input_data.get("headers"))
        keys = {pair[0] for pair in headers if isinstance(pair, list | tuple) and len(pair) == 2}
        return not all(name in keys for name in MANDATORY_HEADERS)

    @staticmethod
    def _fails_duplicate_header_check(input_data: dict[str, Any]) -> bool:
        headers = _as_list(input_data.get("headers"))
        keys = [pair[0] for pair in headers if isinstance(pair, list | tuple) and len(pair) == 2]
        return len(set(keys)) != len(keys)

    @staticmethod
    def _fails_size_limit_checks(input_data: dict[str, Any]) -> bool:
        declared = input_data.get("declared_body_length")
        actual = input_data.get("actual_body_length")
        if not isinstance(declared, int) or declared < 0 or declared > MAX_BODY_LENGTH:
            return True
        if declared != actual:
            return True

        sdp_attributes = _as_list(input_data.get("sdp_attributes"))
        for pair in sdp_attributes:
            if (
                isinstance(pair, list | tuple)
                and len(pair) == 2
                and len(str(pair[1])) > MAX_SDP_ATTR_VALUE_LENGTH
            ):
                return True
        return False

    @staticmethod
    def _fails_sequence_validation(input_data: dict[str, Any]) -> bool:
        sequence_number = input_data.get("sequence_number")
        expected_sequence_number = input_data.get("expected_sequence_number")
        return sequence_number != expected_sequence_number

    @staticmethod
    def _fails_state_machine_check(input_data: dict[str, Any]) -> bool:
        method = input_data.get("method")
        session_state = input_data.get("session_state")
        return (session_state, method) not in LEGAL_TRANSITIONS
