from typing import Any

from zeroshield.models.enums import Decision
from zeroshield.strategies.base import ProcessingStrategy
from zeroshield.strategies.outcome import StrategyOutcome

# Synthetic test-harness thresholds (this experiment's own assumptions), not vendor-sourced limits
MAX_PATH_LENGTH = 256
MAX_BODY_LENGTH = 8192
MAX_HEADER_VALUE_LENGTH = 512
MAX_QUERY_PARAM_VALUE_LENGTH = 512
ALLOWED_ENCODINGS = {"utf-8", "ascii"}
PATH_TRAVERSAL_MARKERS = ("..", "%2e%2e", "%00")


def _as_list(value: Any) -> list[Any]:
    return value if isinstance(value, list) else []


class StrictSchemaCanonicalisationMitigation(ProcessingStrategy):
    """Strict pre-auth VPN request validation (schema/length/type/duplicate/canonicalisation), per SRS §6.1."""

    strategy_id = "strict_schema_canonicalisation_mitigation"

    def process(self, input_data: dict[str, Any]) -> StrategyOutcome:
        if self._is_malformed(input_data):
            return StrategyOutcome(decision=Decision.BLOCKED, parser_reached=False, logged=True)
        return StrategyOutcome(decision=Decision.ACCEPTED, parser_reached=True, logged=False)

    def _is_malformed(self, input_data: dict[str, Any]) -> bool:
        return (
            self._fails_schema_check(input_data)
            or self._fails_length_checks(input_data)
            or self._fails_duplicate_field_check(input_data)
            or self._fails_type_check(input_data)
            or self._fails_path_canonicalisation_check(input_data)
        )

    @staticmethod
    def _fails_schema_check(input_data: dict[str, Any]) -> bool:
        method = input_data.get("method")
        path = input_data.get("path")
        if not isinstance(method, str) or not method:
            return True
        return not isinstance(path, str) or not path

    @staticmethod
    def _fails_length_checks(input_data: dict[str, Any]) -> bool:
        path = input_data.get("path")
        if isinstance(path, str) and len(path) > MAX_PATH_LENGTH:
            return True

        declared = input_data.get("declared_content_length")
        actual = input_data.get("actual_body_length")
        if not isinstance(declared, int) or declared < 0 or declared > MAX_BODY_LENGTH:
            return True
        if declared != actual:
            return True

        headers = _as_list(input_data.get("headers"))
        for pair in headers:
            if (
                isinstance(pair, list | tuple)
                and len(pair) == 2
                and len(str(pair[1])) > MAX_HEADER_VALUE_LENGTH
            ):
                return True

        query_params = input_data.get("query_params", {})
        if isinstance(query_params, dict):
            for value in query_params.values():
                if len(str(value)) > MAX_QUERY_PARAM_VALUE_LENGTH:
                    return True

        return False

    @staticmethod
    def _fails_duplicate_field_check(input_data: dict[str, Any]) -> bool:
        headers = _as_list(input_data.get("headers"))
        keys = [pair[0] for pair in headers if isinstance(pair, list | tuple) and len(pair) == 2]
        return len(set(keys)) != len(keys)

    @staticmethod
    def _fails_type_check(input_data: dict[str, Any]) -> bool:
        encoding = input_data.get("encoding")
        return encoding not in ALLOWED_ENCODINGS

    @staticmethod
    def _fails_path_canonicalisation_check(input_data: dict[str, Any]) -> bool:
        # path type/presence is already guaranteed by _fails_schema_check, which runs first
        lowered = str(input_data.get("path", "")).lower()
        return any(marker in lowered for marker in PATH_TRAVERSAL_MARKERS)
