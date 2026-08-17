"""Shared HTTP fetch helper for every connector: timeout, retry/backoff, a
descriptive User-Agent (Step 3), and response-shape validation, since external
data is always untrusted (Step 3). No connector talks to `httpx` directly
outside this module, so every source gets the same defensive behaviour.
"""

import time
from typing import Any

import httpx

_USER_AGENT = "ZeroShield-ThreatIntel/1.0 (+https://github.com/raihamariam/ZeroShield; research/defensive use)"
_MAX_RESPONSE_BYTES = 25 * 1024 * 1024  # 25MB - generous for a JSON page/catalog, still bounded
_RETRYABLE_STATUS_CODES = frozenset({429, 500, 502, 503, 504})


class ConnectorFetchError(Exception):
    """Raised when a connector cannot obtain usable data from its upstream
    source - network failure, exhausted retries, a non-2xx/non-retryable
    status, or a response that fails basic shape/size validation. Callers
    (zeroshield.intelligence.sync_service) treat this as a whole-sync failure,
    distinct from an individual record failing normalisation (counted, not
    fatal - see Step 7's fetched/created/updated/unchanged/failed counters)."""


def build_default_client(*, timeout: float = 15.0) -> httpx.Client:
    return httpx.Client(
        timeout=httpx.Timeout(timeout),
        headers={"User-Agent": _USER_AGENT, "Accept": "application/json"},
    )


def fetch_json(
    client: httpx.Client,
    url: str,
    *,
    params: dict[str, Any] | None = None,
    headers: dict[str, str] | None = None,
    max_retries: int = 3,
    backoff_seconds: float = 1.0,
    sleep: Any = time.sleep,
) -> Any:
    """GETs `url`, retrying transient failures (connection errors, 429/5xx)
    with exponential backoff; never retries a non-retryable 4xx (bad request,
    not found, forbidden) - those are treated as an immediate, permanent
    failure for this fetch. Validates the response is well-formed JSON within
    a bounded size before returning it - callers still must not trust the
    *content* (field types/ranges), only that basic transport-level shape
    checks passed here.
    """
    last_error: Exception | None = None
    for attempt in range(max_retries + 1):
        try:
            response = client.get(url, params=params, headers=headers)
        except httpx.TransportError as exc:
            last_error = exc
        else:
            if response.status_code < 300:
                content_length = len(response.content)
                if content_length > _MAX_RESPONSE_BYTES:
                    raise ConnectorFetchError(
                        f"response from {url} exceeded the {_MAX_RESPONSE_BYTES}-byte safety "
                        f"limit ({content_length} bytes) - refusing to parse"
                    )
                try:
                    return response.json()
                except ValueError as exc:
                    raise ConnectorFetchError(f"response from {url} was not valid JSON: {exc}") from exc
            if response.status_code not in _RETRYABLE_STATUS_CODES:
                raise ConnectorFetchError(
                    f"request to {url} failed with non-retryable status {response.status_code}: "
                    f"{response.text[:200]!r}"
                )
            last_error = ConnectorFetchError(
                f"request to {url} failed with retryable status {response.status_code}"
            )

        if attempt < max_retries:
            sleep(backoff_seconds * (2**attempt))

    raise ConnectorFetchError(
        f"request to {url} failed after {max_retries + 1} attempts: {last_error}"
    ) from last_error
