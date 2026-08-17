"""HTTP request instrumentation middleware.

Uses the matched route TEMPLATE (e.g. "/experiments/{experiment_id}"), never
the raw resolved path, as a Prometheus label - using the raw path would give
every distinct experiment_id (or, worse, every arbitrary probed 404 path) its
own label combination, an unbounded-cardinality footgun. Requests that never
match a route (404s from arbitrary path probing) are grouped under a single
"unmatched" label for the same reason.
"""

import time
import uuid
from collections.abc import Awaitable, Callable

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import Response

from zeroshield.observability.metrics import API_REQUEST_DURATION_SECONDS, API_REQUESTS_TOTAL

REQUEST_ID_HEADER = "X-Request-ID"


class RequestContextMiddleware(BaseHTTPMiddleware):
    """V2 Phase 6, Steps 3/5: every request gets a correlation ID, available
    to route handlers via `request.state.request_id` (see
    zeroshield.api.dependencies.get_request_id) and echoed back on the
    response so a browser/log line/audit event can all be tied together.
    Reuses an inbound X-Request-ID if the caller already set one (so a
    request proxied through the Next.js web app can carry a
    browser-originated ID all the way through), otherwise generates a fresh
    UUID4 - never trusts the header's *content* for anything beyond
    correlation display (it is never used to look up or authorize anything)."""

    async def dispatch(
        self, request: Request, call_next: Callable[[Request], Awaitable[Response]]
    ) -> Response:
        request_id = request.headers.get(REQUEST_ID_HEADER) or uuid.uuid4().hex
        request.state.request_id = request_id
        response = await call_next(request)
        response.headers[REQUEST_ID_HEADER] = request_id
        return response


class PrometheusMiddleware(BaseHTTPMiddleware):
    async def dispatch(
        self, request: Request, call_next: Callable[[Request], Awaitable[Response]]
    ) -> Response:
        start = time.perf_counter()
        response = await call_next(request)
        duration = time.perf_counter() - start

        route = request.scope.get("route")
        path = getattr(route, "path", None) or "unmatched"

        API_REQUESTS_TOTAL.labels(
            method=request.method, path=path, status_code=str(response.status_code)
        ).inc()
        API_REQUEST_DURATION_SECONDS.labels(method=request.method, path=path).observe(duration)
        return response
