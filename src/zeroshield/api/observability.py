"""HTTP request instrumentation middleware.

Uses the matched route TEMPLATE (e.g. "/experiments/{experiment_id}"), never
the raw resolved path, as a Prometheus label - using the raw path would give
every distinct experiment_id (or, worse, every arbitrary probed 404 path) its
own label combination, an unbounded-cardinality footgun. Requests that never
match a route (404s from arbitrary path probing) are grouped under a single
"unmatched" label for the same reason.
"""

import time
from collections.abc import Awaitable, Callable

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import Response

from zeroshield.observability.metrics import API_REQUEST_DURATION_SECONDS, API_REQUESTS_TOTAL


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
