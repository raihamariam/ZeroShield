from fastapi import APIRouter
from fastapi.responses import Response
from prometheus_client import CONTENT_TYPE_LATEST, generate_latest

router = APIRouter(tags=["observability"])


@router.get(
    "/metrics",
    summary="Prometheus operational metrics",
    description="Request counts/latency, submitted-run counts. Operational only - never a "
    "substitute for the scientific evidence under results/ or GET /experiments/{id}/results.",
)
def get_metrics() -> Response:
    return Response(content=generate_latest(), media_type=CONTENT_TYPE_LATEST)
