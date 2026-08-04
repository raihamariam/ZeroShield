from fastapi import APIRouter

from zeroshield.api.schemas import HealthResponse

router = APIRouter(tags=["health"])


@router.get(
    "/health",
    response_model=HealthResponse,
    summary="Health check",
    description="Returns a simple machine-readable indicator that the API process is running.",
)
def get_health() -> HealthResponse:
    return HealthResponse(status="healthy", service="zeroshield")
