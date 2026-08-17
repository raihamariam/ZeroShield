"""Asset inventory routes (V2 Phase 5, Step 7). Thin wrappers over
zeroshield.assurance.repository.AssuranceRepository - no matching logic
duplicated here beyond what list_potentially_affected_assets already does.
"""

from datetime import UTC, datetime
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException

from zeroshield.api.dependencies import get_assurance_repository
from zeroshield.api.schemas import (
    AffectedAssetListResponse,
    AssetListResponse,
    AssetResponse,
    CreateAssetRequest,
    UpdateAssetRequest,
)
from zeroshield.assurance.models import Asset
from zeroshield.assurance.repository import AssuranceRepository

router = APIRouter(tags=["assets"])


def _response(asset: Asset) -> AssetResponse:
    return AssetResponse(
        asset_id=asset.asset_id, name=asset.name, vendor=asset.vendor, product=asset.product,
        version=asset.version, environment=asset.environment, exposure=asset.exposure,
        criticality=asset.criticality, active=asset.active, created_at=asset.created_at.isoformat(),
        updated_at=asset.updated_at.isoformat(),
    )


@router.get("/assets", response_model=AssetListResponse, summary="List the asset inventory")
def list_assets(
    repository: Annotated[AssuranceRepository, Depends(get_assurance_repository)],
    active: bool | None = None,
    vendor: str | None = None,
) -> AssetListResponse:
    return AssetListResponse(assets=[_response(a) for a in repository.list_assets(active=active, vendor=vendor)])


@router.post(
    "/assets",
    response_model=AssetResponse,
    status_code=201,
    summary="Register an asset",
    description="Step 7's deliberately small inventory - asset ID/name, vendor, product, version, "
    "environment, exposure, criticality, active status. Not a CMDB.",
)
def create_asset(
    request: CreateAssetRequest, repository: Annotated[AssuranceRepository, Depends(get_assurance_repository)]
) -> AssetResponse:
    if repository.get_asset(request.asset_id) is not None:
        raise HTTPException(
            status_code=409, detail={"error": "asset_exists", "detail": f"asset '{request.asset_id}' already exists"}
        )
    now = datetime.now(UTC)
    asset = repository.create_asset(
        Asset(
            asset_id=request.asset_id, name=request.name, vendor=request.vendor, product=request.product,
            version=request.version, environment=request.environment, exposure=request.exposure,
            criticality=request.criticality, active=request.active, created_at=now, updated_at=now,
        )
    )
    return _response(asset)


@router.get("/assets/{asset_id}", response_model=AssetResponse, summary="Get one asset")
def get_asset(
    asset_id: str, repository: Annotated[AssuranceRepository, Depends(get_assurance_repository)]
) -> AssetResponse:
    asset = repository.get_asset(asset_id)
    if asset is None:
        raise HTTPException(status_code=404, detail={"error": "asset_not_found", "detail": f"no asset '{asset_id}'"})
    return _response(asset)


@router.patch("/assets/{asset_id}", response_model=AssetResponse, summary="Update an asset")
def update_asset(
    asset_id: str,
    request: UpdateAssetRequest,
    repository: Annotated[AssuranceRepository, Depends(get_assurance_repository)],
) -> AssetResponse:
    updates = {k: v for k, v in request.model_dump().items() if v is not None}
    asset = repository.update_asset(asset_id, **updates)
    if asset is None:
        raise HTTPException(status_code=404, detail={"error": "asset_not_found", "detail": f"no asset '{asset_id}'"})
    return _response(asset)


@router.get(
    "/vulnerabilities/{cve_id}/affected-assets",
    response_model=AffectedAssetListResponse,
    summary="Assets potentially affected by a CVE",
    description="Deterministic vendor/product match against the asset inventory - never AI, "
    "never a fuzzy guess.",
)
def get_affected_assets(
    cve_id: str, repository: Annotated[AssuranceRepository, Depends(get_assurance_repository)]
) -> AffectedAssetListResponse:
    assets = repository.list_potentially_affected_assets(cve_id)
    return AffectedAssetListResponse(cve_id=cve_id, assets=[_response(a) for a in assets])
