"""Asset inventory routes (V2 Phase 5, Step 7). Thin wrappers over
zeroshield.assurance.repository.AssuranceRepository - no matching logic
duplicated here beyond what list_potentially_affected_assets already does.
"""

from datetime import UTC, datetime
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException

from zeroshield.api.dependencies import (
    CurrentUser,
    get_assurance_repository,
    get_audit_repository,
    get_request_id,
    require_role,
)
from zeroshield.api.schemas import (
    AffectedAssetListResponse,
    AssetListResponse,
    AssetResponse,
    CreateAssetRequest,
    UpdateAssetRequest,
)
from zeroshield.assurance.models import Asset
from zeroshield.assurance.repository import AssuranceRepository
from zeroshield.audit.models import Action
from zeroshield.audit.repository import AuditRepository
from zeroshield.auth.models import Role, User

router = APIRouter(tags=["assets"])

# The brief assigns asset-inventory maintenance to no single role explicitly
# (Step 2 lists it under neither RESEARCHER nor ADMIN by name) - treated as a
# RESEARCHER-maintainable part of the research context (an analyst
# registering the asset a CVE they're investigating actually affects),
# with ADMIN retaining the same access as everywhere else.
_ASSET_WRITE_ROLES = (Role.RESEARCHER, Role.ADMIN)


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
    _current_user: CurrentUser,
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
    request: CreateAssetRequest,
    repository: Annotated[AssuranceRepository, Depends(get_assurance_repository)],
    audit_repository: Annotated[AuditRepository, Depends(get_audit_repository)],
    request_id: Annotated[str | None, Depends(get_request_id)],
    current_user: Annotated[User, Depends(require_role(*_ASSET_WRITE_ROLES))],
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
    audit_repository.record(
        actor_user_id=current_user.user_id, actor_username=current_user.username, actor_role=current_user.role.value,
        action=Action.ASSET_CREATED, target_type="asset", target_id=asset.asset_id, request_id=request_id,
        metadata={"vendor": asset.vendor, "product": asset.product},
    )
    return _response(asset)


@router.get("/assets/{asset_id}", response_model=AssetResponse, summary="Get one asset")
def get_asset(
    asset_id: str, repository: Annotated[AssuranceRepository, Depends(get_assurance_repository)],
    _current_user: CurrentUser,
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
    audit_repository: Annotated[AuditRepository, Depends(get_audit_repository)],
    request_id: Annotated[str | None, Depends(get_request_id)],
    current_user: Annotated[User, Depends(require_role(*_ASSET_WRITE_ROLES))],
) -> AssetResponse:
    updates = {k: v for k, v in request.model_dump().items() if v is not None}
    asset = repository.update_asset(asset_id, **updates)
    if asset is None:
        raise HTTPException(status_code=404, detail={"error": "asset_not_found", "detail": f"no asset '{asset_id}'"})
    audit_repository.record(
        actor_user_id=current_user.user_id, actor_username=current_user.username, actor_role=current_user.role.value,
        action=Action.ASSET_UPDATED, target_type="asset", target_id=asset_id, request_id=request_id,
        metadata={"fields_changed": sorted(updates)},
    )
    return _response(asset)


@router.get(
    "/vulnerabilities/{cve_id}/affected-assets",
    response_model=AffectedAssetListResponse,
    summary="Assets potentially affected by a CVE",
    description="Deterministic vendor/product match against the asset inventory - never AI, "
    "never a fuzzy guess.",
)
def get_affected_assets(
    cve_id: str, repository: Annotated[AssuranceRepository, Depends(get_assurance_repository)],
    _current_user: CurrentUser,
) -> AffectedAssetListResponse:
    assets = repository.list_potentially_affected_assets(cve_id)
    return AffectedAssetListResponse(cve_id=cve_id, assets=[_response(a) for a in assets])
