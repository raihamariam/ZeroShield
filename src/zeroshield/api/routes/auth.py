"""Authentication and user-management routes (V2 Phase 6, Steps 1-2).

POST /auth/login is the only route in this entire API that does not require
an existing session - every other route (including every other route in
this file) depends on get_current_user, directly or via require_role.
"""

import os
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Request, Response

from zeroshield.api.dependencies import (
    SESSION_COOKIE_NAME,
    CurrentUser,
    get_auth_service,
    get_request_id,
    require_role,
)
from zeroshield.api.schemas import (
    CreateUserRequest,
    LoginRequest,
    LoginResponse,
    UpdateUserActiveRequest,
    UpdateUserRoleRequest,
    UserListResponse,
    UserResponse,
)
from zeroshield.auth.models import Role, User
from zeroshield.auth.passwords import MIN_PASSWORD_LENGTH, hash_password
from zeroshield.auth.repository import UsernameAlreadyExistsError
from zeroshield.auth.service import (
    AccountInactiveError,
    AccountLockedError,
    AuthService,
    InvalidCredentialsError,
)

router = APIRouter(tags=["auth"])

_COOKIE_MAX_AGE_SECONDS = 12 * 60 * 60  # matches zeroshield.auth.service.SESSION_TTL


def _user_response(user: User) -> UserResponse:
    return UserResponse(
        user_id=user.user_id, username=user.username, role=user.role.value, active=user.active,
        created_at=user.created_at.isoformat(), updated_at=user.updated_at.isoformat(),
    )


def _cookie_secure() -> bool:
    """Defaults to False so local HTTP development (localhost, no TLS) can
    actually receive the cookie - a Secure cookie is silently dropped by the
    browser over plain HTTP. Set ZEROSHIELD_SESSION_COOKIE_SECURE=true for
    any real (HTTPS) deployment - see docs/V2_SECURITY.md."""
    return os.environ.get("ZEROSHIELD_SESSION_COOKIE_SECURE", "false").strip().lower() == "true"


@router.post("/auth/login", response_model=LoginResponse, summary="Log in and receive a session cookie")
def login(
    request: LoginRequest,
    http_request: Request,
    response: Response,
    auth_service: Annotated[AuthService, Depends(get_auth_service)],
    request_id: Annotated[str | None, Depends(get_request_id)],
) -> LoginResponse:
    try:
        result = auth_service.login(
            username=request.username, password=request.password,
            ip_address=http_request.client.host if http_request.client else None,
            user_agent=http_request.headers.get("user-agent"), request_id=request_id,
        )
    except AccountLockedError as exc:
        raise HTTPException(
            status_code=423,
            detail={
                "error": "account_locked",
                "detail": f"too many failed login attempts; try again after {exc.locked_until.isoformat()}",
            },
        ) from None
    except AccountInactiveError:
        raise HTTPException(
            status_code=403, detail={"error": "account_inactive", "detail": "this account has been deactivated"}
        ) from None
    except InvalidCredentialsError:
        raise HTTPException(
            status_code=401, detail={"error": "invalid_credentials", "detail": "invalid username or password"}
        ) from None

    response.set_cookie(
        key=SESSION_COOKIE_NAME, value=result.raw_session_token, max_age=_COOKIE_MAX_AGE_SECONDS,
        httponly=True, samesite="lax", secure=_cookie_secure(), path="/",
    )
    return LoginResponse(user=_user_response(result.user))


@router.post("/auth/logout", status_code=204, summary="Log out and invalidate the current session")
def logout(
    http_request: Request,
    response: Response,
    auth_service: Annotated[AuthService, Depends(get_auth_service)],
    request_id: Annotated[str | None, Depends(get_request_id)],
    current_user: CurrentUser,
) -> None:
    session_token = http_request.cookies.get(SESSION_COOKIE_NAME)
    if session_token:
        auth_service.logout(raw_session_token=session_token, actor=current_user, request_id=request_id)
    response.delete_cookie(key=SESSION_COOKIE_NAME, path="/")


@router.get("/auth/me", response_model=UserResponse, summary="The currently authenticated user")
def me(current_user: CurrentUser) -> UserResponse:
    return _user_response(current_user)


# -- User management (ADMIN only, Step 2: "users, integration configuration and system settings") --


@router.get("/users", response_model=UserListResponse, summary="List users (ADMIN only)")
def list_users(
    auth_service: Annotated[AuthService, Depends(get_auth_service)],
    _actor: Annotated[User, Depends(require_role(Role.ADMIN))],
) -> UserListResponse:
    return UserListResponse(users=[_user_response(u) for u in auth_service.list_users()])


@router.post("/users", response_model=UserResponse, status_code=201, summary="Create a user (ADMIN only)")
def create_user(
    request: CreateUserRequest,
    auth_service: Annotated[AuthService, Depends(get_auth_service)],
    request_id: Annotated[str | None, Depends(get_request_id)],
    actor: Annotated[User, Depends(require_role(Role.ADMIN))],
) -> UserResponse:
    try:
        role = Role(request.role)
    except ValueError:
        raise HTTPException(
            status_code=422,
            detail={"error": "invalid_role", "detail": f"'{request.role}' is not a valid role"},
        ) from None
    if len(request.password) < MIN_PASSWORD_LENGTH:
        raise HTTPException(
            status_code=422,
            detail={"error": "weak_password", "detail": f"password must be at least {MIN_PASSWORD_LENGTH} characters"},
        )
    try:
        created = auth_service.create_user(
            username=request.username, password_hash=hash_password(request.password), role=role,
            actor=actor, request_id=request_id,
        )
    except UsernameAlreadyExistsError as exc:
        raise HTTPException(status_code=409, detail={"error": "username_exists", "detail": str(exc)}) from None
    return _user_response(created)


@router.patch("/users/{user_id}/role", response_model=UserResponse, summary="Change a user's role (ADMIN only)")
def update_user_role(
    user_id: str,
    request: UpdateUserRoleRequest,
    auth_service: Annotated[AuthService, Depends(get_auth_service)],
    request_id: Annotated[str | None, Depends(get_request_id)],
    actor: Annotated[User, Depends(require_role(Role.ADMIN))],
) -> UserResponse:
    try:
        role = Role(request.role)
    except ValueError:
        raise HTTPException(
            status_code=422, detail={"error": "invalid_role", "detail": f"'{request.role}' is not a valid role"}
        ) from None
    updated = auth_service.update_user_role(user_id, role=role, actor=actor, request_id=request_id)
    if updated is None:
        raise HTTPException(status_code=404, detail={"error": "user_not_found", "detail": f"no user '{user_id}'"})
    return _user_response(updated)


@router.patch("/users/{user_id}/active", response_model=UserResponse, summary="Activate/deactivate a user (ADMIN only)")
def update_user_active(
    user_id: str,
    request: UpdateUserActiveRequest,
    auth_service: Annotated[AuthService, Depends(get_auth_service)],
    request_id: Annotated[str | None, Depends(get_request_id)],
    actor: Annotated[User, Depends(require_role(Role.ADMIN))],
) -> UserResponse:
    updated = auth_service.set_user_active(user_id, active=request.active, actor=actor, request_id=request_id)
    if updated is None:
        raise HTTPException(status_code=404, detail={"error": "user_not_found", "detail": f"no user '{user_id}'"})
    return _user_response(updated)
