from __future__ import annotations

from collections.abc import Callable

from fastapi import Depends, HTTPException, Request, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

from app.mappings.permissions import ROLE_PERMISSIONS
from app.models.enums import Permission, Role
from app.models.user import User
from app.services.auth_service import AuthService


security = HTTPBearer(auto_error=False)


def get_auth_service(request: Request) -> AuthService:
    return request.app.state.auth_service


def _extract_bearer_token(authorization: str | None) -> str | None:
    if not authorization:
        return None
    prefix = "Bearer "
    if not authorization.startswith(prefix):
        return None
    token = authorization[len(prefix) :].strip()
    return token or None


def _resolve_token(
    request: Request,
    credentials: HTTPAuthorizationCredentials | None = None,
) -> str | None:
    if isinstance(credentials, HTTPAuthorizationCredentials):
        return credentials.credentials.strip() or None
    return _extract_bearer_token(request.headers.get("authorization"))


def _resolve_user_from_request(request: Request) -> User | None:
    principal = getattr(request.state, "principal", None)
    if isinstance(principal, User):
        return principal

    token = _extract_bearer_token(request.headers.get("authorization"))
    if token is None:
        return None

    user = request.app.state.auth_service.get_user_from_token(token)
    if user is not None:
        request.state.principal = user
    return user


def get_current_user(
    request: Request,
    credentials: HTTPAuthorizationCredentials | None = Depends(security),
    auth_service: AuthService = Depends(get_auth_service),
) -> User:
    principal = getattr(request.state, "principal", None)
    if isinstance(principal, User):
        return principal

    token = _resolve_token(request, credentials)

    if token is None:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Missing bearer token")

    user = auth_service.get_user_from_token(token)
    if user is None:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid or expired token")

    request.state.principal = user
    return user


def get_current_user_from_request(request: Request) -> User | None:
    return _resolve_user_from_request(request)


def get_admin_user(current_user: User = Depends(get_current_user)) -> User:
    if current_user.role != Role.ADMIN:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Admin access required")
    return current_user


def require_permissions(*required_permissions: Permission) -> Callable[[User], User]:
    def dependency(current_user: User = Depends(get_current_user)) -> User:
        user = current_user
        allowed_permissions = ROLE_PERMISSIONS[user.role]
        missing_permissions = [permission for permission in required_permissions if permission not in allowed_permissions]
        if missing_permissions:
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Insufficient permissions")
        return user

    return dependency
