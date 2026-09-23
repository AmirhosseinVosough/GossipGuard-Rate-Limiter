from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Request, status
from fastapi.concurrency import run_in_threadpool
from fastapi.security import OAuth2PasswordRequestForm

from app.core.security import get_auth_service, get_current_user
from app.models.user import User
from app.services.auth_service import AuthService

router = APIRouter(prefix="/auth", tags=["auth"])


@router.post("/token")
async def login_for_access_token(
    form_data: OAuth2PasswordRequestForm = Depends(),
    auth_service: AuthService = Depends(get_auth_service),
) -> dict[str, str]:
    # bcrypt at cost 12 takes roughly 350ms, and both the hit and miss paths run it
    # so that response time does not reveal which usernames exist. Calling it inline
    # would stall the event loop for that whole time, blocking every other request
    # on this node, and /auth/token is unauthenticated.
    user = await run_in_threadpool(
        auth_service.authenticate_user, form_data.username, form_data.password
    )
    if user is None:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Incorrect username or password")

    access_token = auth_service.create_access_token(user)
    return {"access_token": access_token, "token_type": "bearer"}


@router.get("/me")
async def read_me(current_user: User = Depends(get_current_user)) -> dict[str, str]:
    return {
        "username": current_user.username,
        "user_id": current_user.user_id,
        "email": current_user.email,
        "role": current_user.role.value,
    }
