from __future__ import annotations

from app.core.auth import (
    ABSENT_USER_PASSWORD_HASH,
    _create_access_token,
    decode_access_token,
    verify_password,
)
from app.core.config import Settings
from app.repositories.auth_repository import AuthRepository
from app.models.user import User


class AuthService:
    def __init__(self, repository: AuthRepository, settings: Settings) -> None:
        self.repository = repository
        self.settings = settings

    def authenticate_user(self, username: str, password: str) -> User | None:
        entry = self.repository.get_user(username)
        if entry is None:
            verify_password(password, ABSENT_USER_PASSWORD_HASH)
            return None
        if not verify_password(password, entry.hashed_password):
            return None
        return entry.user

    def get_user_from_token(self, token: str) -> User | None:
        payload = decode_access_token(token, self.settings)
        if payload is None:
            return None

        subject = payload.get("sub")
        if not isinstance(subject, str):
            return None

        entry = self.repository.get_user(subject)
        return None if entry is None else entry.user

    def create_access_token(self, user: User) -> str:
        token, _ = _create_access_token(user.username, self.settings)
        return token

    def list_users(self) -> list[User]:
        return self.repository.list_users()
