from __future__ import annotations

from dataclasses import dataclass

from app.models.user import User


@dataclass(slots=True, frozen=True)
class AuthEntry:
    user: User
    hashed_password: str


class AuthRepository:
    def __init__(self) -> None:
        # Initialize with empty users dictionary
        # Users must be added via proper user management (e.g., database, admin setup)
        self._users_by_username: dict[str, AuthEntry] = {}

    def get_user(self, username: str) -> AuthEntry | None:
        return self._users_by_username.get(username)

    def list_users(self) -> list[User]:
        return [entry.user for entry in self._users_by_username.values()]

    def add_user(self, username: str, user: User, hashed_password: str) -> None:
        """Add a user to the repository (for testing or admin setup only)."""
        self._users_by_username[username] = AuthEntry(user=user, hashed_password=hashed_password)
