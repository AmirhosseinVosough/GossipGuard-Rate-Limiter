from __future__ import annotations

from app.core.config import Settings
from app.models.enums import Role
from app.models.user import User
from app.repositories.rate_limit_repository import DistributedRateLimitRepository


class RateLimitService:
    def __init__(self, repository: DistributedRateLimitRepository, settings: Settings) -> None:
        self.repository = repository
        self.settings = settings

    def limit_for(self, user: User | None) -> int:
        if user is None:
            return self.settings.anonymous_limit
        if user.role == Role.ADMIN:
            return self.settings.admin_limit
        if user.role == Role.EDITOR:
            return self.settings.editor_limit
        return self.settings.viewer_limit

    async def allow_request(self, user_key: str, user: User | None) -> tuple[bool, int, int]:
        limit = self.limit_for(user)
        allowed, current_total = await self.repository.try_acquire(user_key, limit)
        return allowed, current_total, limit
