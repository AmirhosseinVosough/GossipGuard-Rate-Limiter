from __future__ import annotations

import asyncio
from time import time


def is_fresh(timestamp: float, max_skew_seconds: float, now: float | None = None) -> bool:
    current_time = time() if now is None else now
    return abs(timestamp - current_time) <= max_skew_seconds


class ReplayGuard:
    """Remembers recently accepted signatures so a captured envelope cannot be resent.

    Entries live exactly as long as the freshness window, because anything older
    is already refused by is_fresh and need not be remembered.
    """

    def __init__(self, window_seconds: float) -> None:
        self.window_seconds = window_seconds
        self._lock = asyncio.Lock()
        self._seen: dict[str, float] = {}

    async def accept(self, signature: str, now: float | None = None) -> bool:
        current_time = time() if now is None else now
        async with self._lock:
            self._prune_locked(current_time)
            if signature in self._seen:
                return False
            self._seen[signature] = current_time + self.window_seconds
            return True

    async def size(self, now: float | None = None) -> int:
        current_time = time() if now is None else now
        async with self._lock:
            self._prune_locked(current_time)
            return len(self._seen)

    def _prune_locked(self, current_time: float) -> None:
        expired = [key for key, expires_at in self._seen.items() if expires_at <= current_time]
        for key in expired:
            del self._seen[key]
