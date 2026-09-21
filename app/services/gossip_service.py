from __future__ import annotations

import asyncio
import contextlib
import random
from time import time

import httpx

from app.core.config import Settings
from app.core.signing import compute_signature
from app.repositories.rate_limit_repository import DistributedRateLimitRepository


class GossipService:
    def __init__(self, repository: DistributedRateLimitRepository, settings: Settings) -> None:
        self.repository = repository
        self.settings = settings
        self._task: asyncio.Task[None] | None = None
        self._janitor_task: asyncio.Task[None] | None = None
        self._stopped = asyncio.Event()
        self._last_envelope: dict[str, object] | None = None

    async def start(self) -> None:
        if self._task is not None:
            return
        self._stopped.clear()
        self._task = asyncio.create_task(self._gossip_loop())
        self._janitor_task = asyncio.create_task(self._janitor_loop())

    async def stop(self) -> None:
        self._stopped.set()
        tasks = [task for task in (self._task, self._janitor_task) if task is not None]
        for task in tasks:
            task.cancel()
        for task in tasks:
            with contextlib.suppress(asyncio.CancelledError):
                await task
        self._task = None
        self._janitor_task = None

    async def ingest_envelope(
        self,
        source_node_id: str,
        snapshot: dict[str, dict[str, dict[str, float | int]]],
        received_at: float,
    ) -> None:
        self._last_envelope = {
            "source_node_id": source_node_id,
            "received_at": received_at,
            "version": 1,
        }
        await self.repository.merge_snapshot(snapshot, received_at=received_at)

    async def local_snapshot(self) -> dict[str, dict[str, dict[str, float | int]]]:
        return await self.repository.snapshot()

    def node_count(self) -> int:
        return 1 + len(self.settings.peer_urls)

    def gossip_enabled(self) -> bool:
        return bool(self.settings.peer_urls)

    def last_envelope(self) -> dict[str, object] | None:
        return self._last_envelope

    async def _gossip_loop(self) -> None:
        async with httpx.AsyncClient(timeout=2.0) as client:
            while not self._stopped.is_set():
                await self._gossip_once(client)
                try:
                    await asyncio.wait_for(self._stopped.wait(), timeout=self.settings.gossip_interval_seconds)
                except asyncio.TimeoutError:
                    continue

    async def _janitor_loop(self) -> None:
        while not self._stopped.is_set():
            await self.repository.janitor()
            try:
                await asyncio.wait_for(self._stopped.wait(), timeout=60.0)
            except asyncio.TimeoutError:
                continue

    async def _gossip_once(self, client: httpx.AsyncClient) -> None:
        peers = list(self.settings.peer_urls)
        if not peers:
            return
        fanout = min(self.settings.gossip_fanout, len(peers))
        chosen_peers = random.sample(peers, fanout)
        snapshot = await self.repository.snapshot()
        timestamp = time()
        envelope = {
            "node_id": self.settings.node_id,
            "timestamp": timestamp,
            "version": 1,
            "snapshot": snapshot,
        }
        # Add HMAC signature
        envelope["signature"] = compute_signature(
            self.settings.node_id,
            timestamp,
            1,
            snapshot,
            self.settings.gossip_secret_key
        )
        for peer in chosen_peers:
            try:
                await client.post(f"{peer.rstrip('/')}/internal/gossip/sync", json=envelope)
            except httpx.HTTPError:
                continue
