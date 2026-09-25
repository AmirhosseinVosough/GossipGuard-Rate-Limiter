from __future__ import annotations

import asyncio

from app.repositories.rate_limit_repository import DistributedRateLimitRepository


def test_repository_merges_by_node_and_expires_old_records() -> None:
    async def run() -> None:
        repository = DistributedRateLimitRepository(node_id="node-a", window_seconds=10)

        await repository.try_acquire("user-1", limit=10, now=100.0)
        await repository.merge_snapshot(
            {
                "user-1": {
                    "node-b": {"count": 2, "window": 10, "expires_at": 110.0},
                }
            },
            now=100.0,
        )

        assert await repository.current_total("user-1", now=100.0) == 3

        await repository.janitor(now=111.0)
        assert await repository.current_total("user-1", now=111.0) == 0

    asyncio.run(run())


def test_a_client_under_the_limit_is_never_blocked() -> None:
    """The bug this replaces: every hit pushed the expiry back a full window, so
    a client sending 2 a minute against a limit of 3 was blocked by its fourth
    request and never let back in."""

    async def run() -> None:
        repository = DistributedRateLimitRepository(node_id="node-a", window_seconds=60)

        for second in range(0, 600, 25):
            allowed, _ = await repository.try_acquire("steady", limit=3, now=float(second))
            assert allowed, f"blocked at t={second}s"

    asyncio.run(run())


def test_a_blocked_client_gets_back_in_when_the_window_rolls_over() -> None:
    async def run() -> None:
        repository = DistributedRateLimitRepository(node_id="node-a", window_seconds=60)

        results = [(await repository.try_acquire("burst", limit=3, now=float(second)))[0] for second in range(5)]
        assert results == [True, True, True, False, False]

        for second in range(14, 60, 10):
            allowed, _ = await repository.try_acquire("burst", limit=3, now=float(second))
            assert not allowed

        allowed, total = await repository.try_acquire("burst", limit=3, now=64.0)
        assert allowed
        assert total == 1

    asyncio.run(run())


def test_refused_requests_are_not_counted() -> None:
    async def run() -> None:
        repository = DistributedRateLimitRepository(node_id="node-a", window_seconds=60)

        for second in range(20):
            await repository.try_acquire("hammer", limit=3, now=float(second))

        assert await repository.current_total("hammer", now=20.0) == 3

    asyncio.run(run())


def test_the_count_resets_at_the_window_boundary() -> None:
    async def run() -> None:
        repository = DistributedRateLimitRepository(node_id="node-a", window_seconds=60)

        await repository.try_acquire("edge", limit=3, now=59.0)
        await repository.try_acquire("edge", limit=3, now=59.9)
        allowed, total = await repository.try_acquire("edge", limit=3, now=60.0)

        assert allowed
        assert total == 1

    asyncio.run(run())


def test_gossip_from_a_previous_window_does_not_overwrite_the_current_one() -> None:
    async def run() -> None:
        repository = DistributedRateLimitRepository(node_id="node-a", window_seconds=60)
        current = {"count": 1, "window": 2, "expires_at": 180.0, "updated_at": 125.0}
        late = {"count": 40, "window": 1, "expires_at": 120.0, "updated_at": 119.0}

        await repository.merge_snapshot({"user-1": {"node-b": current}}, now=125.0)
        await repository.merge_snapshot({"user-1": {"node-b": late}}, now=125.0)

        assert await repository.current_total("user-1", now=125.0) == 1

    asyncio.run(run())


def test_a_peer_slot_from_a_later_window_replaces_the_old_one() -> None:
    async def run() -> None:
        repository = DistributedRateLimitRepository(node_id="node-a", window_seconds=60)
        old = {"count": 30, "window": 1, "expires_at": 120.0, "updated_at": 110.0}
        new = {"count": 2, "window": 2, "expires_at": 180.0, "updated_at": 121.0}

        await repository.merge_snapshot({"user-1": {"node-b": old}}, now=110.0)
        await repository.merge_snapshot({"user-1": {"node-b": new}}, now=121.0)

        assert await repository.current_total("user-1", now=121.0) == 2

    asyncio.run(run())


def test_peer_counts_join_the_limit_check() -> None:
    async def run() -> None:
        repository = DistributedRateLimitRepository(node_id="node-a", window_seconds=60)
        await repository.merge_snapshot(
            {"user-1": {"node-b": {"count": 3, "window": 0, "expires_at": 60.0, "updated_at": 5.0}}},
            now=5.0,
        )

        allowed, total = await repository.try_acquire("user-1", limit=3, now=6.0)

        assert not allowed
        assert total == 3

    asyncio.run(run())
