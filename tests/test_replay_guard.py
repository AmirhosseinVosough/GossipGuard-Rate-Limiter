from __future__ import annotations

import asyncio
from time import time

from fastapi.testclient import TestClient

from app.core.config import Settings
from app.core.replay_guard import ReplayGuard, is_fresh
from app.core.signing import compute_signature
from app.main import create_app

SECRET = "test-gossip-secret-key-that-is-long-enough"


def test_freshness_window_accepts_current_timestamps() -> None:
    assert is_fresh(1_000.0, 60.0, now=1_000.0)
    assert is_fresh(1_000.0, 60.0, now=1_030.0)
    assert is_fresh(1_030.0, 60.0, now=1_000.0)


def test_freshness_window_rejects_stale_and_future_timestamps() -> None:
    assert not is_fresh(1_000.0, 60.0, now=1_061.0)
    assert not is_fresh(1_061.0, 60.0, now=1_000.0)


def test_freshness_boundary_is_inclusive() -> None:
    assert is_fresh(1_000.0, 60.0, now=1_060.0)
    assert not is_fresh(1_000.0, 60.0, now=1_060.1)


def test_guard_accepts_a_signature_once() -> None:
    async def run() -> None:
        guard = ReplayGuard(window_seconds=60.0)

        assert await guard.accept("sig-a", now=100.0)
        assert not await guard.accept("sig-a", now=100.0)
        assert not await guard.accept("sig-a", now=159.0)

    asyncio.run(run())


def test_guard_forgets_entries_once_they_leave_the_window() -> None:
    async def run() -> None:
        guard = ReplayGuard(window_seconds=60.0)

        assert await guard.accept("sig-a", now=100.0)
        assert await guard.accept("sig-a", now=161.0)

    asyncio.run(run())


def test_guard_does_not_grow_without_bound() -> None:
    async def run() -> None:
        guard = ReplayGuard(window_seconds=60.0)

        for index in range(500):
            await guard.accept(f"sig-{index}", now=100.0)
        assert await guard.size(now=100.0) == 500

        assert await guard.size(now=161.0) == 0

    asyncio.run(run())


def test_distinct_signatures_are_independent() -> None:
    async def run() -> None:
        guard = ReplayGuard(window_seconds=60.0)

        assert await guard.accept("sig-a", now=100.0)
        assert await guard.accept("sig-b", now=100.0)
        assert not await guard.accept("sig-a", now=100.0)

    asyncio.run(run())


def _node(**overrides) -> Settings:
    base = dict(
        node_id="node-under-test",
        peer_urls=("http://127.0.0.1:8001",),
        gossip_secret_key=SECRET,
        jwt_secret_key="test-jwt-secret-key-that-is-long-enough",
    )
    base.update(overrides)
    return Settings(**base)


def _envelope(timestamp: float, snapshot: dict | None = None) -> dict:
    body = snapshot if snapshot is not None else {"u1": {"peer": {"count": 1, "expires_at": timestamp + 60, "updated_at": timestamp}}}
    return {
        "node_id": "peer",
        "timestamp": timestamp,
        "version": 1,
        "snapshot": body,
        "signature": compute_signature("peer", timestamp, 1, body, SECRET),
    }


def test_replaying_a_captured_envelope_is_refused() -> None:
    client = TestClient(create_app(_node()), client=("127.0.0.1", 50000))
    envelope = _envelope(time())

    first = client.post("/internal/gossip/sync", json=envelope)
    second = client.post("/internal/gossip/sync", json=envelope)

    assert first.status_code == 200
    assert second.status_code == 403
    assert second.json()["detail"] == "Envelope already processed"


def test_stale_envelope_is_refused() -> None:
    client = TestClient(create_app(_node()), client=("127.0.0.1", 50000))

    response = client.post("/internal/gossip/sync", json=_envelope(time() - 3600))

    assert response.status_code == 403
    assert response.json()["detail"] == "Envelope outside the accepted time window"


def test_future_dated_envelope_is_refused() -> None:
    client = TestClient(create_app(_node()), client=("127.0.0.1", 50000))

    response = client.post("/internal/gossip/sync", json=_envelope(time() + 3600))

    assert response.status_code == 403


def test_a_genuinely_new_envelope_is_still_accepted() -> None:
    client = TestClient(create_app(_node()), client=("127.0.0.1", 50000))
    now = time()

    first = client.post("/internal/gossip/sync", json=_envelope(now))
    second = client.post("/internal/gossip/sync", json=_envelope(now + 0.5))

    assert first.status_code == 200
    assert second.status_code == 200


def test_signature_is_checked_before_the_replay_cache_is_touched() -> None:
    app = create_app(_node())
    client = TestClient(app, client=("127.0.0.1", 50000))

    forged = _envelope(time())
    forged["signature"] = "0" * 64

    assert client.post("/internal/gossip/sync", json=forged).status_code == 403
    assert asyncio.run(app.state.replay_guard.size()) == 0
