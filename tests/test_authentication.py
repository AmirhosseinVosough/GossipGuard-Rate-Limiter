from __future__ import annotations

from unittest.mock import patch

from fastapi.testclient import TestClient

from app.core.auth import hash_password
from app.core.config import Settings
from app.main import create_app
from app.models.enums import Role
from app.models.user import User
from app.repositories.auth_repository import AuthRepository
from app.services.auth_service import AuthService


def _service() -> AuthService:
    settings = Settings(
        gossip_secret_key="test-gossip-secret-key-that-is-long-enough",
        jwt_secret_key="test-jwt-secret-key-that-is-long-enough",
    )
    repository = AuthRepository()
    repository.add_user(
        "known",
        User(username="known", user_id="u-1", email="known@example.com", role=Role.VIEWER),
        hash_password("correct-password"),
    )
    return AuthService(repository, settings)


def test_missing_account_still_runs_a_password_comparison() -> None:
    """The timing oracle fix: both paths must cost one bcrypt comparison.

    Asserted by call count rather than by clock, because wall-clock assertions
    are flaky on shared CI runners.
    """
    service = _service()

    with patch("app.services.auth_service.verify_password", return_value=False) as spy:
        assert service.authenticate_user("no-such-user", "anything") is None

    assert spy.call_count == 1


def test_existing_account_with_wrong_password_runs_one_comparison() -> None:
    service = _service()

    with patch("app.services.auth_service.verify_password", return_value=False) as spy:
        assert service.authenticate_user("known", "wrong-password") is None

    assert spy.call_count == 1


def test_correct_credentials_return_the_user() -> None:
    service = _service()

    user = service.authenticate_user("known", "correct-password")

    assert user is not None
    assert user.username == "known"


def test_login_failures_are_indistinguishable_to_the_caller() -> None:
    settings = Settings(
        node_id="test-node",
        peer_urls=(),
        gossip_secret_key="test-gossip-secret-key-that-is-long-enough",
        jwt_secret_key="test-jwt-secret-key-that-is-long-enough",
        enable_demo_users=True,
        viewer_password="viewer123",
        admin_password="admin123",
    )
    client = TestClient(create_app(settings))

    unknown = client.post("/auth/token", data={"username": "ghost", "password": "x"})
    wrong = client.post("/auth/token", data={"username": "admin", "password": "x"})

    assert unknown.status_code == wrong.status_code == 401
    assert unknown.json() == wrong.json()


def test_password_check_runs_off_the_event_loop() -> None:
    """bcrypt costs ~350ms and must not run inline on the event loop.

    Asserted by thread identity rather than by clock, so it cannot flake on a
    loaded CI runner. If the check ever moves back onto the loop thread, every
    other request on the node stalls for the duration, and /auth/token is
    unauthenticated so anyone could trigger it.
    """
    import asyncio
    import threading

    import httpx

    import app.services.auth_service as auth_service_module

    settings = Settings(
        node_id="test-node",
        peer_urls=(),
        gossip_secret_key="test-gossip-secret-key-that-is-long-enough",
        jwt_secret_key="test-jwt-secret-key-that-is-long-enough",
        enable_demo_users=True,
        viewer_password="viewer123",
        admin_password="admin123",
    )
    application = create_app(settings)

    observed: dict[str, threading.Thread] = {}
    original = auth_service_module.verify_password

    def spy(password: str, hashed_password: str) -> bool:
        observed["checked_on"] = threading.current_thread()
        return original(password, hashed_password)

    async def run() -> None:
        observed["loop_on"] = threading.current_thread()
        transport = httpx.ASGITransport(app=application)
        async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
            response = await client.post(
                "/auth/token", data={"username": "admin", "password": "admin123"}
            )
        assert response.status_code == 200

    with patch.object(auth_service_module, "verify_password", spy):
        asyncio.run(run())

    assert "checked_on" in observed, "verify_password was never called"
    assert observed["checked_on"] is not observed["loop_on"], (
        "bcrypt ran on the event loop thread; it must be offloaded to a worker"
    )
