from __future__ import annotations

from fastapi.testclient import TestClient

from app.core.config import Settings
from app.main import create_app


def _settings(**overrides) -> Settings:
    base = dict(
        node_id="test-node",
        peer_urls=(),
        anonymous_limit=10,
        viewer_limit=3,
        admin_limit=3,
        gossip_secret_key="test-gossip-secret-key-that-is-long-enough",
        jwt_secret_key="test-jwt-secret-key-that-is-long-enough",
        enable_demo_users=True,
        viewer_password="viewer123",
        admin_password="admin123",
    )
    base.update(overrides)
    return Settings(**base)


def _client(app, ip: str) -> TestClient:
    return TestClient(app, client=(ip, 50000))


def _login(client: TestClient, username: str, password: str) -> dict[str, str]:
    token = client.post("/auth/token", data={"username": username, "password": password}).json()["access_token"]
    return {"Authorization": f"Bearer {token}"}


def test_one_user_on_two_ips_shares_one_bucket() -> None:
    app = create_app(_settings())
    laptop = _client(app, "1.1.1.1")
    phone = _client(app, "2.2.2.2")
    headers = _login(laptop, "viewer", "viewer123")

    assert laptop.get("/protected/profile", headers=headers).status_code == 200
    assert laptop.get("/protected/profile", headers=headers).status_code == 200
    assert phone.get("/protected/profile", headers=headers).status_code == 200
    assert phone.get("/protected/profile", headers=headers).status_code == 429


def test_two_users_on_one_ip_get_separate_buckets() -> None:
    app = create_app(_settings())
    office = _client(app, "5.5.5.5")
    viewer = _login(office, "viewer", "viewer123")
    admin = _login(office, "admin", "admin123")

    for _ in range(3):
        assert office.get("/protected/profile", headers=viewer).status_code == 200
    assert office.get("/protected/profile", headers=viewer).status_code == 429

    assert office.get("/protected/profile", headers=admin).status_code == 200


def test_anonymous_clients_are_limited_per_ip() -> None:
    app = create_app(_settings(anonymous_limit=2))
    first = _client(app, "1.1.1.1")
    second = _client(app, "2.2.2.2")

    assert first.get("/protected/public").status_code == 200
    assert first.get("/protected/public").status_code == 200
    assert first.get("/protected/public").status_code == 429

    assert second.get("/protected/public").status_code == 200


def test_an_invalid_token_falls_back_to_the_ip_bucket() -> None:
    app = create_app(_settings(anonymous_limit=2))
    client = _client(app, "1.1.1.1")
    forged = {"Authorization": "Bearer not-a-real-token"}

    assert client.get("/protected/public", headers=forged).status_code == 200
    assert client.get("/protected/public", headers=forged).status_code == 200
    assert client.get("/protected/public").status_code == 429
