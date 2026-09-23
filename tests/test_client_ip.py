from __future__ import annotations

from fastapi.testclient import TestClient

from app.core.client_ip import parse_trusted_proxies, resolve_client_ip
from app.core.config import Settings
from app.main import create_app


def test_forwarded_header_is_ignored_for_direct_connections() -> None:
    trusted = parse_trusted_proxies(["10.0.0.0/8"])

    resolved = resolve_client_ip("203.0.113.9", "1.2.3.4", trusted)

    assert resolved == "203.0.113.9"


def test_forwarded_header_is_ignored_when_no_proxies_configured() -> None:
    resolved = resolve_client_ip("10.0.0.5", "1.2.3.4", ())

    assert resolved == "10.0.0.5"


def test_trusted_proxy_reveals_originating_client() -> None:
    trusted = parse_trusted_proxies(["10.0.0.0/8"])

    resolved = resolve_client_ip("10.0.0.5", "203.0.113.9", trusted)

    assert resolved == "203.0.113.9"


def test_chained_proxies_skip_every_trusted_hop() -> None:
    trusted = parse_trusted_proxies(["10.0.0.0/8", "192.168.0.0/16"])

    resolved = resolve_client_ip("10.0.0.5", "203.0.113.9, 192.168.1.1, 10.0.0.9", trusted)

    assert resolved == "203.0.113.9"


def test_spoofed_entries_before_the_real_client_are_not_reached() -> None:
    trusted = parse_trusted_proxies(["10.0.0.0/8"])

    resolved = resolve_client_ip("10.0.0.5", "1.1.1.1, 203.0.113.9", trusted)

    assert resolved == "203.0.113.9"


def test_all_trusted_chain_falls_back_to_peer_address() -> None:
    trusted = parse_trusted_proxies(["10.0.0.0/8"])

    resolved = resolve_client_ip("10.0.0.5", "10.0.0.7, 10.0.0.8", trusted)

    assert resolved == "10.0.0.5"


def test_malformed_entry_stops_the_walk() -> None:
    trusted = parse_trusted_proxies(["10.0.0.0/8"])

    resolved = resolve_client_ip("10.0.0.5", "203.0.113.9, not-an-ip", trusted)

    assert resolved == "10.0.0.5"


def test_port_suffixes_are_stripped() -> None:
    trusted = parse_trusted_proxies(["10.0.0.0/8"])

    assert resolve_client_ip("10.0.0.5", "203.0.113.9:51234", trusted) == "203.0.113.9"
    assert resolve_client_ip("10.0.0.5", "[2001:db8::1]:443", trusted) == "2001:db8::1"


def test_ipv6_proxy_range_is_matched_without_crossing_families() -> None:
    trusted = parse_trusted_proxies(["2001:db8::/32"])

    assert resolve_client_ip("2001:db8::5", "203.0.113.9", trusted) == "203.0.113.9"
    assert resolve_client_ip("203.0.113.1", "203.0.113.9", trusted) == "203.0.113.1"


def test_invalid_proxy_configuration_is_discarded() -> None:
    trusted = parse_trusted_proxies(["not-a-network", "", "10.0.0.0/8"])

    assert len(trusted) == 1
    assert resolve_client_ip("10.0.0.5", "203.0.113.9", trusted) == "203.0.113.9"


def test_missing_peer_address_is_reported_as_unknown() -> None:
    assert resolve_client_ip(None, "203.0.113.9", parse_trusted_proxies(["10.0.0.0/8"])) == "unknown"


def _app_settings(**overrides) -> Settings:
    base = dict(
        node_id="test-node",
        peer_urls=(),
        anonymous_limit=3,
        gossip_secret_key="test-gossip-secret-key-that-is-long-enough",
        jwt_secret_key="test-jwt-secret-key-that-is-long-enough",
    )
    base.update(overrides)
    return Settings(**base)


def test_spoofed_forwarded_header_cannot_escape_the_limit() -> None:
    app = create_app(_app_settings())
    client = TestClient(app, client=("10.0.0.5", 50000))

    statuses = [
        client.get("/protected/public", headers={"X-Forwarded-For": f"1.2.3.{index}"}).status_code
        for index in range(6)
    ]

    assert 429 in statuses


def test_trusted_proxy_separates_distinct_clients() -> None:
    app = create_app(_app_settings(trusted_proxies=("10.0.0.0/8",)))
    client = TestClient(app, client=("10.0.0.5", 50000))

    statuses = [
        client.get("/protected/public", headers={"X-Forwarded-For": f"203.0.113.{index}"}).status_code
        for index in range(6)
    ]

    assert statuses == [200] * 6


def test_trusted_proxy_still_throttles_a_single_client() -> None:
    app = create_app(_app_settings(trusted_proxies=("10.0.0.0/8",)))
    client = TestClient(app, client=("10.0.0.5", 50000))

    statuses = [
        client.get("/protected/public", headers={"X-Forwarded-For": "203.0.113.77"}).status_code
        for _ in range(6)
    ]

    assert 429 in statuses


def test_health_checks_are_never_throttled() -> None:
    """Docker polls /health every five seconds, which alone exceeds the anonymous limit."""
    app = create_app(_app_settings())
    client = TestClient(app, client=("127.0.0.1", 50000))

    statuses = [client.get("/health").status_code for _ in range(20)]

    assert statuses == [200] * 20
