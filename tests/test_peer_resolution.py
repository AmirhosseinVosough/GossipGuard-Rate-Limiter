from __future__ import annotations

import socket
from unittest.mock import patch

from app.api.routes import internal

PEERS = ("http://node-b:8000", "http://node-c:8000")
BOTH = (frozenset({"10.0.0.2", "10.0.0.3"}), True)
ONLY_B = (frozenset({"10.0.0.2"}), False)


def setup_function() -> None:
    internal._peer_ip_cache.clear()


def _addr(ip: str) -> tuple:
    return (socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", (ip, 0))


def test_resolution_is_cached_within_the_ttl() -> None:
    with patch.object(internal, "_resolve_peer_ips_uncached", return_value=BOTH) as lookup:
        internal._resolve_peer_ips(PEERS, now=100.0)
        internal._resolve_peer_ips(PEERS, now=120.0)

    assert lookup.call_count == 1


def test_a_peer_that_changes_address_is_seen_once_the_ttl_expires() -> None:
    with patch.object(internal, "_resolve_peer_ips_uncached", side_effect=[
        BOTH,
        (frozenset({"10.0.0.9", "10.0.0.3"}), True),
    ]):
        first = internal._resolve_peer_ips(PEERS, now=100.0)
        second = internal._resolve_peer_ips(PEERS, now=100.0 + internal.PEER_DNS_TTL_SECONDS + 1)

    assert "10.0.0.2" in first
    assert "10.0.0.9" in second


def test_a_peer_that_starts_late_is_seen_within_the_retry_window() -> None:
    """The startup race: node-c has no DNS entry yet when node-b first looks."""
    with patch.object(internal, "_resolve_peer_ips_uncached", side_effect=[ONLY_B, BOTH]) as lookup:
        internal._resolve_peer_ips(PEERS, now=100.0)
        resolved = internal._resolve_peer_ips(PEERS, now=100.0 + internal.PEER_DNS_RETRY_SECONDS + 0.1)

    assert lookup.call_count == 2
    assert resolved == BOTH[0]


def test_complete_resolution_is_held_for_the_full_ttl() -> None:
    with patch.object(internal, "_resolve_peer_ips_uncached", return_value=BOTH) as lookup:
        internal._resolve_peer_ips(PEERS, now=100.0)
        internal._resolve_peer_ips(PEERS, now=100.0 + internal.PEER_DNS_RETRY_SECONDS + 0.1)

    assert lookup.call_count == 1


def test_an_unresolvable_peer_marks_the_answer_incomplete() -> None:
    def fake_getaddrinfo(host: str, *_args, **_kwargs):
        if host == "node-c":
            raise socket.gaierror("not running yet")
        return [_addr("10.0.0.2")]

    with patch.object(internal.socket, "getaddrinfo", side_effect=fake_getaddrinfo):
        resolved, complete = internal._resolve_peer_ips_uncached(PEERS)

    assert resolved == frozenset({"10.0.0.2"})
    assert not complete


def test_a_multi_address_peer_does_not_hide_a_missing_one() -> None:
    """Counting addresses against peers would call this complete: 2 addresses, 2 peers."""
    def fake_getaddrinfo(host: str, *_args, **_kwargs):
        if host == "node-c":
            raise socket.gaierror("not running yet")
        return [_addr("10.0.0.2"), _addr("10.0.0.20")]

    with patch.object(internal.socket, "getaddrinfo", side_effect=fake_getaddrinfo):
        _, complete = internal._resolve_peer_ips_uncached(PEERS)

    assert not complete


def test_literal_ip_peers_need_no_lookup() -> None:
    with patch.object(internal.socket, "getaddrinfo") as lookup:
        resolved, complete = internal._resolve_peer_ips_uncached(("http://127.0.0.1:8000",))

    lookup.assert_not_called()
    assert resolved == frozenset({"127.0.0.1"})
    assert complete
