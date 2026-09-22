from __future__ import annotations

import ipaddress
from collections.abc import Iterable

TrustedNetworks = tuple[ipaddress.IPv4Network | ipaddress.IPv6Network, ...]


def parse_trusted_proxies(values: Iterable[str]) -> TrustedNetworks:
    networks: list[ipaddress.IPv4Network | ipaddress.IPv6Network] = []
    for value in values:
        candidate = value.strip()
        if not candidate:
            continue
        try:
            networks.append(ipaddress.ip_network(candidate, strict=False))
        except ValueError:
            continue
    return tuple(networks)


def _normalize(value: str) -> str | None:
    candidate = value.strip()
    if not candidate:
        return None

    if candidate.startswith("["):
        closing = candidate.find("]")
        if closing == -1:
            return None
        candidate = candidate[1:closing]
    elif candidate.count(":") == 1:
        candidate = candidate.split(":", 1)[0]

    try:
        return ipaddress.ip_address(candidate).compressed
    except ValueError:
        return None


def _is_trusted(address: str, trusted: TrustedNetworks) -> bool:
    try:
        parsed = ipaddress.ip_address(address)
    except ValueError:
        return False
    return any(parsed.version == network.version and parsed in network for network in trusted)


def resolve_client_ip(
    peer_address: str | None,
    forwarded_for: str | None,
    trusted: TrustedNetworks,
) -> str:
    if peer_address is None:
        return "unknown"

    peer = _normalize(peer_address) or peer_address

    if not trusted or not _is_trusted(peer, trusted):
        return peer

    if not forwarded_for:
        return peer

    for entry in reversed(forwarded_for.split(",")):
        address = _normalize(entry)
        if address is None:
            return peer
        if not _is_trusted(address, trusted):
            return address

    return peer
