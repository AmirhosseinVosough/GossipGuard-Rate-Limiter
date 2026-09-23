from __future__ import annotations

import ipaddress
import socket
from time import time
from urllib.parse import urlparse

from fastapi import APIRouter, Request, HTTPException, Depends
from pydantic import BaseModel, Field

from app.core.replay_guard import is_fresh
from app.core.security import require_permissions
from app.core.signing import verify_signature
from app.models.enums import Permission
from app.models.user import User

router = APIRouter(prefix="/internal/gossip", tags=["internal"])


class GossipEnvelope(BaseModel):
    node_id: str
    timestamp: float
    version: int = 1
    snapshot: dict[str, dict[str, dict[str, float | int]]] = Field(default_factory=dict)
    signature: str  # HMAC-SHA256 signature


@router.get("/state")
async def state(
    request: Request,
    _current_user: User = Depends(require_permissions(Permission.VIEW_AUDIT_LOGS)),
) -> dict[str, object]:
    gossip_service = request.app.state.gossip_service
    return {
        "node_id": request.app.state.settings.node_id,
        "snapshot": await gossip_service.local_snapshot(),
    }


def _normalize_ip(value: str) -> str | None:
    try:
        return ipaddress.ip_address(value).compressed
    except ValueError:
        return None


# Resolution is cached, but never permanently: a peer that changes address, or
# one that had not started yet when we first looked, must eventually be seen.
# An incomplete answer is held only briefly so startup converges quickly.
PEER_DNS_TTL_SECONDS = 30.0
PEER_DNS_RETRY_SECONDS = 1.0

_peer_ip_cache: dict[tuple[str, ...], tuple[float, frozenset[str]]] = {}


def _resolve_peer_ips(peer_urls: tuple[str, ...], now: float | None = None) -> frozenset[str]:
    current_time = time() if now is None else now
    cached = _peer_ip_cache.get(peer_urls)
    if cached is not None and cached[0] > current_time:
        return cached[1]

    resolved, complete = _resolve_peer_ips_uncached(peer_urls)
    ttl = PEER_DNS_TTL_SECONDS if complete else PEER_DNS_RETRY_SECONDS
    _peer_ip_cache[peer_urls] = (current_time + ttl, resolved)
    return resolved


def _resolve_peer_ips_uncached(peer_urls: tuple[str, ...]) -> tuple[frozenset[str], bool]:
    """Return every address the peers resolve to, and whether each peer resolved.

    Completeness is tracked per peer, not by counting addresses: one peer can
    resolve to several addresses, which would otherwise hide a peer that
    resolved to none.
    """
    resolved_ips: set[str] = set()
    complete = True
    for peer_url in peer_urls:
        hostname = urlparse(peer_url).hostname
        if not hostname:
            continue

        normalized = _normalize_ip(hostname)
        if normalized is not None:
            resolved_ips.add(normalized)
            continue

        try:
            addr_info = socket.getaddrinfo(hostname, None, proto=socket.IPPROTO_TCP)
        except socket.gaierror:
            complete = False
            continue

        peer_ips = {
            resolved
            for _, _, _, _, sockaddr in addr_info
            if sockaddr and (resolved := _normalize_ip(sockaddr[0])) is not None
        }
        if not peer_ips:
            complete = False
        resolved_ips.update(peer_ips)

    return frozenset(resolved_ips), complete


def verify_source_ip(request: Request, peer_urls: tuple[str, ...]) -> bool:
    """Verify that the request comes from an IP resolved from known peer URLs."""
    client_ip = request.client.host if request.client else None

    if not client_ip:
        return False

    normalized_client_ip = _normalize_ip(client_ip)
    if normalized_client_ip is None:
        return False

    return normalized_client_ip in _resolve_peer_ips(peer_urls)


@router.post("/sync")
async def sync(payload: GossipEnvelope, request: Request) -> dict[str, str]:
    gossip_service = request.app.state.gossip_service
    settings = request.app.state.settings
    secret_key = settings.gossip_secret_key

    if not verify_signature(
        payload.node_id,
        payload.timestamp,
        payload.version,
        payload.snapshot,
        payload.signature,
        secret_key,
    ):
        raise HTTPException(status_code=403, detail="Invalid signature")

    if not verify_source_ip(request, settings.peer_urls):
        raise HTTPException(status_code=403, detail="Unauthorized node")

    if not is_fresh(payload.timestamp, settings.gossip_max_skew_seconds):
        raise HTTPException(status_code=403, detail="Envelope outside the accepted time window")

    if not await request.app.state.replay_guard.accept(payload.signature):
        raise HTTPException(status_code=403, detail="Envelope already processed")

    source_node_id = payload.node_id
    received_at = payload.timestamp

    # The repository compares timestamps and ignores stale snapshots.
    await gossip_service.ingest_envelope(
        source_node_id=source_node_id,
        snapshot=payload.snapshot,
        received_at=received_at,
    )

    return {
        "status": "merged",
        "source": source_node_id,
    }


@router.get("/debug")
async def debug(
    request: Request,
    _current_user: User = Depends(require_permissions(Permission.VIEW_AUDIT_LOGS))
) -> dict[str, object]:
    gossip_service = request.app.state.gossip_service

    return {
        "node_id": request.app.state.settings.node_id,
        "node_count": gossip_service.node_count(),
        "gossip_enabled": gossip_service.gossip_enabled(),
        "peers": tuple(request.app.state.settings.peer_urls),
        "last_sync": gossip_service.last_envelope(),
        "snapshot_size": len(await gossip_service.local_snapshot()),
    }
