from __future__ import annotations

import ipaddress
import socket
from functools import lru_cache
from time import time
from urllib.parse import urlparse

from fastapi import APIRouter, Request, HTTPException, Depends
from pydantic import BaseModel, Field, field_validator

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

    @field_validator("timestamp")
    @classmethod
    def validate_timestamp(cls, v: float) -> float:
        now = time()
        time_diff = abs(v - now)
        if time_diff > 3600:  # 1 hour in seconds
            raise ValueError(f"Timestamp too far from now: {v} (diff: {time_diff}s)")
        return v


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


@lru_cache(maxsize=32)
def _resolve_peer_ips(peer_urls: tuple[str, ...]) -> frozenset[str]:
    resolved_ips: set[str] = set()
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
            continue

        for _, _, _, _, sockaddr in addr_info:
            if not sockaddr:
                continue
            resolved = _normalize_ip(sockaddr[0])
            if resolved is not None:
                resolved_ips.add(resolved)

    return frozenset(resolved_ips)


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
