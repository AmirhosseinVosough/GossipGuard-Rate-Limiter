from __future__ import annotations

from dataclasses import dataclass, field
import os
from os import getenv
from pathlib import Path
from socket import gethostname


def _load_dotenv() -> None:
    env_path = Path(__file__).resolve().parents[2] / ".env"
    if not env_path.exists():
        return

    for raw_line in env_path.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue

        key, value = line.split("=", 1)
        key = key.strip()
        value = value.strip().strip('"').strip("'")
        if key and key not in os.environ:
            os.environ[key] = value


_load_dotenv()


def _split_csv(value: str) -> tuple[str, ...]:
    return tuple(item.strip() for item in value.split(",") if item.strip())


def _as_bool(value: str) -> bool:
    return value.strip().lower() in {"1", "true", "yes", "on"}


@dataclass(slots=True)
class Settings:
    app_name: str = "GossipGuard Rate Limiter"
    node_id: str = field(default_factory=gethostname)
    peer_urls: tuple[str, ...] = field(default_factory=tuple)
    trusted_proxies: tuple[str, ...] = field(default_factory=tuple)
    rate_limit_window_seconds: int = 60
    anonymous_limit: int = 10
    viewer_limit: int = 30
    editor_limit: int = 60
    admin_limit: int = 120
    gossip_interval_seconds: float = 0.5
    gossip_fanout: int = 2
    gossip_secret_key: str = ""
    jwt_secret_key: str = ""
    jwt_algorithm: str = "HS256"
    access_token_expire_minutes: int = 30
    enable_demo_users: bool = False
    viewer_username: str = "viewer"
    viewer_password: str = ""
    viewer_user_id: str = "viewer-1"
    viewer_email: str = "viewer@example.com"
    admin_username: str = "admin"
    admin_password: str = ""
    admin_user_id: str = "admin-1"
    admin_email: str = "admin@example.com"

    def __post_init__(self) -> None:
        if not self.gossip_secret_key:
            raise ValueError("GOSSIP_SECRET_KEY environment variable is required")
        if not self.jwt_secret_key:
            raise ValueError("JWT_SECRET_KEY environment variable is required")
        if self.enable_demo_users:
            if not self.viewer_password:
                raise ValueError("VIEWER_PASSWORD environment variable is required when ENABLE_DEMO_USERS is enabled")
            if not self.admin_password:
                raise ValueError("ADMIN_PASSWORD environment variable is required when ENABLE_DEMO_USERS is enabled")

    @classmethod
    def from_env(cls) -> "Settings":
        return cls(
            node_id=getenv("NODE_ID", gethostname()),
            peer_urls=_split_csv(getenv("PEER_URLS", "")),
            trusted_proxies=_split_csv(getenv("TRUSTED_PROXIES", "")),
            rate_limit_window_seconds=int(getenv("RATE_LIMIT_WINDOW_SECONDS", "60")),
            anonymous_limit=int(getenv("ANONYMOUS_LIMIT", "10")),
            viewer_limit=int(getenv("VIEWER_LIMIT", "30")),
            editor_limit=int(getenv("EDITOR_LIMIT", "60")),
            admin_limit=int(getenv("ADMIN_LIMIT", "120")),
            gossip_interval_seconds=float(getenv("GOSSIP_INTERVAL_SECONDS", "0.5")),
            gossip_fanout=int(getenv("GOSSIP_FANOUT", "2")),
            gossip_secret_key=getenv("GOSSIP_SECRET_KEY", ""),
            jwt_secret_key=getenv("JWT_SECRET_KEY", ""),
            jwt_algorithm=getenv("JWT_ALGORITHM", "HS256"),
            access_token_expire_minutes=int(getenv("ACCESS_TOKEN_EXPIRE_MINUTES", "30")),
            enable_demo_users=_as_bool(getenv("ENABLE_DEMO_USERS", "false")),
            viewer_username=getenv("VIEWER_USERNAME", "viewer"),
            viewer_password=getenv("VIEWER_PASSWORD", ""),
            viewer_user_id=getenv("VIEWER_USER_ID", "viewer-1"),
            viewer_email=getenv("VIEWER_EMAIL", "viewer@example.com"),
            admin_username=getenv("ADMIN_USERNAME", "admin"),
            admin_password=getenv("ADMIN_PASSWORD", ""),
            admin_user_id=getenv("ADMIN_USER_ID", "admin-1"),
            admin_email=getenv("ADMIN_EMAIL", "admin@example.com"),
        )
