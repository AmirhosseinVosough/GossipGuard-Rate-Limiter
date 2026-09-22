from __future__ import annotations

from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles

from app.api.routes.auth import router as auth_router
from app.api.routes.health import router as health_router
from app.api.routes.internal import router as internal_router
from app.api.routes.protected import router as protected_router
from app.core.auth import hash_password
from app.core.client_ip import parse_trusted_proxies
from app.core.config import Settings
from app.models.enums import Role
from app.models.user import User
from app.middleware.rate_limit_middleware import RateLimitMiddleware
from app.repositories.auth_repository import AuthRepository
from app.repositories.rate_limit_repository import DistributedRateLimitRepository
from app.services.auth_service import AuthService
from app.services.gossip_service import GossipService
from app.services.rate_limit_service import RateLimitService


FRONTEND_DIR = Path(__file__).resolve().parent.parent / "frontend"


def _seed_demo_users(auth_repository: AuthRepository, settings: Settings) -> None:
    if not settings.enable_demo_users:
        return

    demo_users = (
        (
            settings.viewer_username,
            settings.viewer_password,
            User(
                username=settings.viewer_username,
                user_id=settings.viewer_user_id,
                email=settings.viewer_email,
                role=Role.VIEWER,
            ),
        ),
        (
            settings.admin_username,
            settings.admin_password,
            User(
                username=settings.admin_username,
                user_id=settings.admin_user_id,
                email=settings.admin_email,
                role=Role.ADMIN,
            ),
        ),
    )

    for username, password, user in demo_users:
        if auth_repository.get_user(username) is None:
            auth_repository.add_user(username, user, hash_password(password))


def create_app(settings: Settings | None = None) -> FastAPI:
    resolved_settings = settings or Settings.from_env()

    auth_repository = AuthRepository()
    _seed_demo_users(auth_repository, resolved_settings)
    auth_service = AuthService(auth_repository, resolved_settings)
    rate_limit_repository = DistributedRateLimitRepository(
        node_id=resolved_settings.node_id,
        window_seconds=resolved_settings.rate_limit_window_seconds,
    )
    rate_limit_service = RateLimitService(rate_limit_repository, resolved_settings)
    gossip_service = GossipService(rate_limit_repository, resolved_settings)

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        await gossip_service.start()
        try:
            yield
        finally:
            await gossip_service.stop()

    app = FastAPI(title=resolved_settings.app_name, lifespan=lifespan)
    app.state.settings = resolved_settings
    app.state.auth_service = auth_service
    app.state.rate_limit_service = rate_limit_service
    app.state.gossip_service = gossip_service

    app.add_middleware(
        RateLimitMiddleware,
        service=rate_limit_service,
        trusted_proxies=parse_trusted_proxies(resolved_settings.trusted_proxies),
    )
    app.include_router(health_router)
    app.include_router(auth_router)
    app.include_router(protected_router)
    app.include_router(internal_router)

    app.mount("/static", StaticFiles(directory=FRONTEND_DIR), name="static")

    @app.get("/", include_in_schema=False)
    @app.get("/dashboard", include_in_schema=False)
    async def dashboard() -> FileResponse:
        return FileResponse(FRONTEND_DIR / "index.html")

    return app


class _LazyApp:
    def __init__(self) -> None:
        self._app: FastAPI | None = None

    def _get_app(self) -> FastAPI:
        if self._app is None:
            self._app = create_app()
        return self._app

    async def __call__(self, scope, receive, send) -> None:
        await self._get_app()(scope, receive, send)


app = _LazyApp()
