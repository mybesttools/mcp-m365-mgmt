"""ASGI entrypoint for Azure-hosted deployment: `gunicorn ... webapp.asgi:app`.

Composes the existing FastMCP tool server (mounted at /mcp, protected by
per-agent bearer secrets) with the admin secret-management UI (mounted at
/admin, protected by App Service Easy Auth).

mcp.streamable_http_app() returns its own Starlette app whose lifespan starts
the MCP session manager. Starlette does not forward ASGI lifespan events to a
sub-app mounted via Mount() — only the top-level app receives them — so without
manually entering `mcp.session_manager.run()` here, the MCP endpoint would hang
on its first request. Verified directly against mcp==1.28.1's source.
"""

from __future__ import annotations

from collections.abc import AsyncIterator
from contextlib import AsyncExitStack, asynccontextmanager

from starlette.applications import Starlette
from starlette.routing import Mount

from mcp_m365_mgmt import mcp

from .admin_routes import build_admin_app
from .auth_middleware import BearerSecretMiddleware
from .secrets_store import ClientSecretStore


def build_app() -> Starlette:
    store = ClientSecretStore.from_env()
    mcp_app = BearerSecretMiddleware(mcp.streamable_http_app(), store=store)
    admin_app = build_admin_app(store)

    @asynccontextmanager
    async def lifespan(app: Starlette) -> AsyncIterator[None]:
        async with AsyncExitStack() as stack:
            await stack.enter_async_context(mcp.session_manager.run())
            await stack.enter_async_context(store)
            yield

    return Starlette(
        routes=[
            Mount("/admin", app=admin_app),
            Mount("/mcp", app=mcp_app),
        ],
        lifespan=lifespan,
    )


app = build_app()
