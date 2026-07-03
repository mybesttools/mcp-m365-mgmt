"""Bearer-secret auth for the agent-facing /mcp surface.

Wrap only the /mcp sub-app with this middleware. /admin relies on App Service
Easy Auth (Entra SSO) instead, enforced in admin_routes.py.
"""

from __future__ import annotations

from starlette.requests import Request
from starlette.responses import JSONResponse
from starlette.types import ASGIApp, Receive, Scope, Send

from .secrets_store import ClientSecretStore


class BearerSecretMiddleware:
    def __init__(self, app: ASGIApp, store: ClientSecretStore):
        self._app = app
        self._store = store

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self._app(scope, receive, send)
            return

        request = Request(scope)
        scheme, _, token = request.headers.get("authorization", "").partition(" ")
        if scheme.lower() != "bearer" or not token:
            await self._reject(scope, receive, send, "missing bearer token")
            return

        record = await self._store.verify(token)
        if record is None:
            await self._reject(scope, receive, send, "invalid or revoked secret")
            return

        scope["client_secret_record"] = record
        await self._app(scope, receive, send)

    @staticmethod
    async def _reject(scope: Scope, receive: Receive, send: Send, detail: str) -> None:
        response = JSONResponse({"error": detail}, status_code=401)
        await response(scope, receive, send)
