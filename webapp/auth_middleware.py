"""Bearer-secret auth for the agent-facing /mcp surface.

Wrap only the /mcp sub-app with this middleware. /admin relies on App Service
Easy Auth (Entra SSO) instead, enforced in admin_routes.py.
"""

from __future__ import annotations

import json
from typing import Any

from starlette.requests import Request
from starlette.responses import JSONResponse
from starlette.types import ASGIApp, Receive, Scope, Send

from .secrets_store import ClientSecretStore, SecretRecord, scope_allows


class BearerSecretMiddleware:
    def __init__(self, app: ASGIApp, store: ClientSecretStore):
        self._app = app
        self._store = store

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self._app(scope, receive, send)
            return

        request = Request(scope, receive=receive)
        scheme, _, token = request.headers.get("authorization", "").partition(" ")
        if scheme.lower() != "bearer" or not token:
            await self._reject(scope, receive, send, "missing bearer token")
            return

        record = await self._store.verify(token)
        if record is None:
            await self._reject(scope, receive, send, "invalid or revoked secret")
            return

        scope["client_secret_record"] = record

        # Only POST bodies can carry a tools/call JSON-RPC message; GET (the SSE
        # stream) and DELETE (session termination) have none to inspect.
        if request.method != "POST":
            await self._app(scope, receive, send)
            return

        body = await request.body()
        denial = self._check_tool_scope(body, record)
        if denial is not None:
            await denial(scope, receive, send)
            return

        # request.body() already drained the original `receive`, so give the
        # downstream app a fresh one that replays the buffered bytes.
        async def cached_receive() -> dict[str, Any]:
            return {"type": "http.request", "body": body, "more_body": False}

        await self._app(scope, cached_receive, send)

    @staticmethod
    def _check_tool_scope(body: bytes, record: SecretRecord) -> JSONResponse | None:
        try:
            payload = json.loads(body)
        except json.JSONDecodeError:
            return None

        for message in payload if isinstance(payload, list) else [payload]:
            if not isinstance(message, dict) or message.get("method") != "tools/call":
                continue
            tool_name = (message.get("params") or {}).get("name")
            if tool_name and not scope_allows(record.scopes, tool_name):
                return JSONResponse(
                    {
                        "jsonrpc": "2.0",
                        "id": message.get("id"),
                        "result": {
                            "content": [
                                {
                                    "type": "text",
                                    "text": f"This client secret is not permitted to call tool '{tool_name}'.",
                                }
                            ],
                            "isError": True,
                        },
                    }
                )
        return None

    @staticmethod
    async def _reject(scope: Scope, receive: Receive, send: Send, detail: str) -> None:
        response = JSONResponse({"error": detail}, status_code=401)
        await response(scope, receive, send)
