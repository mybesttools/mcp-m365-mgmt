"""Admin routes for issuing/revoking agent client secrets.

Protection comes from App Service Easy Auth (Entra SSO), not the bearer-secret
middleware used by /mcp. Easy Auth's `unauthenticatedClientAction` is set to
`AllowAnonymous` at the platform level (see infra/modules/authSettings.bicep)
because Easy Auth cannot be scoped to a single path prefix — so every handler
here re-checks the platform-injected X-MS-CLIENT-PRINCIPAL header itself. That
header is safe to trust without independently verifying a token: App Service's
edge proxy strips any client-supplied copy of X-MS-* headers before injecting
its own, so a caller cannot forge it directly.
"""

from __future__ import annotations

import base64
import binascii
import dataclasses
import json
import os
from pathlib import Path

from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import HTMLResponse, JSONResponse, RedirectResponse, Response
from starlette.routing import Route
from starlette.templating import Jinja2Templates

from mcp_m365_mgmt import mcp as tool_server

from .openapi import OPENAPI_SPEC, SWAGGER_UI_HTML
from .secrets_store import ClientSecretStore

_TEMPLATES_DIR = Path(__file__).parent / "templates"
templates = Jinja2Templates(directory=str(_TEMPLATES_DIR))

ADMIN_APP_ROLE_NAME = os.getenv("ADMIN_APP_ROLE_NAME", "Admin")
_LOGIN_PATH = "/.auth/login/aad?post_login_redirect_uri=/admin"


@dataclasses.dataclass
class AdminPrincipal:
    user_id: str
    name: str
    roles: list[str]

    @property
    def is_admin(self) -> bool:
        return ADMIN_APP_ROLE_NAME in self.roles


def _get_principal(request: Request) -> AdminPrincipal | None:
    encoded = request.headers.get("x-ms-client-principal")
    if not encoded:
        return None
    try:
        payload = json.loads(base64.b64decode(encoded))
    except (binascii.Error, json.JSONDecodeError):
        return None
    claims = payload.get("claims", [])
    roles = [c["val"] for c in claims if c.get("typ") == "roles"]
    name = next((c["val"] for c in claims if c.get("typ") == "name"), payload.get("userDetails", "unknown"))
    return AdminPrincipal(user_id=payload.get("userId", ""), name=name, roles=roles)


def _require_admin(request: Request) -> AdminPrincipal | Response:
    principal = _get_principal(request)
    if principal is None:
        return RedirectResponse(_LOGIN_PATH)
    if not principal.is_admin:
        return JSONResponse({"error": "forbidden"}, status_code=403)
    return principal


def _store(request: Request) -> ClientSecretStore:
    return request.app.state.store


async def _tool_names() -> list[str]:
    return sorted(tool.name for tool in await tool_server.list_tools())


def _scopes_summary(record) -> str:
    scopes = json.loads(record.scopes) if record.scopes else []
    return "all tools" if not scopes else ", ".join(scopes)


async def list_secrets(request: Request) -> Response:
    principal = _require_admin(request)
    if not isinstance(principal, AdminPrincipal):
        return principal
    secret_list = await _store(request).list()
    return templates.TemplateResponse(
        request,
        "secrets_list.html",
        {"principal": principal, "secrets": secret_list, "scopes_summary": _scopes_summary},
    )


async def new_secret_form(request: Request) -> Response:
    principal = _require_admin(request)
    if not isinstance(principal, AdminPrincipal):
        return principal
    return templates.TemplateResponse(
        request, "secret_new.html", {"principal": principal, "tools": await _tool_names()}
    )


async def create_secret(request: Request) -> Response:
    principal = _require_admin(request)
    if not isinstance(principal, AdminPrincipal):
        return principal
    form = await request.form()
    label = str(form.get("label", "")).strip()
    if not label:
        return JSONResponse({"error": "label is required"}, status_code=400)
    scopes = [str(v) for v in form.getlist("scopes")]
    token, record = await _store(request).create(label=label, created_by=principal.name, scopes=scopes)
    return templates.TemplateResponse(
        request,
        "secret_created.html",
        {"principal": principal, "token": token, "record": record, "scopes_summary": _scopes_summary(record)},
    )


async def revoke_secret(request: Request) -> Response:
    principal = _require_admin(request)
    if not isinstance(principal, AdminPrincipal):
        return principal
    await _store(request).revoke(request.path_params["key_id"])
    return RedirectResponse("/admin", status_code=303)


async def api_list_secrets(request: Request) -> Response:
    principal = _require_admin(request)
    if not isinstance(principal, AdminPrincipal):
        return principal
    secret_list = await _store(request).list()
    return JSONResponse([dataclasses.asdict(s) for s in secret_list])


async def api_create_secret(request: Request) -> Response:
    principal = _require_admin(request)
    if not isinstance(principal, AdminPrincipal):
        return principal
    body = await request.json()
    label = str(body.get("label", "")).strip()
    if not label:
        return JSONResponse({"error": "label is required"}, status_code=400)
    scopes = [str(v) for v in body.get("scopes", [])]
    token, record = await _store(request).create(label=label, created_by=principal.name, scopes=scopes)
    return JSONResponse({"token": token, "record": dataclasses.asdict(record)})


async def api_list_tools(request: Request) -> Response:
    principal = _require_admin(request)
    if not isinstance(principal, AdminPrincipal):
        return principal
    return JSONResponse(await _tool_names())


async def api_revoke_secret(request: Request) -> Response:
    principal = _require_admin(request)
    if not isinstance(principal, AdminPrincipal):
        return principal
    await _store(request).revoke(request.path_params["key_id"])
    return JSONResponse({"ok": True})


async def openapi_json(request: Request) -> Response:
    principal = _require_admin(request)
    if not isinstance(principal, AdminPrincipal):
        return principal
    return JSONResponse(OPENAPI_SPEC)


async def api_docs(request: Request) -> Response:
    principal = _require_admin(request)
    if not isinstance(principal, AdminPrincipal):
        return principal
    return HTMLResponse(SWAGGER_UI_HTML)


def build_admin_app(store: ClientSecretStore) -> Starlette:
    app = Starlette(
        routes=[
            Route("/", list_secrets, methods=["GET"]),
            Route("/secrets/new", new_secret_form, methods=["GET"]),
            Route("/secrets", create_secret, methods=["POST"]),
            Route("/secrets/{key_id}/revoke", revoke_secret, methods=["POST"]),
            Route("/api/secrets", api_list_secrets, methods=["GET"]),
            Route("/api/secrets", api_create_secret, methods=["POST"]),
            Route("/api/secrets/{key_id}/revoke", api_revoke_secret, methods=["POST"]),
            Route("/api/tools", api_list_tools, methods=["GET"]),
            Route("/openapi.json", openapi_json, methods=["GET"]),
            Route("/docs", api_docs, methods=["GET"]),
        ],
    )
    app.state.store = store
    return app
