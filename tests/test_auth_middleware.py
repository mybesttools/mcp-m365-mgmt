from starlette.applications import Starlette
from starlette.responses import JSONResponse, PlainTextResponse
from starlette.routing import Route
from starlette.testclient import TestClient

from webapp.auth_middleware import BearerSecretMiddleware
from webapp.secrets_store import ClientSecretStore


async def _ok(request):
    return PlainTextResponse("ok")


async def _echo(request):
    # Proves the middleware correctly replays the buffered body to the
    # downstream app after reading it once to check tool scope.
    return JSONResponse(await request.json())


def _client(store: ClientSecretStore) -> TestClient:
    inner = Starlette(routes=[Route("/", _ok), Route("/", _echo, methods=["POST"])])
    app = BearerSecretMiddleware(inner, store=store)
    return TestClient(app)


def test_rejects_missing_authorization_header(store: ClientSecretStore):
    resp = _client(store).get("/")
    assert resp.status_code == 401


def test_rejects_non_bearer_scheme(store: ClientSecretStore):
    resp = _client(store).get("/", headers={"Authorization": "Basic somevalue"})
    assert resp.status_code == 401


async def test_rejects_invalid_token(store: ClientSecretStore):
    resp = _client(store).get("/", headers={"Authorization": "Bearer amk_bad.token"})
    assert resp.status_code == 401


async def test_accepts_valid_token(store: ClientSecretStore):
    token, _ = await store.create(label="test-agent", created_by="admin@example.com")
    resp = _client(store).get("/", headers={"Authorization": f"Bearer {token}"})
    assert resp.status_code == 200
    assert resp.text == "ok"


async def test_rejects_revoked_token(store: ClientSecretStore):
    token, record = await store.create(label="test-agent", created_by="admin@example.com")
    await store.revoke(record.key_id)
    resp = _client(store).get("/", headers={"Authorization": f"Bearer {token}"})
    assert resp.status_code == 401


async def test_unrestricted_secret_can_call_any_tool(store: ClientSecretStore):
    token, _ = await store.create(label="test-agent", created_by="admin@example.com")
    body = {"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {"name": "list_users", "arguments": {}}}
    resp = _client(store).post("/", headers={"Authorization": f"Bearer {token}"}, json=body)
    assert resp.status_code == 200
    assert resp.json() == body  # proves the body reached the downstream app unchanged


async def test_scoped_secret_can_call_allowed_tool(store: ClientSecretStore):
    token, _ = await store.create(
        label="test-agent", created_by="admin@example.com", scopes=["list_users", "list_groups"]
    )
    body = {"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {"name": "list_users", "arguments": {}}}
    resp = _client(store).post("/", headers={"Authorization": f"Bearer {token}"}, json=body)
    assert resp.status_code == 200
    assert resp.json() == body


async def test_scoped_secret_is_denied_for_out_of_scope_tool(store: ClientSecretStore):
    token, _ = await store.create(label="test-agent", created_by="admin@example.com", scopes=["list_users"])
    body = {"jsonrpc": "2.0", "id": 7, "method": "tools/call", "params": {"name": "create_user", "arguments": {}}}
    resp = _client(store).post("/", headers={"Authorization": f"Bearer {token}"}, json=body)
    assert resp.status_code == 200  # JSON-RPC error, not an HTTP-level failure
    payload = resp.json()
    assert payload["id"] == 7
    assert payload["result"]["isError"] is True
    assert "create_user" in payload["result"]["content"][0]["text"]


async def test_scoped_secret_can_still_list_tools(store: ClientSecretStore):
    # Non tools/call methods are never scope-checked -- a restricted secret can
    # still see the full tool catalog, it just can't invoke out-of-scope ones.
    token, _ = await store.create(label="test-agent", created_by="admin@example.com", scopes=["list_users"])
    body = {"jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {}}
    resp = _client(store).post("/", headers={"Authorization": f"Bearer {token}"}, json=body)
    assert resp.status_code == 200
    assert resp.json() == body
