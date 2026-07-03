from starlette.applications import Starlette
from starlette.responses import PlainTextResponse
from starlette.routing import Route
from starlette.testclient import TestClient

from webapp.auth_middleware import BearerSecretMiddleware
from webapp.secrets_store import ClientSecretStore


async def _ok(request):
    return PlainTextResponse("ok")


def _client(store: ClientSecretStore) -> TestClient:
    inner = Starlette(routes=[Route("/", _ok)])
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
