from webapp.secrets_store import ClientSecretStore, hash_secret


async def test_create_then_verify_round_trip(store: ClientSecretStore):
    token, record = await store.create(label="test-agent", created_by="admin@example.com")
    assert record.label == "test-agent"
    assert not record.revoked

    verified = await store.verify(token)
    assert verified is not None
    assert verified.key_id == record.key_id


async def test_verify_rejects_wrong_secret(store: ClientSecretStore):
    token, record = await store.create(label="test-agent", created_by="admin@example.com")
    tampered = f"amk_{record.key_id}.not-the-real-secret"

    assert await store.verify(tampered) is None


async def test_verify_rejects_unknown_key_id(store: ClientSecretStore):
    assert await store.verify("amk_doesnotexist.somesecret") is None


async def test_verify_rejects_malformed_token(store: ClientSecretStore):
    assert await store.verify("not-even-the-right-prefix") is None
    assert await store.verify("amk_missing_dot_separator") is None


async def test_verify_rejects_revoked_secret(store: ClientSecretStore):
    token, record = await store.create(label="test-agent", created_by="admin@example.com")
    await store.revoke(record.key_id)

    assert await store.verify(token) is None

    listed = await store.list()
    assert listed[0].revoked is True
    assert listed[0].revoked_at is not None


async def test_list_returns_created_secrets(store: ClientSecretStore):
    await store.create(label="agent-a", created_by="admin@example.com")
    await store.create(label="agent-b", created_by="admin@example.com")

    labels = {record.label for record in await store.list()}
    assert labels == {"agent-a", "agent-b"}


def test_hash_secret_is_deterministic_and_pepper_sensitive():
    assert hash_secret("abc", b"pepper1") == hash_secret("abc", b"pepper1")
    assert hash_secret("abc", b"pepper1") != hash_secret("abc", b"pepper2")
