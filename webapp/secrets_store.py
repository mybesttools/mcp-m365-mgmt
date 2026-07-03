"""Client secret storage for the /mcp bearer-token auth surface.

Secrets are issued as `amk_<key_id>.<secret>` tokens. Only a salted hash of the
secret half is ever stored; the plaintext token is shown to the admin once, at
creation time. Verification is a point-read on `key_id` (not a full-table scan),
so lookups stay O(1) regardless of how many secrets have been issued.
"""

from __future__ import annotations

import asyncio
import base64
import hashlib
import hmac
import os
import secrets as secrets_module
import string
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any

from azure.core.exceptions import ResourceNotFoundError
from azure.data.tables.aio import TableServiceClient
from azure.identity.aio import DefaultAzureCredential

TABLE_NAME = "ClientSecrets"
PARTITION_KEY = "secret"
TOKEN_PREFIX = "amk_"

# Table Storage writes on every request would add latency to every MCP call, so
# lastUsedAt is only refreshed when it's gone stale by more than this.
_LAST_USED_STALE_AFTER = timedelta(minutes=5)

_KEY_ID_ALPHABET = string.ascii_lowercase + string.digits
_KEY_ID_LENGTH = 16


def _generate_key_id() -> str:
    return "".join(secrets_module.choice(_KEY_ID_ALPHABET) for _ in range(_KEY_ID_LENGTH))


def _generate_secret() -> str:
    return base64.urlsafe_b64encode(secrets_module.token_bytes(32)).rstrip(b"=").decode("ascii")


def hash_secret(secret_value: str, pepper: bytes) -> str:
    # HMAC-SHA256, not a slow KDF (PBKDF2/argon2/bcrypt): these are 256-bit
    # machine-generated tokens, not human passwords, so a slow hash only adds
    # per-request latency without a real brute-force benefit.
    return hmac.new(pepper, secret_value.encode("utf-8"), hashlib.sha256).hexdigest()


@dataclass
class SecretRecord:
    key_id: str
    label: str
    created_at: str
    created_by: str
    revoked: bool
    revoked_at: str | None
    last_used_at: str | None
    scopes: str  # JSON-encoded list; unused today, reserved for future per-secret tool scoping


def _record_from_entity(entity: dict[str, Any]) -> SecretRecord:
    return SecretRecord(
        key_id=entity["RowKey"],
        label=entity["label"],
        created_at=entity["createdAt"],
        created_by=entity["createdBy"],
        revoked=bool(entity.get("revoked")),
        revoked_at=entity.get("revokedAt"),
        last_used_at=entity.get("lastUsedAt"),
        scopes=entity.get("scopes", "[]"),
    )


class ClientSecretStore:
    def __init__(self, table_service: TableServiceClient, pepper: bytes):
        self._table_service = table_service
        self._pepper = pepper
        self._table_client = table_service.get_table_client(TABLE_NAME)

    @classmethod
    def from_env(cls) -> "ClientSecretStore":
        account_name = os.environ["STORAGE_ACCOUNT_NAME"]
        pepper = os.environ["SECRET_PEPPER"].encode("utf-8")
        endpoint = f"https://{account_name}.table.core.windows.net"
        table_service = TableServiceClient(endpoint=endpoint, credential=DefaultAzureCredential())
        return cls(table_service, pepper)

    async def __aenter__(self) -> "ClientSecretStore":
        await self._table_service.create_table_if_not_exists(TABLE_NAME)
        return self

    async def __aexit__(self, *exc_info: object) -> None:
        await self._table_service.close()

    async def create(self, label: str, created_by: str) -> tuple[str, SecretRecord]:
        key_id = _generate_key_id()
        secret_value = _generate_secret()
        now = datetime.now(timezone.utc).isoformat()
        entity = {
            "PartitionKey": PARTITION_KEY,
            "RowKey": key_id,
            "secretHash": hash_secret(secret_value, self._pepper),
            "label": label,
            "createdAt": now,
            "createdBy": created_by,
            "revoked": False,
            "revokedAt": None,
            "lastUsedAt": None,
            "scopes": "[]",
        }
        await self._table_client.create_entity(entity)
        token = f"{TOKEN_PREFIX}{key_id}.{secret_value}"
        return token, _record_from_entity(entity)

    async def list(self) -> list[SecretRecord]:
        records = [
            _record_from_entity(entity)
            async for entity in self._table_client.query_entities(f"PartitionKey eq '{PARTITION_KEY}'")
        ]
        records.sort(key=lambda r: r.created_at, reverse=True)
        return records

    async def revoke(self, key_id: str) -> None:
        await self._table_client.update_entity(
            {
                "PartitionKey": PARTITION_KEY,
                "RowKey": key_id,
                "revoked": True,
                "revokedAt": datetime.now(timezone.utc).isoformat(),
            },
            mode="merge",
        )

    async def verify(self, token: str) -> SecretRecord | None:
        if not token.startswith(TOKEN_PREFIX) or "." not in token:
            return None
        key_id, _, secret_value = token[len(TOKEN_PREFIX):].partition(".")
        if not key_id or not secret_value:
            return None

        try:
            entity = await self._table_client.get_entity(PARTITION_KEY, key_id)
        except ResourceNotFoundError:
            return None

        if entity.get("revoked"):
            return None
        if not hmac.compare_digest(entity["secretHash"], hash_secret(secret_value, self._pepper)):
            return None

        self._touch_last_used_if_stale(entity)
        return _record_from_entity(entity)

    def _touch_last_used_if_stale(self, entity: dict[str, Any]) -> None:
        now = datetime.now(timezone.utc)
        last_used_raw = entity.get("lastUsedAt")
        if last_used_raw:
            last_used = datetime.fromisoformat(last_used_raw)
            if now - last_used < _LAST_USED_STALE_AFTER:
                return
        # Fire-and-forget: never let a lastUsedAt write slow down or fail an auth check.
        asyncio.create_task(self._touch_last_used(entity["RowKey"], now))

    async def _touch_last_used(self, key_id: str, now: datetime) -> None:
        try:
            await self._table_client.update_entity(
                {"PartitionKey": PARTITION_KEY, "RowKey": key_id, "lastUsedAt": now.isoformat()},
                mode="merge",
            )
        except Exception:
            pass
