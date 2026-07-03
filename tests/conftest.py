"""In-memory fakes for azure-data-tables so secrets_store/auth_middleware tests
don't need a real storage account or Azurite."""

from __future__ import annotations

import copy

import pytest
from azure.core.exceptions import ResourceNotFoundError

from webapp.secrets_store import ClientSecretStore


class FakeTableClient:
    def __init__(self) -> None:
        self._entities: dict[tuple[str, str], dict] = {}

    async def create_entity(self, entity: dict) -> None:
        key = (entity["PartitionKey"], entity["RowKey"])
        self._entities[key] = copy.deepcopy(entity)

    async def get_entity(self, partition_key: str, row_key: str) -> dict:
        try:
            return copy.deepcopy(self._entities[(partition_key, row_key)])
        except KeyError:
            raise ResourceNotFoundError("not found")

    async def update_entity(self, entity: dict, mode: str = "merge") -> None:
        key = (entity["PartitionKey"], entity["RowKey"])
        if key not in self._entities:
            raise ResourceNotFoundError("not found")
        self._entities[key].update({k: v for k, v in entity.items() if k not in ("PartitionKey", "RowKey")})

    async def query_entities(self, filter: str):  # noqa: A002 - matches azure SDK signature
        for entity in list(self._entities.values()):
            yield copy.deepcopy(entity)


class FakeTableServiceClient:
    def __init__(self) -> None:
        self._table = FakeTableClient()

    def get_table_client(self, name: str) -> FakeTableClient:
        return self._table

    async def create_table_if_not_exists(self, name: str) -> None:
        pass

    async def close(self) -> None:
        pass


@pytest.fixture
def store() -> ClientSecretStore:
    return ClientSecretStore(FakeTableServiceClient(), pepper=b"test-pepper")
