from __future__ import annotations

from typing import List

import pytest
from hypothesis import given
from hypothesis import HealthCheck
from hypothesis import settings
from hypothesis import strategies as st
from pytest_httpserver import HTTPServer

from ..utils import json_from_list
from harborapi.client import HarborAsyncClient
from harborapi.models import Registry
from harborapi.models import RegistryInfo
from harborapi.models import RegistryPing
from harborapi.models import RegistryProviders
from harborapi.models import RegistryUpdate


@pytest.mark.asyncio
@given(st.builds(RegistryPing))
@settings(suppress_health_check=[HealthCheck.function_scoped_fixture])
async def test_check_registry_status_mock(
    async_client: HarborAsyncClient,
    httpserver: HTTPServer,
    ping: RegistryPing,
):
    httpserver.expect_oneshot_request(
        "/api/v2.0/registries/ping",
        method="POST",
        json=ping.model_dump(mode="json", exclude_unset=True),
    ).respond_with_data()
    async_client.url = httpserver.url_for("/api/v2.0")
    await async_client.check_registry_status(ping)


@pytest.mark.asyncio
@given(st.lists(st.text()))
@settings(suppress_health_check=[HealthCheck.function_scoped_fixture])
async def test_get_registry_adapters_mock(
    async_client: HarborAsyncClient,
    httpserver: HTTPServer,
    adapters: List[str],
):
    httpserver.expect_oneshot_request(
        "/api/v2.0/replication/adapters",
        method="GET",
    ).respond_with_json(adapters)
    async_client.url = httpserver.url_for("/api/v2.0")
    await async_client.get_registry_adapters()


@pytest.mark.asyncio
@given(st.builds(RegistryInfo))
@settings(suppress_health_check=[HealthCheck.function_scoped_fixture])
async def test_get_registry_info_mock(
    async_client: HarborAsyncClient,
    httpserver: HTTPServer,
    registryinfo: RegistryInfo,
):
    httpserver.expect_oneshot_request(
        "/api/v2.0/registries/123/info", method="GET"
    ).respond_with_json(registryinfo.model_dump(mode="json", exclude_unset=True))
    async_client.url = httpserver.url_for("/api/v2.0")
    await async_client.get_registry_info(123)


@pytest.mark.asyncio
@given(st.builds(RegistryProviders))
@settings(suppress_health_check=[HealthCheck.function_scoped_fixture])
async def test_get_registry_providers_mock(
    async_client: HarborAsyncClient,
    httpserver: HTTPServer,
    providers: RegistryProviders,
):
    httpserver.expect_oneshot_request(
        "/api/v2.0/replication/adapterinfos", method="GET"
    ).respond_with_data(
        providers.model_dump_json(),
        headers={"Content-Type": "application/json"},
    )
    async_client.url = httpserver.url_for("/api/v2.0")
    resp = await async_client.get_registry_providers()
    assert resp == providers


@pytest.mark.asyncio
@given(st.builds(RegistryUpdate))
@settings(suppress_health_check=[HealthCheck.function_scoped_fixture])
async def test_update_registry_mock(
    async_client: HarborAsyncClient,
    httpserver: HTTPServer,
    registry: RegistryUpdate,
):
    httpserver.expect_oneshot_request(
        "/api/v2.0/registries/123",
        method="PUT",
        json=registry.model_dump(mode="json", exclude_unset=True),
    ).respond_with_data()
    async_client.url = httpserver.url_for("/api/v2.0")
    await async_client.update_registry(123, registry)


@pytest.mark.asyncio
@given(st.builds(Registry))
@settings(suppress_health_check=[HealthCheck.function_scoped_fixture])
async def test_get_registry_mock(
    async_client: HarborAsyncClient,
    httpserver: HTTPServer,
    registry: RegistryUpdate,
):
    httpserver.expect_oneshot_request(
        "/api/v2.0/registries/123", method="GET"
    ).respond_with_json(registry.model_dump(mode="json", exclude_unset=True))
    async_client.url = httpserver.url_for("/api/v2.0")
    resp = await async_client.get_registry(123)
    assert resp == registry


@pytest.mark.asyncio
async def test_delete_registry_mock(
    async_client: HarborAsyncClient,
    httpserver: HTTPServer,
):
    httpserver.expect_oneshot_request(
        "/api/v2.0/registries/123", method="DELETE"
    ).respond_with_data()
    async_client.url = httpserver.url_for("/api/v2.0")
    # TODO test missing_ok=True
    await async_client.delete_registry(123)


@pytest.mark.asyncio
@given(st.builds(Registry))
@settings(suppress_health_check=[HealthCheck.function_scoped_fixture])
async def test_create_registry_mock(
    async_client: HarborAsyncClient,
    httpserver: HTTPServer,
    registry: Registry,
):
    httpserver.expect_oneshot_request(
        "/api/v2.0/registries",
        method="POST",
        json=registry.model_dump(mode="json", exclude_unset=True),
    ).respond_with_data(headers={"Location": "/api/v2.0/registries/123"})
    async_client.url = httpserver.url_for("/api/v2.0")
    resp = await async_client.create_registry(registry)
    assert resp == "/api/v2.0/registries/123"


@pytest.mark.asyncio
@given(st.lists(st.builds(Registry)))
@settings(suppress_health_check=[HealthCheck.function_scoped_fixture])
async def test_get_registries_mock(
    async_client: HarborAsyncClient,
    httpserver: HTTPServer,
    registries: List[Registry],
):
    httpserver.expect_oneshot_request(
        "/api/v2.0/registries", method="GET"
    ).respond_with_data(json_from_list(registries), content_type="application/json")
    async_client.url = httpserver.url_for("/api/v2.0")
    resp = await async_client.get_registries()
    assert resp == registries
