from typing import List, Optional

import pytest
from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st
from pytest_httpserver import HTTPServer

from harborapi.client import HarborAsyncClient
from harborapi.models import (
    Registry,
    RegistryInfo,
    RegistryPing,
    RegistryProviderInfo,
    RegistryUpdate,
)

from ..utils import json_from_list


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
        json=ping.dict(exclude_unset=True),
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
    ).respond_with_json(registryinfo.dict())
    async_client.url = httpserver.url_for("/api/v2.0")
    await async_client.get_registry_info(123)


@pytest.mark.asyncio
@given(st.lists(st.builds(RegistryProviderInfo)))
@settings(suppress_health_check=[HealthCheck.function_scoped_fixture])
async def test_get_registry_providers_mock(
    async_client: HarborAsyncClient,
    httpserver: HTTPServer,
    providers: List[RegistryProviderInfo],
):
    httpserver.expect_oneshot_request(
        "/api/v2.0/replication/adapterinfos", method="GET"
    ).respond_with_data(
        json_from_list(providers),
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
        "/api/v2.0/registries/123", method="PUT", json=registry.dict(exclude_unset=True)
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
    ).respond_with_json(registry.dict())
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
        "/api/v2.0/registries", method="POST", json=registry.dict(exclude_unset=True)
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
