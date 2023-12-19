from __future__ import annotations

import pytest
from hypothesis import given
from hypothesis import HealthCheck
from hypothesis import settings
from hypothesis import strategies as st
from pytest_httpserver import HTTPServer

from harborapi.client import HarborAsyncClient
from harborapi.models.models import Configurations
from harborapi.models.models import ConfigurationsResponse


@pytest.mark.asyncio
@given(st.builds(ConfigurationsResponse))
@settings(suppress_health_check=[HealthCheck.function_scoped_fixture])
async def test_get_config_mock(
    async_client: HarborAsyncClient,
    httpserver: HTTPServer,
    config: ConfigurationsResponse,
):
    httpserver.expect_oneshot_request(
        "/api/v2.0/configurations",
        method="GET",
    ).respond_with_json(config.model_dump(mode="json"))
    async_client.url = httpserver.url_for("/api/v2.0")
    resp = await async_client.get_config()
    assert resp == config


@pytest.mark.asyncio
@given(st.builds(Configurations))
@settings(suppress_health_check=[HealthCheck.function_scoped_fixture])
async def test_update_config_mock(
    async_client: HarborAsyncClient,
    httpserver: HTTPServer,
    config: Configurations,
):
    httpserver.expect_oneshot_request(
        "/api/v2.0/configurations",
        method="PUT",
        json=config.model_dump(mode="json", exclude_unset=True),
    ).respond_with_data()
    async_client.url = httpserver.url_for("/api/v2.0")
    await async_client.update_config(config)
