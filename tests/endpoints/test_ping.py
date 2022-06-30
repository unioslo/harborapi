import pytest
from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st
from pytest_httpserver import HTTPServer

from harborapi.client import HarborAsyncClient


@pytest.mark.asyncio
async def test_ping_harbor_api(
    async_client: HarborAsyncClient,
    httpserver: HTTPServer,
):
    httpserver.expect_request("/api/v2.0/ping").respond_with_data("pong")
    async_client.url = httpserver.url_for("/api/v2.0")
    pong = await async_client.ping_harbor_api()
    assert pong == "pong"
