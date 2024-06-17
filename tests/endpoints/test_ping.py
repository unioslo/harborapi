from __future__ import annotations

import pytest
from pytest_httpserver import HTTPServer

from harborapi.client import HarborAsyncClient


@pytest.mark.asyncio
async def test_ping(
    async_client: HarborAsyncClient,
    httpserver: HTTPServer,
):
    httpserver.expect_oneshot_request("/api/v2.0/ping").respond_with_data("pong")

    pong = await async_client.ping()
    assert pong == "pong"
