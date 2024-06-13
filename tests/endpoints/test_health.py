from __future__ import annotations

import pytest
from hypothesis import HealthCheck
from hypothesis import given
from hypothesis import settings
from hypothesis import strategies as st
from pytest_httpserver import HTTPServer

from harborapi.client import HarborAsyncClient
from harborapi.models import ComponentHealthStatus
from harborapi.models import OverallHealthStatus


@pytest.mark.asyncio
@given(st.builds(OverallHealthStatus))
@settings(suppress_health_check=[HealthCheck.function_scoped_fixture])
async def test_health_check(
    async_client: HarborAsyncClient,
    httpserver: HTTPServer,
    healthstatus: OverallHealthStatus,
):
    httpserver.expect_oneshot_request(
        "/api/v2.0/health", method="GET"
    ).respond_with_json(healthstatus.model_dump(mode="json"))
    async_client.url = httpserver.url_for("/api/v2.0")
    health = await async_client.health_check()
    assert health == healthstatus
    if health.components:  # TODO: add OverallHealthStatus.components strategy
        assert all(isinstance(i, ComponentHealthStatus) for i in health.components)
