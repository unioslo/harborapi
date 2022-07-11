import pytest
from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st
from pytest_httpserver import HTTPServer

from harborapi.client import HarborAsyncClient
from harborapi.models import Statistic


@pytest.mark.asyncio
@given(st.builds(Statistic))
@settings(suppress_health_check=[HealthCheck.function_scoped_fixture])
async def test_get_statistics_mock(
    async_client: HarborAsyncClient,
    httpserver: HTTPServer,
    statistic: Statistic,
):
    httpserver.expect_oneshot_request(
        "/api/v2.0/statistics", method="GET"
    ).respond_with_json(statistic.dict())
    async_client.url = httpserver.url_for("/api/v2.0")
    resp = await async_client.get_statistics()
    assert resp == statistic
