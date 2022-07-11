import pytest
from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st
from pytest_httpserver import HTTPServer

from harborapi.client import HarborAsyncClient
from harborapi.models import SystemInfo
from harborapi.models.models import GeneralInfo


@pytest.mark.asyncio
@given(st.builds(SystemInfo))
@settings(suppress_health_check=[HealthCheck.function_scoped_fixture])
async def test_get_system_volume_info_mock(
    async_client: HarborAsyncClient,
    httpserver: HTTPServer,
    systeminfo: SystemInfo,
):
    httpserver.expect_oneshot_request(
        "/api/v2.0/systeminfo/volumes", method="GET"
    ).respond_with_json(systeminfo.dict())
    async_client.url = httpserver.url_for("/api/v2.0")
    resp = await async_client.get_system_volume_info()
    assert resp == systeminfo


@pytest.mark.asyncio
@given(st.builds(GeneralInfo))
@settings(suppress_health_check=[HealthCheck.function_scoped_fixture])
async def test_get_system_info_mock(
    async_client: HarborAsyncClient,
    httpserver: HTTPServer,
    generalinfo: GeneralInfo,
):
    httpserver.expect_oneshot_request(
        "/api/v2.0/systeminfo", method="GET"
    ).respond_with_json(generalinfo.dict())
    async_client.url = httpserver.url_for("/api/v2.0")
    resp = await async_client.get_system_info()
    assert resp == generalinfo
