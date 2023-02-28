import pytest
from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st
from pytest_httpserver import HTTPServer

from harborapi.client import HarborAsyncClient
from harborapi.models import Icon


@pytest.mark.asyncio
@given(st.builds(Icon))
@settings(suppress_health_check=[HealthCheck.function_scoped_fixture])
async def test_get_icon_mock(
    async_client: HarborAsyncClient,
    httpserver: HTTPServer,
    icon: Icon,
):
    httpserver.expect_oneshot_request(
        "/api/v2.0/icons/digest", method="GET"
    ).respond_with_data(icon.json(), content_type="application/json")
    async_client.url = httpserver.url_for("/api/v2.0")
    resp = await async_client.get_icon("digest")
    assert resp.content_type == icon.content_type
    assert resp.content == icon.content
