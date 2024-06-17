from __future__ import annotations

import pytest
from hypothesis import HealthCheck
from hypothesis import given
from hypothesis import settings
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
    ).respond_with_data(icon.model_dump_json(), content_type="application/json")

    resp = await async_client.get_icon("digest")
    assert resp.content_type == icon.content_type
    assert resp.content == icon.content
