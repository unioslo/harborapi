from typing import List

import pytest
from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st
from pytest_httpserver import HTTPServer

from harborapi.client import HarborAsyncClient
from harborapi.models import Search


@pytest.mark.asyncio
@given(st.builds(Search))
@settings(suppress_health_check=[HealthCheck.function_scoped_fixture])
async def test_search_mock(
    async_client: HarborAsyncClient,
    httpserver: HTTPServer,
    search: Search,
):
    httpserver.expect_oneshot_request(
        "/api/v2.0/search", method="GET", query_string={"q": "testproj"}
    ).respond_with_data(search.json(), content_type="application/json")
    async_client.url = httpserver.url_for("/api/v2.0")
    resp = await async_client.search("testproj")
    assert resp == search
