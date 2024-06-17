from __future__ import annotations

import pytest
from hypothesis import HealthCheck
from hypothesis import given
from hypothesis import settings
from pytest_httpserver import HTTPServer

from harborapi.client import HarborAsyncClient
from harborapi.models import CVEAllowlist
from harborapi.models import CVEAllowlistItem

from ..strategies import cveallowlist_strategy


@pytest.mark.asyncio
@given(cveallowlist_strategy)
@settings(suppress_health_check=[HealthCheck.function_scoped_fixture])
async def test_get_cve_allowlist(
    async_client: HarborAsyncClient,
    httpserver: HTTPServer,
    cve_allowlist: CVEAllowlist,
):
    httpserver.expect_oneshot_request(
        "/api/v2.0/system/CVEAllowlist",
        method="GET",
    ).respond_with_json(cve_allowlist.model_dump(mode="json"))

    allowlist = await async_client.get_cve_allowlist()
    assert allowlist == cve_allowlist
    if allowlist.items:
        assert all(isinstance(i, CVEAllowlistItem) for i in allowlist.items)


@pytest.mark.asyncio
@given(cveallowlist_strategy)
@settings(suppress_health_check=[HealthCheck.function_scoped_fixture])
async def test_update_cve_allowlist(
    async_client: HarborAsyncClient,
    httpserver: HTTPServer,
    cve_allowlist: CVEAllowlist,
):
    # TODO: improve this test? We don't have a way to check the response body
    #       when using .update_cve_allowlist(). Call ._put() directly?
    httpserver.expect_oneshot_request(
        "/api/v2.0/system/CVEAllowlist",
        method="PUT",
    ).respond_with_data()

    await async_client.update_cve_allowlist(cve_allowlist)
