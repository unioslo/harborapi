from __future__ import annotations

import pytest
from hypothesis import HealthCheck
from hypothesis import given
from hypothesis import settings
from hypothesis import strategies as st
from pytest_httpserver import HTTPServer

from harborapi.client import HarborAsyncClient
from harborapi.models.models import Permissions


@pytest.mark.asyncio
@given(st.builds(Permissions))
@settings(suppress_health_check=[HealthCheck.function_scoped_fixture])
async def test_get_permissions(
    async_client: HarborAsyncClient,
    httpserver: HTTPServer,
    permissions: Permissions,
):
    httpserver.expect_oneshot_request(
        "/api/v2.0/permissions",
        method="GET",
    ).respond_with_json(
        permissions.model_dump(mode="json"),
        headers={"Content-Type": "application/json"},
    )

    resp = await async_client.get_permissions()
    assert resp == permissions
