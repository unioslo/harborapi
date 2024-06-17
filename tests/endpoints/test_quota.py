from __future__ import annotations

from typing import List

import pytest
from hypothesis import HealthCheck
from hypothesis import given
from hypothesis import settings
from hypothesis import strategies as st
from pytest_httpserver import HTTPServer

from harborapi.client import HarborAsyncClient
from harborapi.models import Quota
from harborapi.models.models import QuotaUpdateReq
from harborapi.models.models import ResourceList


@pytest.mark.asyncio
@given(st.lists(st.builds(Quota)))
@settings(suppress_health_check=[HealthCheck.function_scoped_fixture])
async def test_get_quotas_mock(
    async_client: HarborAsyncClient,
    httpserver: HTTPServer,
    quotas: List[Quota],
):
    httpserver.expect_oneshot_request(
        "/api/v2.0/quotas", method="GET"
    ).respond_with_json([q.model_dump(mode="json", exclude_unset=True) for q in quotas])

    resp = await async_client.get_quotas()
    if quotas:
        assert resp == quotas


@pytest.mark.asyncio
async def test_update_quota(async_client: HarborAsyncClient, httpserver: HTTPServer):
    httpserver.expect_oneshot_request(
        "/api/v2.0/quotas/1234",
        method="PUT",
        json={"hard": {"storage": 100, "storage2": 200}},
    ).respond_with_data()

    await async_client.update_quota(
        1234,
        QuotaUpdateReq(
            hard=ResourceList(
                storage=100,  # type: ignore
                storage2=200,  # type: ignore
            )
        ),
    )


@pytest.mark.asyncio
@given(st.builds(Quota))
@settings(suppress_health_check=[HealthCheck.function_scoped_fixture])
async def test_get_quota_mock(
    async_client: HarborAsyncClient,
    httpserver: HTTPServer,
    quota: Quota,
):
    httpserver.expect_oneshot_request(
        "/api/v2.0/quotas/1234", method="GET"
    ).respond_with_json(quota.model_dump(mode="json", exclude_unset=True))

    resp = await async_client.get_quota(1234)
    assert resp == quota
