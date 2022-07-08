from typing import List

import pytest
from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st
from pytest_httpserver import HTTPServer

from harborapi.client import HarborAsyncClient
from harborapi.models.models import AuditLog

from ..utils import json_from_list


@pytest.mark.asyncio
@given(st.lists(st.builds(AuditLog)))
@settings(suppress_health_check=[HealthCheck.function_scoped_fixture])
async def test_get_audit_logs_mock(
    async_client: HarborAsyncClient,
    httpserver: HTTPServer,
    audit_logs: List[AuditLog],
):
    httpserver.expect_oneshot_request(
        "/api/v2.0/audit-logs",
        method="GET",
    ).respond_with_data(
        json_from_list(audit_logs),
        headers={"Content-Type": "application/json"},
    )
    async_client.url = httpserver.url_for("/api/v2.0")

    logs = await async_client.get_audit_logs()
    assert logs == audit_logs
