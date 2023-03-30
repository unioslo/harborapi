from typing import List, Optional

import pytest
from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st
from pytest_httpserver import HTTPServer

from harborapi.client import HarborAsyncClient
from harborapi.models import Repository
from harborapi.models.models import ExecHistory, Schedule

from ..utils import json_from_list


@pytest.mark.asyncio
@given(st.builds(ExecHistory))
@settings(suppress_health_check=[HealthCheck.function_scoped_fixture])
async def test_get_audit_log_rotation_mock(
    async_client: HarborAsyncClient,
    httpserver: HTTPServer,
    status: ExecHistory,
):
    httpserver.expect_oneshot_request(
        "/api/v2.0/system/purgeaudit/1234", method="GET"
    ).respond_with_data(status.json(), content_type="application/json")
    async_client.url = httpserver.url_for("/api/v2.0")
    resp = await async_client.get_audit_log_rotation("1234")
    assert resp == status


@pytest.mark.asyncio
async def test_get_audit_log_rotation_log_mock(
    async_client: HarborAsyncClient,
    httpserver: HTTPServer,
):
    httpserver.expect_oneshot_request(
        "/api/v2.0/system/purgeaudit/1234/log", method="GET"
    ).respond_with_data("Hello World")
    async_client.url = httpserver.url_for("/api/v2.0")
    resp = await async_client.get_audit_log_rotation_log(1234)
    assert resp == "Hello World"


@pytest.mark.asyncio
@given(st.builds(Schedule))
@settings(suppress_health_check=[HealthCheck.function_scoped_fixture])
async def test_update_audit_log_rotation_schedule_mock(
    async_client: HarborAsyncClient,
    httpserver: HTTPServer,
    schedule: Schedule,
):
    httpserver.expect_oneshot_request(
        "/api/v2.0/system/purgeaudit/schedule", method="PUT"
    ).respond_with_data()
    async_client.url = httpserver.url_for("/api/v2.0")
    await async_client.update_audit_log_rotation_schedule(schedule)


@pytest.mark.asyncio
async def test_stop_audit_log_rotation_mock(
    async_client: HarborAsyncClient,
    httpserver: HTTPServer,
):
    httpserver.expect_oneshot_request(
        "/api/v2.0/system/purgeaudit/1234",
        method="PUT",
    ).respond_with_data()
    async_client.url = httpserver.url_for("/api/v2.0")
    await async_client.stop_audit_log_rotation(1234)


@pytest.mark.asyncio
@given(st.builds(Schedule))
@settings(suppress_health_check=[HealthCheck.function_scoped_fixture])
async def test_create_audit_log_rotation_schedule_mock(
    async_client: HarborAsyncClient,
    httpserver: HTTPServer,
    schedule: Schedule,
):
    httpserver.expect_oneshot_request(
        "/api/v2.0/system/purgeaudit/schedule", method="POST"
    ).respond_with_data(headers={"Location": "1234"})
    async_client.url = httpserver.url_for("/api/v2.0")
    resp = await async_client.create_audit_log_rotation_schedule(schedule)
    assert resp == "1234"


@pytest.mark.asyncio
@given(st.builds(ExecHistory))
@settings(suppress_health_check=[HealthCheck.function_scoped_fixture])
async def test_get_audit_log_rotation_schedule_mock(
    async_client: HarborAsyncClient,
    httpserver: HTTPServer,
    schedule: ExecHistory,
):
    httpserver.expect_oneshot_request(
        "/api/v2.0/system/purgeaudit/schedule", method="GET"
    ).respond_with_data(schedule.json(), content_type="application/json")
    async_client.url = httpserver.url_for("/api/v2.0")
    resp = await async_client.get_audit_log_rotation_schedule()
    assert resp == schedule


@pytest.mark.asyncio
async def test_get_audit_log_rotation_schedule_none(
    async_client: HarborAsyncClient,
    httpserver: HTTPServer,
):
    """Tests cases where the API returns a 200 OK response, with an empty body."""
    httpserver.expect_oneshot_request(
        "/api/v2.0/system/purgeaudit/schedule", method="GET"
    ).respond_with_data("", content_type="application/json")
    async_client.url = httpserver.url_for("/api/v2.0")
    resp = await async_client.get_audit_log_rotation_schedule()
    assert resp == ExecHistory()  # expect empty ExecHistory object


@pytest.mark.asyncio
@given(st.lists(st.builds(ExecHistory)))
@settings(suppress_health_check=[HealthCheck.function_scoped_fixture])
async def test_get_audit_log_rotation_history_mock(
    async_client: HarborAsyncClient,
    httpserver: HTTPServer,
    logs: List[ExecHistory],
):
    httpserver.expect_oneshot_request(
        "/api/v2.0/system/purgeaudit", method="GET"
    ).respond_with_data(
        json_from_list(logs),
        headers={"Content-Type": "application/json"},
    )
    async_client.url = httpserver.url_for("/api/v2.0")
    resp = await async_client.get_audit_log_rotation_history()
    assert resp == logs
