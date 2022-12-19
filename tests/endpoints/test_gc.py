import json
from typing import List

import pytest
from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st
from pytest_httpserver import HTTPServer

from harborapi.client import HarborAsyncClient
from harborapi.models.models import GCHistory, Schedule

from ..utils import json_from_list


@pytest.mark.asyncio
@given(st.builds(Schedule, creation_time=st.datetimes()))
@settings(suppress_health_check=[HealthCheck.function_scoped_fixture])
async def test_get_gc_schedule_mock(
    async_client: HarborAsyncClient,
    httpserver: HTTPServer,
    schedule: Schedule,
):
    async_client.url = httpserver.url_for("/api/v2.0")
    httpserver.expect_oneshot_request(
        "/api/v2.0/system/gc/schedule",
        method="GET",
    ).respond_with_data(schedule.json(), content_type="application/json")
    resp = await async_client.get_gc_schedule()
    assert resp == schedule


@pytest.mark.asyncio
@given(st.builds(Schedule, creation_time=st.datetimes()))
@settings(suppress_health_check=[HealthCheck.function_scoped_fixture])
async def test_create_gc_schedule_mock(
    async_client: HarborAsyncClient,
    httpserver: HTTPServer,
    schedule: Schedule,
):
    expect_location = "/api/v2.0/system/gc/schedule"  # idk?
    async_client.url = httpserver.url_for("/api/v2.0")
    httpserver.expect_oneshot_request(
        "/api/v2.0/system/gc/schedule",
        method="POST",
        json=json.loads(schedule.json(exclude_unset=True)),
    ).respond_with_data(
        headers={"Location": expect_location},
        status=201,
    )
    location = await async_client.create_gc_schedule(schedule)
    assert location == expect_location


@pytest.mark.asyncio
@given(st.builds(Schedule))
@settings(suppress_health_check=[HealthCheck.function_scoped_fixture])
async def test_update_gc_schedule_mock(
    async_client: HarborAsyncClient,
    httpserver: HTTPServer,
    schedule: Schedule,
):
    async_client.url = httpserver.url_for("/api/v2.0")
    httpserver.expect_oneshot_request(
        "/api/v2.0/system/gc/schedule",
        method="PUT",
        json=schedule.dict(exclude_unset=True),
    ).respond_with_data()
    await async_client.update_gc_schedule(schedule)


@pytest.mark.asyncio
@given(st.lists(st.builds(GCHistory)))
@settings(suppress_health_check=[HealthCheck.function_scoped_fixture])
async def test_get_gc_jobs_mock(
    async_client: HarborAsyncClient,
    httpserver: HTTPServer,
    jobs: List[GCHistory],
):
    httpserver.expect_oneshot_request(
        "/api/v2.0/system/gc",
        method="GET",
    ).respond_with_data(
        json_from_list(jobs),
        content_type="application/json",
    )
    async_client.url = httpserver.url_for("/api/v2.0")
    resp = await async_client.get_gc_jobs()
    assert resp == jobs


@pytest.mark.asyncio
@given(st.builds(GCHistory))
@settings(suppress_health_check=[HealthCheck.function_scoped_fixture])
async def test_get_gc_job_mock(
    async_client: HarborAsyncClient,
    httpserver: HTTPServer,
    job: GCHistory,
):
    job.id = 123
    httpserver.expect_oneshot_request(
        "/api/v2.0/system/gc/123",
        method="GET",
    ).respond_with_data(
        job.json(),
        content_type="application/json",
    )
    async_client.url = httpserver.url_for("/api/v2.0")
    resp = await async_client.get_gc_job(123)
    assert resp == job


@pytest.mark.asyncio
@pytest.mark.parametrize("as_list", [True, False])
@given(st.text())
@settings(suppress_health_check=[HealthCheck.function_scoped_fixture])
async def test_get_gc_log_mock(
    async_client: HarborAsyncClient,
    httpserver: HTTPServer,
    as_list: bool,
    log: str,
):
    httpserver.expect_oneshot_request(
        "/api/v2.0/system/gc/123/log",
        method="GET",
    ).respond_with_data(
        log,
        content_type="text/plain",
    )
    async_client.url = httpserver.url_for("/api/v2.0")
    resp = await async_client.get_gc_log(123, as_list=as_list)
    if as_list:
        assert isinstance(resp, list)
        assert resp == log.splitlines()
        assert len(resp) == len(log.splitlines())
        # any other reasonable assertions?
    else:
        assert resp == log
