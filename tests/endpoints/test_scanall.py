import pytest
from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st
from pytest_httpserver import HTTPServer

from harborapi.client import HarborAsyncClient
from harborapi.models import Schedule, Stats


@pytest.mark.asyncio
@given(st.builds(Stats))
@settings(suppress_health_check=[HealthCheck.function_scoped_fixture])
async def test_get_scan_all_metrics_mock(
    async_client: HarborAsyncClient,
    httpserver: HTTPServer,
    stats: Stats,
):
    httpserver.expect_oneshot_request(
        "/api/v2.0/scans/all/metrics", method="GET"
    ).respond_with_json(stats.dict())
    async_client.url = httpserver.url_for("/api/v2.0")
    metrics = await async_client.get_scan_all_metrics()
    assert metrics is not None


@pytest.mark.asyncio
@given(st.builds(Schedule))
@settings(suppress_health_check=[HealthCheck.function_scoped_fixture])
async def test_update_scan_all_schedule_mock(
    async_client: HarborAsyncClient,
    httpserver: HTTPServer,
    schedule: Schedule,
):
    # TODO: use st.lists(st.builds(ScannerRegistration)) to generate a list of scanners
    httpserver.expect_oneshot_request(
        "/api/v2.0/system/scanAll/schedule", method="PUT"
    ).respond_with_data()
    async_client.url = httpserver.url_for("/api/v2.0")
    await async_client.update_scan_all_schedule(
        schedule
    )  # just test endpoint is working


@pytest.mark.asyncio
@given(st.builds(Schedule))
@settings(suppress_health_check=[HealthCheck.function_scoped_fixture])
async def test_create_scan_all_schedule_mock(
    async_client: HarborAsyncClient,
    httpserver: HTTPServer,
    schedule: Schedule,
):
    # TODO: use st.lists(st.builds(ScannerRegistration)) to generate a list of scanners
    httpserver.expect_oneshot_request(
        "/api/v2.0/system/scanAll/schedule", method="POST"
    ).respond_with_data(
        status=201, headers={"Location": "/system/scanAll/schedules/1234"}
    )
    async_client.url = httpserver.url_for("/api/v2.0")
    resp = await async_client.create_scan_all_schedule(schedule)
    assert resp == "/system/scanAll/schedules/1234"


@pytest.mark.asyncio
@given(st.builds(Schedule))
@settings(suppress_health_check=[HealthCheck.function_scoped_fixture])
async def test_get_scan_all_schedule(
    async_client: HarborAsyncClient,
    httpserver: HTTPServer,
    schedule: Schedule,
):
    # TODO: use st.lists(st.builds(ScannerRegistration)) to generate a list of scanners
    httpserver.expect_oneshot_request(
        "/api/v2.0/system/scanAll/schedule", method="GET"
    ).respond_with_json(schedule.dict())
    async_client.url = httpserver.url_for("/api/v2.0")
    schedule_resp = await async_client.get_scan_all_schedule()
    assert schedule_resp == schedule


@pytest.mark.asyncio
async def test_stop_scan_all_job(
    async_client: HarborAsyncClient, httpserver: HTTPServer
):
    httpserver.expect_oneshot_request(
        "/api/v2.0/system/scanAll/stop", method="POST"
    ).respond_with_data()
    async_client.url = httpserver.url_for("/api/v2.0")
    await async_client.stop_scan_all_job()
