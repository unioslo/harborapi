import pytest
from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st
from pytest_httpserver import HTTPServer

from harborapi.client import HarborAsyncClient
from harborapi.models import (
    ScanDataExportExecution,
    ScanDataExportExecutionList,
    ScanDataExportJob,
    ScanDataExportRequest,
)


@pytest.mark.asyncio
@given(st.builds(ScanDataExportExecutionList))
@settings(suppress_health_check=[HealthCheck.function_scoped_fixture])
async def test_get_scan_exports_mock(
    async_client: HarborAsyncClient,
    httpserver: HTTPServer,
    exports: ScanDataExportExecutionList,
):
    httpserver.expect_oneshot_request(
        f"/api/v2.0/export/cve/executions",
        method="GET",
    ).respond_with_data(
        exports.json(),
        headers={"Content-Type": "application/json"},
    )
    async_client.url = httpserver.url_for("/api/v2.0")
    resp = await async_client.get_scan_exports()
    assert resp == exports


@pytest.mark.asyncio
@given(st.builds(ScanDataExportExecution))
@settings(suppress_health_check=[HealthCheck.function_scoped_fixture])
async def test_get_scan_export_mock(
    async_client: HarborAsyncClient,
    httpserver: HTTPServer,
    execution: ScanDataExportExecution,
):
    execution_id = 123
    httpserver.expect_oneshot_request(
        f"/api/v2.0/export/cve/execution/{execution_id}",
        method="GET",
    ).respond_with_data(
        execution.json(),
        headers={"Content-Type": "application/json"},
    )
    async_client.url = httpserver.url_for("/api/v2.0")
    resp = await async_client.get_scan_export(execution_id)
    assert resp == execution


@pytest.mark.asyncio
@given(st.builds(ScanDataExportRequest), st.builds(ScanDataExportJob))
@settings(suppress_health_check=[HealthCheck.function_scoped_fixture])
async def test_export_scan_data_mock(
    async_client: HarborAsyncClient,
    httpserver: HTTPServer,
    request: ScanDataExportRequest,
    job: ScanDataExportJob,
):
    scan_type = "application/vnd.security.vulnerability.report; version=1.1"
    httpserver.expect_oneshot_request(
        "/api/v2.0/export/cve",
        method="POST",
        headers={"X-Scan-Data-Type": scan_type},
        data=request.json(exclude_unset=True),
    ).respond_with_data(job.json(), content_type="application/json")
    async_client.url = httpserver.url_for("/api/v2.0")
    resp = await async_client.export_scan_data(request, scan_type)
    assert resp == job


@pytest.mark.asyncio
@given(st.binary())
@settings(suppress_health_check=[HealthCheck.function_scoped_fixture])
async def test_download_scan_export_mock(
    async_client: HarborAsyncClient, httpserver: HTTPServer, data: bytes
):
    execution_id = 123
    httpserver.expect_oneshot_request(
        f"/api/v2.0/export/cve/download/{execution_id}",
        method="GET",
    ).respond_with_data(data)
    async_client.url = httpserver.url_for("/api/v2.0")
    resp = await async_client.download_scan_export(execution_id)
    assert resp.content == data
    assert bytes(resp) == data
