import pytest
from pytest_httpserver import HTTPServer

from harborapi.client import HarborAsyncClient
from harborapi.utils import get_artifact_path


@pytest.mark.asyncio
@pytest.mark.parametrize("status_code", [200, 202])
async def test_scan_artifact_mock(
    async_client: HarborAsyncClient,
    httpserver: HTTPServer,
    caplog: pytest.LogCaptureFixture,
    status_code: int,
):
    project = "test-proj"
    repository = "test-repo"
    artifact = "test-artifact"
    # TODO: test "/" in repo name

    artifact_path = get_artifact_path(project, repository, artifact)
    endpoint_path = f"/api/v2.0{artifact_path}/scan"
    httpserver.expect_oneshot_request(
        endpoint_path,
        method="POST",
    ).respond_with_data("foo", status=status_code)
    async_client.url = httpserver.url_for("/api/v2.0")
    await async_client.scan_artifact(project, repository, artifact)
    if status_code == 200:
        assert "expected 202" in caplog.text


@pytest.mark.asyncio
async def test_get_scan_report_log_mock(
    async_client: HarborAsyncClient,
    httpserver: HTTPServer,
):
    project = "test-proj"
    repository = "test-repo"
    artifact = "test-artifact"
    report_id = "bar"

    artifact_path = get_artifact_path(project, repository, artifact)
    endpoint_path = f"/api/v2.0{artifact_path}/scan/{report_id}/log"
    httpserver.expect_oneshot_request(
        endpoint_path,
        method="GET",
    ).respond_with_data(f"foo: {report_id}")

    async_client.url = httpserver.url_for("/api/v2.0")
    resp = await async_client.get_artifact_scan_report_log(
        project, repository, artifact, report_id
    )
    assert resp == "foo: bar"


@pytest.mark.asyncio
@pytest.mark.parametrize("status_code", [200, 202])
async def test_stop_artifact_scan_mock(
    async_client: HarborAsyncClient,
    httpserver: HTTPServer,
    caplog: pytest.LogCaptureFixture,
    status_code: int,
):
    project = "test-proj"
    repository = "test-repo"
    artifact = "test-artifact"
    # TODO: test "/" in repo name

    artifact_path = get_artifact_path(project, repository, artifact)
    endpoint_path = f"/api/v2.0{artifact_path}/scan/stop"
    httpserver.expect_oneshot_request(
        endpoint_path,
        method="POST",
    ).respond_with_data("foo", status=status_code)
    async_client.url = httpserver.url_for("/api/v2.0")
    await async_client.stop_artifact_scan(project, repository, artifact)
    if status_code == 200:
        assert "expected 202" in caplog.text
