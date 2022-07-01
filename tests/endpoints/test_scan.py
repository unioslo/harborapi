from urllib.parse import quote

import pytest
from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st
from pytest_httpserver import HTTPServer

from harborapi.client import HarborAsyncClient
from harborapi.utils import get_artifact_path


# TODO: parametrize
@pytest.mark.skip(reason="Unable to specify correct URL for some reason")
@pytest.mark.asyncio
@pytest.mark.parametrize("status_code", [(200,), (202,)])
async def test_scan_artifact_mock(
    async_client: HarborAsyncClient,
    httpserver: HTTPServer,
    caplog: pytest.LogCaptureFixture,
    status_code: int,
):
    project = "test-proj"
    repository = "test-org/test-service"
    artifact = "test-artifact"
    artifact_path = get_artifact_path(project, repository, artifact)
    # endpoint_path = f"/api/v2.0{artifact_path}/scan"
    endpoint_path = f"/api/v2.0/projects/test-proj/repositories/test-org%2Ftest-service/artifacts/test-artifact/scan"
    httpserver.expect_request(
        endpoint_path,
        # "/api/v2.0/projects/test-proj/repositories/test-org%2Ftest-service/artifacts/test-artifact/scan",
        method="POST",
    ).respond_with_data(status=status_code)
    async_client.url = httpserver.url_for("/api/v2.0")
    await async_client.scan_artifact(project, repository, artifact)
    if status_code == 200:
        assert "expected 202" in caplog.text
