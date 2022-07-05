from typing import List

import pytest
from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st
from pytest_httpserver import HTTPServer

from harborapi.client import HarborAsyncClient
from harborapi.models import HarborVulnerabilityReport
from harborapi.models.models import Tag

from ..strategies.artifact import get_hbv_strategy


@pytest.mark.asyncio
@given(get_hbv_strategy())
@settings(suppress_health_check=[HealthCheck.function_scoped_fixture])
async def test_get_artifact_vulnerabilities_mock(
    async_client: HarborAsyncClient,
    httpserver: HTTPServer,
    report: HarborVulnerabilityReport,
):
    httpserver.expect_oneshot_request(
        "/api/v2.0/projects/testproj/repositories/testrepo/artifacts/latest/additions/vulnerabilities",
        method="GET",
    ).respond_with_data(
        # use report.json() to avoid datetime serialization issues
        '{{"application/vnd.security.vulnerability.report; version=1.1": {r}}}'.format(
            r=report.json()
        ),
        headers={"Content-Type": "application/json"},
    )
    async_client.url = httpserver.url_for("/api/v2.0")
    r = await async_client.get_artifact_vulnerabilities(
        "testproj", "testrepo", "latest"
    )
    # TODO: add test for empty response ('{}')
    # TODO: specify MIME type when testing?
    assert r == report


@pytest.mark.asyncio
async def test_get_artifact_vulnerabilities_empty_mock(
    async_client: HarborAsyncClient,
    httpserver: HTTPServer,
):
    """Tests that an empty response is handled correctly.

    Empty responses can occur when the server does not have a report for
    the given MIME type.
    """
    httpserver.expect_oneshot_request(
        "/api/v2.0/projects/testproj/repositories/testrepo/artifacts/latest/additions/vulnerabilities",
        method="GET",
    ).respond_with_json({})

    async_client.url = httpserver.url_for("/api/v2.0")
    r = await async_client.get_artifact_vulnerabilities(
        "testproj", "testrepo", "latest"
    )
    assert r == None


@pytest.mark.asyncio
@given(st.lists(st.builds(Tag)))
@settings(suppress_health_check=[HealthCheck.function_scoped_fixture])
async def test_get_artifact_tags_mock(
    async_client: HarborAsyncClient,
    httpserver: HTTPServer,
    tags: List[Tag],
):
    httpserver.expect_oneshot_request(
        "/api/v2.0/projects/testproj/repositories/testrepo/artifacts/latest/tags",
        method="GET",
    ).respond_with_data(
        "[" + ",".join(t.json() for t in tags) + "]",
        headers={"Content-Type": "application/json"},
    )
    async_client.url = httpserver.url_for("/api/v2.0")
    tags = await async_client.get_artifact_tags("testproj", "testrepo", "latest")
    for tag in tags:
        assert isinstance(tag, Tag)
