from typing import List, Union

import pytest
from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st
from pytest_httpserver import HTTPServer

from harborapi.client import HarborAsyncClient
from harborapi.models import Quota
from harborapi.models.models import (
    AuditLog,
    Project,
    ProjectReq,
    ProjectSummary,
    QuotaUpdateReq,
    ScannerRegistration,
)
from tests.utils import json_from_list


@pytest.mark.asyncio
async def test_set_project_scanner_mock(
    async_client: HarborAsyncClient,
    httpserver: HTTPServer,
):
    httpserver.expect_oneshot_request(
        "/api/v2.0/projects/1234/scanner", method="PUT"
    ).respond_with_data()
    async_client.url = httpserver.url_for("/api/v2.0")
    await async_client.set_project_scanner("1234", "myscanner")


@pytest.mark.asyncio
@given(st.builds(ScannerRegistration))
@settings(suppress_health_check=[HealthCheck.function_scoped_fixture])
async def test_get_project_scanner_mock(
    async_client: HarborAsyncClient,
    httpserver: HTTPServer,
    scanner: ScannerRegistration,
):
    httpserver.expect_oneshot_request(
        "/api/v2.0/projects/1234/scanner",
        method="GET",
    ).respond_with_data(scanner.json(), content_type="application/json")
    async_client.url = httpserver.url_for("/api/v2.0")
    resp = await async_client.get_project_scanner("1234")
    assert resp == scanner


@pytest.mark.asyncio
@given(st.lists(st.builds(AuditLog)))
@settings(suppress_health_check=[HealthCheck.function_scoped_fixture])
async def test_get_project_logs_mock(
    async_client: HarborAsyncClient,
    httpserver: HTTPServer,
    logs: List[AuditLog],
):
    httpserver.expect_oneshot_request(
        "/api/v2.0/projects/1234/logs", method="GET"
    ).respond_with_data(json_from_list(logs), content_type="application/json")
    async_client.url = httpserver.url_for("/api/v2.0")
    resp = await async_client.get_project_logs("1234")
    assert resp == logs


@pytest.mark.anyio
@pytest.mark.parametrize(
    "status,expected",
    [(200, True), (404, False), (400, False), (500, False)],
)
async def test_project_exists_mock(
    async_client: HarborAsyncClient, httpserver: HTTPServer, status: int, expected: bool
):
    httpserver.expect_oneshot_request(
        "/api/v2.0/projects", method="HEAD", query_string="project_name=1234"
    ).respond_with_data(status=status)
    async_client.url = httpserver.url_for("/api/v2.0")
    try:
        assert await async_client.project_exists("1234") == expected
    except Exception as e:
        if expected:
            raise e


@pytest.mark.asyncio
@given(st.builds(ProjectReq))
@settings(suppress_health_check=[HealthCheck.function_scoped_fixture])
async def test_create_project_mock(
    async_client: HarborAsyncClient,
    httpserver: HTTPServer,
    project: ProjectReq,
):
    httpserver.expect_oneshot_request(
        "/api/v2.0/projects",
        method="POST",
        json=project.dict(exclude_unset=True),
    ).respond_with_data(headers={"Location": "%2Fapi%2Fv2.0%2Fprojects%2F1234"})
    async_client.url = httpserver.url_for("/api/v2.0")
    resp = await async_client.create_project(project)
    assert resp == "/api/v2.0/projects/1234"


@pytest.mark.asyncio
@given(st.lists(st.builds(Project)))
@settings(suppress_health_check=[HealthCheck.function_scoped_fixture])
async def test_get_projects_mock(
    async_client: HarborAsyncClient,
    httpserver: HTTPServer,
    projects: List[Project],
):
    httpserver.expect_oneshot_request(
        "/api/v2.0/projects",
        method="GET",
    ).respond_with_data(json_from_list(projects), content_type="application/json")
    async_client.url = httpserver.url_for("/api/v2.0")
    resp = await async_client.get_projects("1234")
    assert resp == projects


@pytest.mark.asyncio
@given(st.builds(ProjectReq))
@settings(suppress_health_check=[HealthCheck.function_scoped_fixture])
async def test_update_project_mock(
    async_client: HarborAsyncClient,
    httpserver: HTTPServer,
    project: ProjectReq,
):
    httpserver.expect_oneshot_request(
        "/api/v2.0/projects/1234",
        method="PUT",
    ).respond_with_data(project.json(), content_type="application/json")
    async_client.url = httpserver.url_for("/api/v2.0")
    await async_client.update_project("1234", project)


@pytest.mark.asyncio
@given(st.builds(Project))
@settings(suppress_health_check=[HealthCheck.function_scoped_fixture])
async def test_get_project_mock(
    async_client: HarborAsyncClient,
    httpserver: HTTPServer,
    project: Project,
):
    httpserver.expect_oneshot_request(
        "/api/v2.0/projects/1234",
        method="GET",
    ).respond_with_data(project.json(), content_type="application/json")
    async_client.url = httpserver.url_for("/api/v2.0")
    resp = await async_client.get_project("1234")
    assert resp == project


@pytest.mark.asyncio
async def test_delete_project_mock(
    async_client: HarborAsyncClient,
    httpserver: HTTPServer,
):
    httpserver.expect_oneshot_request(
        "/api/v2.0/projects/1234",
        method="DELETE",
    ).respond_with_data()
    async_client.url = httpserver.url_for("/api/v2.0")
    await async_client.delete_project("1234")


@pytest.mark.asyncio
@given(st.lists(st.builds(ScannerRegistration)))
@settings(suppress_health_check=[HealthCheck.function_scoped_fixture])
async def test_get_project_scanner_candidates_mock(
    async_client: HarborAsyncClient,
    httpserver: HTTPServer,
    scanners: List[ScannerRegistration],
):
    httpserver.expect_oneshot_request(
        "/api/v2.0/projects/1234/scanner/candidates",
        method="GET",
    ).respond_with_data(json_from_list(scanners), content_type="application/json")
    async_client.url = httpserver.url_for("/api/v2.0")
    resp = await async_client.get_project_scanner_candidates("1234")
    assert resp == scanners


@pytest.mark.asyncio
@given(st.builds(ProjectSummary))
@settings(suppress_health_check=[HealthCheck.function_scoped_fixture])
async def test_get_project_summary_mock(
    async_client: HarborAsyncClient,
    httpserver: HTTPServer,
    project_summary: ProjectSummary,
):
    httpserver.expect_oneshot_request(
        "/api/v2.0/projects/1234/summary",
        method="GET",
    ).respond_with_data(project_summary.json(), content_type="application/json")
    async_client.url = httpserver.url_for("/api/v2.0")
    resp = await async_client.get_project_summary("1234")
    assert resp == project_summary
