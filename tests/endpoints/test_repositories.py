from typing import List, Optional

import pytest
from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st
from pytest_httpserver import HTTPServer

from harborapi.client import HarborAsyncClient
from harborapi.models import Repository

from ..utils import json_from_list


@pytest.mark.asyncio
@given(st.builds(Repository))
@settings(suppress_health_check=[HealthCheck.function_scoped_fixture])
async def test_get_repository_mock(
    async_client: HarborAsyncClient,
    httpserver: HTTPServer,
    repository: Repository,
):
    httpserver.expect_oneshot_request(
        "/api/v2.0/projects/testproj/repositories/testrepo", method="GET"
    ).respond_with_data(repository.json(), headers={"Content-Type": "application/json"})
    async_client.url = httpserver.url_for("/api/v2.0")
    resp = await async_client.get_repository("testproj", "testrepo")
    assert resp == repository


@pytest.mark.asyncio
@given(st.builds(Repository))
@settings(suppress_health_check=[HealthCheck.function_scoped_fixture])
async def test_update_repository_mock(
    async_client: HarborAsyncClient,
    httpserver: HTTPServer,
    repository: Repository,
):
    httpserver.expect_oneshot_request(
        "/api/v2.0/projects/testproj/repositories/testrepo",
        method="PUT",
        json=repository.dict(exclude_unset=True),
    ).respond_with_data()
    async_client.url = httpserver.url_for("/api/v2.0")
    await async_client.update_repository(
        "testproj",
        "testrepo",
        repository,
    )


@pytest.mark.asyncio
async def test_delete_repository_mock(
    async_client: HarborAsyncClient,
    httpserver: HTTPServer,
):
    httpserver.expect_oneshot_request(
        "/api/v2.0/projects/testproj/repositories/testrepo", method="DELETE"
    ).respond_with_data()
    async_client.url = httpserver.url_for("/api/v2.0")
    await async_client.delete_repository("testproj", "testrepo")


@pytest.mark.asyncio
@given(st.lists(st.builds(Repository)))
@pytest.mark.parametrize(
    "project_name,expected_url",
    [
        ("testproj", "/api/v2.0/projects/testproj/repositories"),
        (None, "/api/v2.0/repositories"),
    ],
)
@settings(suppress_health_check=[HealthCheck.function_scoped_fixture])
async def test_get_repositories_mock(
    async_client: HarborAsyncClient,
    httpserver: HTTPServer,
    project_name: Optional[str],
    expected_url: str,
    repositories: List[Repository],
):
    httpserver.expect_oneshot_request(expected_url, method="GET").respond_with_data(
        json_from_list(repositories),
        headers={"Content-Type": "application/json"},
    )
    async_client.url = httpserver.url_for("/api/v2.0")
    resp = await async_client.get_repositories(project_name)
    assert resp == repositories
