from typing import Dict, List, Optional, Union

import pytest
from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st
from pytest_httpserver import HTTPServer

from harborapi.client import HarborAsyncClient
from harborapi.models.models import ProjectMetadata

from ..utils import json_from_list


@pytest.mark.asyncio
@given(st.builds(ProjectMetadata))
@settings(suppress_health_check=[HealthCheck.function_scoped_fixture])
async def test_get_project_metadata_mock(
    async_client: HarborAsyncClient,
    httpserver: HTTPServer,
    project_name_or_id: Union[str, int],
    metadata: ProjectMetadata,
):
    httpserver.expect_oneshot_request(
        f"/api/v2.0/projects/{project_name_or_id}/metadatas", method="GET"
    ).respond_with_data(metadata.json(), content_type="application/json")
    async_client.url = httpserver.url_for("/api/v2.0")
    resp = await async_client.get_project_metadata(project_name_or_id)
    assert resp == metadata


@pytest.mark.asyncio
@given(st.builds(ProjectMetadata))
@settings(suppress_health_check=[HealthCheck.function_scoped_fixture])
async def test_set_project_metadata_mock(
    async_client: HarborAsyncClient,
    httpserver: HTTPServer,
    project_name_or_id: Union[str, int],
    metadata: ProjectMetadata,
):
    httpserver.expect_oneshot_request(
        f"/api/v2.0/projects/{project_name_or_id}/metadatas",
        method="POST",
        json=metadata.dict(exclude_unset=True),
    ).respond_with_data()
    async_client.url = httpserver.url_for("/api/v2.0")
    await async_client.set_project_metadata(project_name_or_id, metadata)


@pytest.mark.asyncio
async def test_get_project_metadata_entry_mock(
    async_client: HarborAsyncClient,
    httpserver: HTTPServer,
    project_name_or_id: Union[str, int],
):
    httpserver.expect_oneshot_request(
        f"/api/v2.0/projects/{project_name_or_id}/metadatas/auto_scan", method="GET"
    ).respond_with_json({"auto_scan": "true"})
    async_client.url = httpserver.url_for("/api/v2.0")
    resp = await async_client.get_project_metadata_entry(
        project_name_or_id, "auto_scan"
    )
    assert resp == {"auto_scan": "true"}


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "new_metadata", [ProjectMetadata(auto_scan="true"), {"auto_scan": "true"}]
)
async def test_update_project_metadata_entry_mock(
    async_client: HarborAsyncClient,
    httpserver: HTTPServer,
    project_name_or_id: Union[str, int],
    new_metadata: Union[ProjectMetadata, Dict[str, str]],
):
    httpserver.expect_oneshot_request(
        f"/api/v2.0/projects/{project_name_or_id}/metadatas/auto_scan", method="PUT"
    ).respond_with_data()
    async_client.url = httpserver.url_for("/api/v2.0")
    await async_client.update_project_metadata_entry(
        project_name_or_id,
        "auto_scan",
        new_metadata,
    )


async def test_update_project_metadata_with_extra_field_mock(
    async_client: HarborAsyncClient,
    httpserver: HTTPServer,
    project_name_or_id: Union[str, int],
):
    """Testing that we can instantiate ProjectMetadata with extra fields,
    and it will be serialized correctly when sending to the API."""
    new_metadata = ProjectMetadata(foo="bar")
    httpserver.expect_oneshot_request(
        f"/api/v2.0/projects/{project_name_or_id}/metadatas/foo", method="PUT"
    ).respond_with_data()
    async_client.url = httpserver.url_for("/api/v2.0")
    await async_client.update_project_metadata_entry(
        project_name_or_id,
        "foo",
        new_metadata,
    )


@pytest.mark.asyncio
async def test_delete_project_metadata_entry_mock(
    async_client: HarborAsyncClient,
    httpserver: HTTPServer,
    project_name_or_id: Union[str, int],
):
    httpserver.expect_oneshot_request(
        f"/api/v2.0/projects/{project_name_or_id}/metadatas/foo", method="DELETE"
    ).respond_with_data()
    async_client.url = httpserver.url_for("/api/v2.0")
    await async_client.delete_project_metadata_entry(project_name_or_id, "foo")
