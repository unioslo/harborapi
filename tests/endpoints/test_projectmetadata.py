from typing import Dict, List, Optional, Union

import pytest
from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st
from pytest_httpserver import HTTPServer

from harborapi.client import HarborAsyncClient

from ..utils import json_from_list


@pytest.mark.asyncio
async def test_get_project_metadata_mock(
    async_client: HarborAsyncClient,
    httpserver: HTTPServer,
    project_name_or_id: Union[str, int],
):
    metadata = {"foo": "bar", "baz": "qux"}
    httpserver.expect_oneshot_request(
        f"/api/v2.0/projects/{project_name_or_id}/metadatas", method="GET"
    ).respond_with_json(metadata)
    async_client.url = httpserver.url_for("/api/v2.0")
    resp = await async_client.get_project_metadata(project_name_or_id)
    assert resp == metadata


@pytest.mark.asyncio
async def test_add_project_metadata_mock(
    async_client: HarborAsyncClient,
    httpserver: HTTPServer,
    project_name_or_id: Union[str, int],
):
    metadata = {"foo": "bar", "baz": "qux"}
    httpserver.expect_oneshot_request(
        f"/api/v2.0/projects/{project_name_or_id}/metadatas",
        method="POST",
        json=metadata,
    ).respond_with_data()
    async_client.url = httpserver.url_for("/api/v2.0")
    await async_client.add_project_metadata(project_name_or_id, metadata)


@pytest.mark.asyncio
async def test_get_project_metadata_entry_mock(
    async_client: HarborAsyncClient,
    httpserver: HTTPServer,
    project_name_or_id: Union[str, int],
):
    metadata = {"foo": "bar"}
    httpserver.expect_oneshot_request(
        f"/api/v2.0/projects/{project_name_or_id}/metadatas/foo", method="GET"
    ).respond_with_json(metadata)
    async_client.url = httpserver.url_for("/api/v2.0")
    resp = await async_client.get_project_metadata_entry(project_name_or_id, "foo")
    assert resp == metadata


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "new_metadata", ["baz", {"foo": "baz"}, 123, [1, 2, 3], True, None]
)
async def test_update_project_metadata_entry_mock(
    async_client: HarborAsyncClient,
    httpserver: HTTPServer,
    project_name_or_id: Union[str, int],
    new_metadata: Union[str, Dict[str, str]],
):
    httpserver.expect_oneshot_request(
        f"/api/v2.0/projects/{project_name_or_id}/metadatas/foo", method="PUT"
    ).respond_with_data()
    async_client.url = httpserver.url_for("/api/v2.0")
    await async_client.update_project_metadata_entry(
        project_name_or_id,
        "foo",
        new_metadata,  # type: ignore # we test with different JSONable values
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
