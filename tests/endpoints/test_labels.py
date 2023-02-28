from typing import List

import pytest
from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st
from pytest_httpserver import HTTPServer

from harborapi.client import HarborAsyncClient
from harborapi.models import Label

from ..utils import json_from_list


@pytest.mark.asyncio
@given(st.builds(Label))
@settings(suppress_health_check=[HealthCheck.function_scoped_fixture])
async def test_get_label_mock(
    async_client: HarborAsyncClient,
    httpserver: HTTPServer,
    label: Label,
):
    label_id = 123
    httpserver.expect_oneshot_request(
        f"/api/v2.0/labels/{label_id}", method="GET"
    ).respond_with_data(label.json(), headers={"Content-Type": "application/json"})
    async_client.url = httpserver.url_for("/api/v2.0")
    resp = await async_client.get_label(123)
    assert resp == label


@pytest.mark.asyncio
@given(st.builds(Label))
@settings(suppress_health_check=[HealthCheck.function_scoped_fixture])
async def test_update_label_mock(
    async_client: HarborAsyncClient,
    httpserver: HTTPServer,
    label: Label,
):
    label_id = 123
    httpserver.expect_oneshot_request(
        f"/api/v2.0/labels/{label_id}",
        method="PUT",
        json=label.dict(exclude_unset=True),
    ).respond_with_data()
    async_client.url = httpserver.url_for("/api/v2.0")
    await async_client.update_label(123, label)


@pytest.mark.asyncio
@given(st.builds(Label))
@settings(suppress_health_check=[HealthCheck.function_scoped_fixture])
async def test_create_label_mock(
    async_client: HarborAsyncClient,
    httpserver: HTTPServer,
    label: Label,
):
    label_id = 123
    expect_location = f"/api/v2.0/labels/{label_id}"
    httpserver.expect_oneshot_request(
        f"/api/v2.0/labels",
        method="POST",
        json=label.dict(exclude_unset=True),
    ).respond_with_data(headers={"Location": expect_location})
    async_client.url = httpserver.url_for("/api/v2.0")
    resp = await async_client.create_label(label)
    assert resp == expect_location


@pytest.mark.asyncio
async def test_delete_label_mock(
    async_client: HarborAsyncClient,
    httpserver: HTTPServer,
):
    label_id = 123
    httpserver.expect_oneshot_request(
        f"/api/v2.0/labels/{label_id}", method="DELETE"
    ).respond_with_data()
    async_client.url = httpserver.url_for("/api/v2.0")
    await async_client.delete_label(label_id)


@pytest.mark.asyncio
@given(st.lists(st.builds(Label)))
@settings(suppress_health_check=[HealthCheck.function_scoped_fixture])
async def test_get_labels_mock(
    async_client: HarborAsyncClient,
    httpserver: HTTPServer,
    labels: List[Label],
):
    httpserver.expect_oneshot_request(
        "/api/v2.0/labels", method="GET"
    ).respond_with_data(
        json_from_list(labels),
        headers={"Content-Type": "application/json"},
    )
    async_client.url = httpserver.url_for("/api/v2.0")
    # TODO: query parameters
    resp = await async_client.get_labels()
    assert resp == labels
