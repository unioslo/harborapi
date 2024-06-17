from __future__ import annotations

from typing import List

import pytest
from hypothesis import HealthCheck
from hypothesis import given
from hypothesis import settings
from hypothesis import strategies as st
from pytest_httpserver import HTTPServer

from harborapi.client import HarborAsyncClient
from harborapi.models.models import UserGroup
from harborapi.models.models import UserGroupSearchItem

from ..utils import json_from_list


@pytest.mark.asyncio
@given(st.lists(st.builds(UserGroupSearchItem)))
@settings(suppress_health_check=[HealthCheck.function_scoped_fixture])
async def test_search_usergroups_mock(
    async_client: HarborAsyncClient,
    httpserver: HTTPServer,
    usergroups: List[UserGroupSearchItem],
):
    httpserver.expect_oneshot_request(
        "/api/v2.0/usergroups/search",
        method="GET",
        query_string={"groupname": "test", "page": "1", "page_size": "10"},
    ).respond_with_data(json_from_list(usergroups), content_type="application/json")
    resp = await async_client.search_usergroups("test")
    assert resp == usergroups


@pytest.mark.asyncio
@given(st.builds(UserGroup))
@settings(suppress_health_check=[HealthCheck.function_scoped_fixture])
async def test_create_usergroup_mock(
    async_client: HarborAsyncClient,
    httpserver: HTTPServer,
    usergroup: UserGroup,
):
    usergroup.id = 123
    expect_location = "/api/v2.0/usergroups/123"  # idk?

    httpserver.expect_oneshot_request(
        "/api/v2.0/usergroups",
        method="POST",
        json=usergroup.model_dump(mode="json", exclude_unset=True),
    ).respond_with_data(
        headers={"Location": expect_location},
        status=201,
    )
    location = await async_client.create_usergroup(usergroup)
    assert location == expect_location


@pytest.mark.asyncio
@given(st.builds(UserGroup))
@settings(suppress_health_check=[HealthCheck.function_scoped_fixture])
async def test_update_usergroup_mock(
    async_client: HarborAsyncClient,
    httpserver: HTTPServer,
    usergroup: UserGroup,
):
    httpserver.expect_oneshot_request(
        "/api/v2.0/usergroups/123",
        method="PUT",
        json=usergroup.model_dump(mode="json", exclude_unset=True),
    ).respond_with_data()
    await async_client.update_usergroup(123, usergroup)


@pytest.mark.asyncio
@given(st.lists(st.builds(UserGroup)))
@settings(suppress_health_check=[HealthCheck.function_scoped_fixture])
async def test_get_usergroups_mock(
    async_client: HarborAsyncClient,
    httpserver: HTTPServer,
    usergroups: List[UserGroup],
):
    httpserver.expect_oneshot_request(
        "/api/v2.0/usergroups",
        method="GET",
    ).respond_with_data(
        json_from_list(usergroups),
        content_type="application/json",
    )

    resp = await async_client.get_usergroups()
    assert resp == usergroups


@pytest.mark.asyncio
@given(st.builds(UserGroup))
@settings(suppress_health_check=[HealthCheck.function_scoped_fixture])
async def test_get_usergroup_mock(
    async_client: HarborAsyncClient,
    httpserver: HTTPServer,
    usergroup: UserGroup,
):
    usergroup.id = 123
    httpserver.expect_oneshot_request(
        "/api/v2.0/usergroups/123",
        method="GET",
    ).respond_with_data(
        usergroup.model_dump_json(),
        content_type="application/json",
    )

    resp = await async_client.get_usergroup(123)
    assert resp == usergroup


@pytest.mark.asyncio
async def test_delete_usergroup(
    async_client: HarborAsyncClient,
    httpserver: HTTPServer,
):
    httpserver.expect_oneshot_request(
        "/api/v2.0/usergroups/123",
        method="DELETE",
    ).respond_with_data()

    await async_client.delete_usergroup(123)
