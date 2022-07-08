from typing import List, Optional

import pytest
from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st
from pytest_httpserver import HTTPServer

from harborapi.client import HarborAsyncClient
from harborapi.models import UserResp
from harborapi.models.models import Permission, UserSearchRespItem

from ..utils import json_from_list


@pytest.mark.asyncio
@given(st.builds(UserResp), st.builds(UserResp))
@settings(suppress_health_check=[HealthCheck.function_scoped_fixture])
async def test_get_users_mock(
    async_client: HarborAsyncClient,
    httpserver: HTTPServer,
    user1: UserResp,
    user2: UserResp,
):
    httpserver.expect_oneshot_request("/api/v2.0/users").respond_with_json(
        [user1.dict(), user2.dict()]
    )
    async_client.url = httpserver.url_for("/api/v2.0")
    users = await async_client.get_users()
    assert len(users) == 2
    assert users[0] == user1
    assert users[1] == user2


@pytest.mark.asyncio
async def test_set_user_cli_secret_mock(
    async_client: HarborAsyncClient,
    httpserver: HTTPServer,
):
    httpserver.expect_request(
        "/api/v2.0/users/1234/cli_secret", method="PUT", json={"secret": "secret1234"}
    ).respond_with_data()
    async_client.url = httpserver.url_for("/api/v2.0")
    await async_client.set_user_cli_secret(1234, "secret1234")


@pytest.mark.asyncio
@given(st.lists(st.builds(UserSearchRespItem)))
@settings(suppress_health_check=[HealthCheck.function_scoped_fixture])
async def test_get_users_by_username_mock(
    async_client: HarborAsyncClient,
    httpserver: HTTPServer,
    users: List[UserSearchRespItem],
):
    httpserver.expect_oneshot_request("/api/v2.0/users/search").respond_with_data(
        json_from_list(users), content_type="application/json"
    )
    async_client.url = httpserver.url_for("/api/v2.0")
    resp = await async_client.get_users_by_username("username")
    assert resp == users
