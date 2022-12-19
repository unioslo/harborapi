from typing import List, Optional

import pytest
from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st
from pytest_httpserver import HTTPServer

from harborapi.client import HarborAsyncClient
from harborapi.models import UserResp
from harborapi.models.models import (
    PasswordReq,
    Permission,
    UserCreationReq,
    UserProfile,
    UserSearchRespItem,
)

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
    httpserver.expect_oneshot_request(
        "/api/v2.0/users", method="GET"
    ).respond_with_json([user1.dict(), user2.dict()])
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
    httpserver.expect_oneshot_request(
        "/api/v2.0/users/1234/cli_secret", method="PUT", json={"secret": "secret1234"}
    ).respond_with_data()
    async_client.url = httpserver.url_for("/api/v2.0")
    await async_client.set_user_cli_secret(1234, "secret1234")


@pytest.mark.asyncio
@given(st.lists(st.builds(UserSearchRespItem)))
@settings(suppress_health_check=[HealthCheck.function_scoped_fixture])
async def test_search_users_by_username_mock(
    async_client: HarborAsyncClient,
    httpserver: HTTPServer,
    users: List[UserSearchRespItem],
):
    httpserver.expect_oneshot_request("/api/v2.0/users/search").respond_with_data(
        json_from_list(users), content_type="application/json"
    )
    async_client.url = httpserver.url_for("/api/v2.0")
    resp = await async_client.search_users_by_username("username")
    assert resp == users


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "scope,relative,expected_query",
    [
        ("user", False, {"scope": "user", "relative": False}),
        ("user", True, {"scope": "user", "relative": True}),
        (None, False, {"relative": False}),
        (None, True, {"relative": True}),
        ("", True, {"scope": "", "relative": True}),
        ("", False, {"scope": "", "relative": False}),
    ],
)
@given(st.lists(st.builds(Permission)))
@settings(suppress_health_check=[HealthCheck.function_scoped_fixture])
async def test_get_current_user_permissions_mock(
    async_client: HarborAsyncClient,
    httpserver: HTTPServer,
    scope: Optional[str],
    relative: bool,
    expected_query: dict,
    permissions: List[Permission],
):
    # for some reason, pytest-httpserver will not match the query string
    # when passing it as a dict, so we need to convert it to a string
    query_string = "&".join(
        f"{k}={v}".lower() for k, v in expected_query.items() if v is not None
    )
    httpserver.expect_oneshot_request(
        "/api/v2.0/users/current/permissions",
        method="GET",
        query_string=query_string,
    ).respond_with_data(json_from_list(permissions), content_type="application/json")
    async_client.url = httpserver.url_for("/api/v2.0")
    resp = await async_client.get_current_user_permissions(scope, relative)
    assert resp == permissions


@pytest.mark.asyncio
@given(st.builds(UserResp))
@settings(suppress_health_check=[HealthCheck.function_scoped_fixture])
async def test_get_current_user_mock(
    async_client: HarborAsyncClient,
    httpserver: HTTPServer,
    user: UserResp,
):
    httpserver.expect_oneshot_request(
        "/api/v2.0/users/current",
        method="GET",
    ).respond_with_data(user.json(), content_type="application/json")
    async_client.url = httpserver.url_for("/api/v2.0")
    resp = await async_client.get_current_user()
    assert resp == user


@pytest.mark.asyncio
@pytest.mark.parametrize("is_admin", [True, False])
async def test_set_user_admin_mock(
    async_client: HarborAsyncClient,
    httpserver: HTTPServer,
    is_admin: bool,
):
    httpserver.expect_oneshot_request(
        f"/api/v2.0/users/1234/sysadmin",
        method="PUT",
    ).respond_with_data()
    async_client.url = httpserver.url_for("/api/v2.0")
    await async_client.set_user_admin(1234, is_admin)


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "new_password,old_password",
    (
        # Using new and old password (regular user)
        ["newpw123", "oldpw123"],
        # Omitting the old password (admin)
        ["newpw123", None],
    ),
)
async def test_set_user_password_mock(
    async_client: HarborAsyncClient,
    httpserver: HTTPServer,
    new_password: str,
    old_password: Optional[str],
):
    # NOTE: This mock could stand to be expanded/improved
    #       We are not mocking the distinction between user and admin behavior
    httpserver.expect_oneshot_request(
        f"/api/v2.0/users/1234/password",
        method="PUT",
        json=PasswordReq(new_password=new_password, old_password=old_password).dict(),
    ).respond_with_data()
    async_client.url = httpserver.url_for("/api/v2.0")
    await async_client.set_user_password(1234, new_password, old_password)


@pytest.mark.asyncio
@given(st.builds(UserCreationReq))
@settings(suppress_health_check=[HealthCheck.function_scoped_fixture])
async def test_create_user_mock(
    async_client: HarborAsyncClient,
    httpserver: HTTPServer,
    user: UserCreationReq,
):
    httpserver.expect_oneshot_request(
        "/api/v2.0/users",
        method="POST",
        json=user.dict(exclude_unset=True),
    ).respond_with_data(status=201, headers={"Location": "/api/v2.0/users/1234"})
    async_client.url = httpserver.url_for("/api/v2.0")
    resp = await async_client.create_user(user)
    assert resp == "/api/v2.0/users/1234"


@pytest.mark.asyncio
@given(st.builds(UserProfile))
@settings(suppress_health_check=[HealthCheck.function_scoped_fixture])
async def test_update_user_mock(
    async_client: HarborAsyncClient,
    httpserver: HTTPServer,
    user: UserProfile,
):
    httpserver.expect_oneshot_request(
        "/api/v2.0/users/1234",
        method="PUT",
        json=user.dict(exclude_unset=True),
    ).respond_with_data(status=200)
    async_client.url = httpserver.url_for("/api/v2.0")
    await async_client.update_user(1234, user)


@pytest.mark.asyncio
@given(st.builds(UserResp))
@settings(suppress_health_check=[HealthCheck.function_scoped_fixture])
async def test_get_user_mock(
    async_client: HarborAsyncClient,
    httpserver: HTTPServer,
    user: UserResp,
):
    httpserver.expect_oneshot_request(
        "/api/v2.0/users/1234",
        method="GET",
    ).respond_with_data(user.json(), content_type="application/json")
    async_client.url = httpserver.url_for("/api/v2.0")
    resp = await async_client.get_user(1234)
    assert user == resp


@pytest.mark.asyncio
@given(st.builds(UserResp))
@settings(suppress_health_check=[HealthCheck.function_scoped_fixture])
async def test_get_user_by_username_mock(
    async_client: HarborAsyncClient,
    httpserver: HTTPServer,
    # users: List[UserSearchRespItem],
    user: UserResp,
):
    user.user_id = 1234
    user.username = "test-user"
    search_resp = [UserSearchRespItem(user_id=1234, username="test-user")]

    # Set up search endpoint
    httpserver.expect_oneshot_request("/api/v2.0/users/search").respond_with_data(
        json_from_list(search_resp),
        content_type="application/json",
    )

    # Set up user endpoint
    httpserver.expect_oneshot_request(
        "/api/v2.0/users/1234",
        method="GET",
    ).respond_with_data(user.json(), content_type="application/json")

    async_client.url = httpserver.url_for("/api/v2.0")
    resp = await async_client.get_user_by_username("test-user")
    assert resp == user


@pytest.mark.asyncio
async def test_delete_user_mock(
    async_client: HarborAsyncClient,
    httpserver: HTTPServer,
):
    httpserver.expect_oneshot_request(
        "/api/v2.0/users/1234",
        method="DELETE",
    ).respond_with_data()  # API responds with status 200, not 204
    async_client.url = httpserver.url_for("/api/v2.0")
    await async_client.delete_user(1234)
