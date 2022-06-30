import pytest
from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st
from pytest_httpserver import HTTPServer

from harborapi.client import HarborAsyncClient
from harborapi.model import UserResp


@pytest.mark.asyncio
@given(st.builds(UserResp), st.builds(UserResp))
@settings(suppress_health_check=[HealthCheck.function_scoped_fixture])
async def test_get_users_mock(
    async_client: HarborAsyncClient,
    httpserver: HTTPServer,
    user1: UserResp,
    user2: UserResp,
):
    httpserver.expect_request("/api/v2.0/users").respond_with_json(
        [user1.dict(), user2.dict()]
    )
    async_client.url = httpserver.url_for("/api/v2.0")
    users = await async_client.get_users()
    assert len(users) == 2
    assert users[0] == user1
    assert users[1] == user2
