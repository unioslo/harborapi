import asyncio

from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st
from pytest_httpserver import HTTPServer

from harborapi import HarborClient
from harborapi.models import UserResp


# NOTE: this will likely be removed in the future in favor of auto-generated
#       sync client tests.
@given(st.builds(UserResp))
@settings(suppress_health_check=[HealthCheck.function_scoped_fixture])
def test_get_users_mock_sync(httpserver: HTTPServer, user: UserResp):
    # manually set version to v2.0 for this test

    httpserver.expect_oneshot_request(
        "/api/v2.0/users/1234",
        method="GET",
    ).respond_with_data(user.json(), content_type="application/json")
    client = HarborClient(
        url=httpserver.url_for("/api/v2.0"),
        username="username",
        secret="secret",
        loop=asyncio.new_event_loop(),
    )
    resp = client.get_user(1234)
    assert user == resp
