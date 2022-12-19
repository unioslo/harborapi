from typing import List

import pytest
from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st
from pytest_httpserver import HTTPServer

from harborapi.client import HarborAsyncClient
from harborapi.models.models import Robot, RobotCreate, RobotCreated, RobotSec

from ..utils import json_from_list


@pytest.mark.asyncio
@given(st.builds(RobotCreate), st.builds(RobotCreated))
@settings(suppress_health_check=[HealthCheck.function_scoped_fixture])
async def test_create_robot_mock(
    async_client: HarborAsyncClient,
    httpserver: HTTPServer,
    robot: RobotCreate,
    robot_created: RobotCreated,
):
    httpserver.expect_oneshot_request(
        "/api/v2.0/robots",
        method="POST",
        json=robot.dict(exclude_unset=True),
    ).respond_with_data(robot_created.json(), content_type="application/json")
    async_client.url = httpserver.url_for("/api/v2.0")
    resp = await async_client.create_robot(robot)
    assert resp == robot_created


@pytest.mark.asyncio
@given(st.lists(st.builds(Robot)))
@settings(suppress_health_check=[HealthCheck.function_scoped_fixture])
async def test_get_robots_mock(
    async_client: HarborAsyncClient,
    httpserver: HTTPServer,
    robots: List[Robot],
):
    httpserver.expect_oneshot_request(
        "/api/v2.0/robots", method="GET"
    ).respond_with_data(json_from_list(robots), content_type="application/json")
    async_client.url = httpserver.url_for("/api/v2.0")
    resp = await async_client.get_robots()
    assert resp == robots


@pytest.mark.asyncio
@given(st.builds(Robot))
@settings(suppress_health_check=[HealthCheck.function_scoped_fixture])
async def test_get_robot_mock(
    async_client: HarborAsyncClient,
    httpserver: HTTPServer,
    robot: Robot,
):
    httpserver.expect_oneshot_request(
        "/api/v2.0/robots/1234", method="GET"
    ).respond_with_data(robot.json(), content_type="application/json")
    async_client.url = httpserver.url_for("/api/v2.0")
    resp = await async_client.get_robot(1234)
    assert resp == robot


@pytest.mark.asyncio
@given(st.builds(Robot))
@settings(suppress_health_check=[HealthCheck.function_scoped_fixture])
async def test_update_robot_mock(
    async_client: HarborAsyncClient,
    httpserver: HTTPServer,
    robot: Robot,
):
    httpserver.expect_oneshot_request(
        "/api/v2.0/robots/1234",
        method="PUT",
        json=robot.dict(exclude_unset=True),
    ).respond_with_data()
    async_client.url = httpserver.url_for("/api/v2.0")
    await async_client.update_robot(1234, robot)


@pytest.mark.asyncio
async def test_delete_robot_mock(
    async_client: HarborAsyncClient,
    httpserver: HTTPServer,
):
    httpserver.expect_oneshot_request(
        "/api/v2.0/robots/1234", method="DELETE"
    ).respond_with_data()
    async_client.url = httpserver.url_for("/api/v2.0")
    await async_client.delete_robot(1234)


@pytest.mark.asyncio
@given(st.text())
@settings(suppress_health_check=[HealthCheck.function_scoped_fixture])
async def test_update_robot_secret_mock(
    async_client: HarborAsyncClient,
    httpserver: HTTPServer,
    secret: str,
):
    expected_resp = RobotSec(secret=secret)
    httpserver.expect_oneshot_request(
        "/api/v2.0/robots/1234",
        method="PATCH",
        json=expected_resp.dict(),
    ).respond_with_data(expected_resp.json(), content_type="application/json")
    async_client.url = httpserver.url_for("/api/v2.0")
    resp = await async_client.update_robot_secret(1234, secret)
    assert resp == expected_resp
