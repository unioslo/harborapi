import json
from pathlib import Path
from typing import List

import pytest
from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st
from pytest_httpserver import HTTPServer

from harborapi.auth import HarborAuthFile
from harborapi.client import HarborAsyncClient
from harborapi.exceptions import HarborAPIException
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
@given(st.builds(RobotCreate))
@settings(suppress_health_check=[HealthCheck.function_scoped_fixture])
async def test_create_robot_empty_response_mock(
    async_client: HarborAsyncClient,
    httpserver: HTTPServer,
    robot: RobotCreate,
):
    httpserver.expect_oneshot_request(
        "/api/v2.0/robots",
        method="POST",
        json=robot.dict(exclude_unset=True),
    ).respond_with_data("{}", content_type="application/json")
    async_client.url = httpserver.url_for("/api/v2.0")
    with pytest.raises(HarborAPIException) as exc_info:
        await async_client.create_robot(robot)
    assert "empty response" in exc_info.value.args[0].lower()


@pytest.mark.asyncio
@given(st.builds(RobotCreate), st.builds(RobotCreated))
@settings(
    suppress_health_check=[HealthCheck.function_scoped_fixture], max_examples=1
)  # Only run once
async def test_create_robot_with_path_mock(
    async_client: HarborAsyncClient,
    httpserver: HTTPServer,
    tmp_path: Path,
    robot: RobotCreate,
    robot_created: RobotCreated,
):
    httpserver.expect_oneshot_request(
        "/api/v2.0/robots",
        method="POST",
        json=robot.dict(exclude_unset=True),
    ).respond_with_data(robot_created.json(), content_type="application/json")
    async_client.url = httpserver.url_for("/api/v2.0")

    filename = f"{robot_created.name or robot.name}.json"
    filepath = tmp_path / filename
    resp = await async_client.create_robot(robot, path=filepath, overwrite=True)

    assert resp == robot_created

    assert filepath.exists()
    with open(filepath, "r") as f:
        authfile_json = json.load(f)

    authfile = HarborAuthFile(**authfile_json)
    assert authfile.name == robot_created.name or robot.name
    assert authfile.secret == robot_created.secret or robot.secret
    assert authfile.id == robot_created.id
    assert authfile.description == robot.description
    assert authfile.level == robot.level
    assert authfile.duration == robot.duration
    assert authfile.disable == robot.disable
    assert authfile.expires_at == robot_created.expires_at
    assert authfile.permissions == robot.permissions
    assert authfile.creation_time == robot_created.creation_time


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
async def test_refresh_robot_secret_mock(
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
    resp = await async_client.refresh_robot_secret(1234, secret)
    assert resp == expected_resp
